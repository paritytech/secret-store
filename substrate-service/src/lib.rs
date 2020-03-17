// Copyright 2015-2020 Parity Technologies (UK) Ltd.
// This file is part of Parity Secret Store.

// Parity Secret Store is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity Secret Store is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity Secret Store.  If not, see <http://www.gnu.org/licenses/>.

use std::{
	collections::{BTreeSet, VecDeque},
	future::Future,
	ops::Range,
	pin::Pin,
	sync::Arc,
};
use futures::{FutureExt, Stream, StreamExt, future::ready};
use log::trace;
use primitives::{
	Address, KeyServerId, Public, ServerKeyId,
	error::Error,
	executor::Executor,
	key_server::KeyServer,
	key_storage::KeyStorage,
	service::ServiceTasksListenerRegistrar,
};
use crate::{
	transaction_pool::SubstrateTransactionPool,
};

// hide blockchain-service dependency
pub use blockchain_service::Configuration;

pub type BlockchainServiceTask = blockchain_service::BlockchainServiceTask;

mod transaction_pool;

/// Substrate block id.
pub enum BlockId<Hash> {
	/// Use block referenced by the hash.
	Hash(Hash),
	/// Use best known block.
	Best,
}

/// Block event that is maybe an event coming from SecretStore runtime module.
pub trait MaybeSecretStoreEvent {
	/// Try convert to secret store event.
	fn as_secret_store_event(self) -> Option<BlockchainServiceTask>;
}

/// Substrate Secret Store module calls.
#[derive(Debug)]
pub enum SecretStoreCall {
	/// Called when server key is generated.
	ServerKeyGenerated(ServerKeyId, Public),
	/// Called when server key generation error happens.
	ServerKeyGenerationError(ServerKeyId),
	/// Called when server key is retrieved.
	ServerKeyRetrieved(ServerKeyId, Public, u8),
	/// Called when server key retrieval error happens.
	ServerKeyRetrievalError(ServerKeyId),
	/// Called when document key is stored.
	DocumentKeyStored(ServerKeyId),
	/// Called when document key store error happens.
	DocumentKeyStoreError(ServerKeyId),
	/// Called when document key common part is retrieved.
	DocumentKeyCommonRetrieved(ServerKeyId, Address, Public, u8),
	/// Called when document key personal part is retrieved.
	DocumentKeyPersonalRetrieved(ServerKeyId, Address, Vec<Address>, Public, Vec<u8>),
	/// Called when document key shadow retireval error happens.
	DocumentKeyShadowRetrievalError(ServerKeyId, Address),
}

/// Substrate blockchain.
pub trait Blockchain: 'static + Send + Sync {
	/// Block hash type.
	type BlockHash: Clone + Send + Sync;
	/// Blockchain event type.
	type Event: MaybeSecretStoreEvent + Send;
	/// Block events stream type.
	type BlockEventsStream: Stream<Item = Self::Event> + Send;
	/// Future that results in pending tasks iterator.
	type PendingEventsStream: Stream<Item = Self::Event> + Send;
	/// Future that results in current key servers set.
	type CurrentKeyServersSetFuture: Future<Output = BTreeSet<KeyServerId>> + Send;
	/// Future that results in a boolean flag which is true when submitting response is required.
	type ResponseRequiredFuture: Future<Output = Result<bool, String>> + Send;

	/// Get block events.
	fn block_events(&self, block_hash: Self::BlockHash) -> Self::BlockEventsStream;
	/// Get current key servers set. This should return current key servers set at the best
	/// known (finalized) block. That's because we use this to determine key server which
	/// will should start corresponding session AND the session starts at the time when
	/// current set should have been read from the best block.
	fn current_key_servers_set(&self) -> Self::CurrentKeyServersSetFuture;

	/// Get pending server key generation tasks range at given block.
	fn server_key_generation_tasks(
		&self,
		block_hash: Self::BlockHash,
		range: Range<usize>,
	) -> Self::PendingEventsStream;
	/// Is server key generation request response required?
	fn is_server_key_generation_response_required(
		&self,
		key_id: ServerKeyId,
		key_server_id: KeyServerId,
	) -> Self::ResponseRequiredFuture;

	/// Get pending server key retrieval tasks range at given block.
	fn server_key_retrieval_tasks(
		&self,
		block_hash: Self::BlockHash,
		range: Range<usize>,
	) -> Self::PendingEventsStream;
	/// Is server key retrieval request response required?
	fn is_server_key_retrieval_response_required(
		&self,
		key_id: ServerKeyId,
		key_server_id: KeyServerId,
	) -> Self::ResponseRequiredFuture;

	/// Get pending document key store tasks range at given block.
	fn document_key_store_tasks(
		&self,
		block_hash: Self::BlockHash,
		range: Range<usize>,
	) -> Self::PendingEventsStream;
	/// Is document key store request response required?
	fn is_document_key_store_response_required(
		&self,
		key_id: ServerKeyId,
		key_server_id: KeyServerId,
	) -> Self::ResponseRequiredFuture;

	/// Get pending document key shadow retrieval tasks range at given block.
	fn document_key_shadow_retrieval_tasks(
		&self,
		block_hash: Self::BlockHash,
		range: Range<usize>,
	) -> Self::PendingEventsStream;
	/// Is document key shadow retrieval request response required?
	fn is_document_key_shadow_retrieval_response_required(
		&self,
		key_id: ServerKeyId,
		requester: Address,
		key_server_id: KeyServerId,
	) -> Self::ResponseRequiredFuture;
}

/// Transaction pool API.
pub trait TransactionPool: Send + Sync + 'static {
	/// Transaction hash.
	type TransactionHash: std::fmt::Display;
	/// Future that results in submitted transaction hash.
	type SubmitTransactionFuture: Future<Output = Result<Self::TransactionHash, String>> + Send;

	/// Submit transaction to the pool.
	fn submit_transaction(&self, call: SecretStoreCall) -> Self::SubmitTransactionFuture;
}

/// Substrate block passed to the blockchain service.
struct SubstrateBlock<B: Blockchain> {
	/// Origin block.
	pub block_hash: B::BlockHash,
	/// Shared blockchain reference.
	pub blockchain: Arc<B>,
	/// This server key address.
	pub key_server_address: Address,
}

/// Start listening requests from given contract.
pub fn start_service<B, E, TP, KSrv, KStr>(
	key_server: Arc<KSrv>,
	key_storage: Arc<KStr>,
	listener_registrar: Arc<dyn ServiceTasksListenerRegistrar>,
	blockchain: Arc<B>,
	executor: Arc<E>,
	transaction_pool: Arc<TP>,
	config: Configuration,
	new_blocks_stream: impl Stream<Item = B::BlockHash> + Send + 'static,
) -> Result<(), Error> where
	B: Blockchain,
	E: Executor,
	TP: TransactionPool,
	KSrv: KeyServer,
	KStr: KeyStorage,
{
	let key_server_address = config.self_id;
	let transaction_pool = Arc::new(SubstrateTransactionPool::new(
		executor.clone(),
		blockchain.clone(),
		transaction_pool,
		key_server_address.clone(),
	));
	let new_blocks_future = blockchain_service::start_service(
		key_server,
		key_storage,
		listener_registrar,
		executor.clone(),
		transaction_pool,
		config,
		new_blocks_stream
			.map(move |block_hash| SubstrateBlock {
				block_hash,
				blockchain: blockchain.clone(),
				key_server_address: key_server_address.clone(),
			})
	);
	executor.spawn(new_blocks_future
		.map(|err| trace!(
			target: "secretstore",
			"Blockhain service future failed: {:?}",
			err,
		))
		.boxed()
	);
	Ok(())
}

impl<B: Blockchain> blockchain_service::Block for SubstrateBlock<B> {
	type NewTasksStream = Pin<Box<dyn Stream<Item = BlockchainServiceTask> + Send>>;
	type PendingTasksStream = Pin<Box<dyn Stream<Item = BlockchainServiceTask> + Send>>;
	type CurrentKeyServersSetFuture = Pin<Box<dyn Future<Output = BTreeSet<KeyServerId>> + Send>>;

	fn new_tasks(&self) -> Self::NewTasksStream {
		self.blockchain
			.block_events(self.block_hash.clone())
			.filter_map(|evt| ready(MaybeSecretStoreEvent::as_secret_store_event(evt)))
			.boxed()
	}

	fn pending_tasks(&self) -> Self::PendingTasksStream {
		pending_tasks_stream(
			self.blockchain.clone(),
			self.block_hash.clone(),
			|blockchain, block_hash, range| blockchain.server_key_generation_tasks(
				block_hash,
				range,
			),
		).chain(pending_tasks_stream(
			self.blockchain.clone(),
			self.block_hash.clone(),
			|blockchain, block_hash, range| blockchain.server_key_retrieval_tasks(
				block_hash,
				range,
			),
		)).chain(pending_tasks_stream(
			self.blockchain.clone(),
			self.block_hash.clone(),
			|blockchain, block_hash, range| blockchain.document_key_store_tasks(
				block_hash,
				range,
			),
		)).chain(pending_tasks_stream(
			self.blockchain.clone(),
			self.block_hash.clone(),
			|blockchain, block_hash, range| blockchain.document_key_shadow_retrieval_tasks(
				block_hash,
				range,
			),
		)).boxed()
	}

	fn current_key_servers_set(&self) -> Self::CurrentKeyServersSetFuture {
		self.blockchain.current_key_servers_set().boxed()
	}
}

/// Returns pending tasks stream.
fn pending_tasks_stream<B: Blockchain, S: Stream<Item = B::Event> + Send>(
	blockchain: Arc<B>,
	block_hash: B::BlockHash,
	get_pending_tasks: impl Fn(Arc<B>, B::BlockHash, Range<usize>) -> S + Send + Sync + 'static,
) -> impl Stream<Item = BlockchainServiceTask> + Send {
	const PENDING_RANGE_LENGTH: usize = 16;

	futures::stream::unfold(
		(blockchain, block_hash, get_pending_tasks, VecDeque::new(), 0..std::usize::MAX),
		|(blockchain, block_hash, get_pending_tasks, mut pending, mut range)| async move {
			loop {
				if let Some(pending_task) = pending.pop_front() {
					return Some((pending_task, (blockchain, block_hash, get_pending_tasks, pending, range)));
				}

				if range.start == range.end {
					return None;
				}

				let next_range_start = range.start + PENDING_RANGE_LENGTH;
				let pending_range = range.start..next_range_start;
				pending = get_pending_tasks(blockchain.clone(),block_hash.clone(),pending_range)
					.filter_map(|event| ready(MaybeSecretStoreEvent::as_secret_store_event(event)))
					.collect()
					.await;

				if pending.len() == PENDING_RANGE_LENGTH {
					range = next_range_start..range.end;
				} else {
					range = range.end..range.end;
				}
			}
		},
	)
}
