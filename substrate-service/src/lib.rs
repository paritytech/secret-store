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
	ops::Range,
	sync::Arc,
};
use futures::{FutureExt, Stream, StreamExt};
use log::error;
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
	type Event: MaybeSecretStoreEvent;
	/// Block events iterator type.
	type BlockEvents: IntoIterator<Item = Self::Event>;
	/// Pending events iterator type.
	type PendingEvents: IntoIterator<Item = Self::Event>;

	/// Get block events.
	fn block_events(&self, block_hash: Self::BlockHash) -> Self::BlockEvents;
	/// Get current key servers set. This should return current key servers set at the best
	/// known (finalized) block. That's because we use this to determine key server which
	/// will should start corresponding session AND the session starts at the time when
	/// current set should have been read from the best block.
	fn current_key_servers_set(&self) -> BTreeSet<KeyServerId>;

	/// Get pending server key generation tasks range at given block.
	fn server_key_generation_tasks(
		&self,
		block_hash: Self::BlockHash,
		range: Range<usize>,
	) -> Result<Self::PendingEvents, String>;
	/// Is server key generation request response required?
	fn is_server_key_generation_response_required(
		&self,
		key_id: ServerKeyId,
		key_server_id: KeyServerId,
	) -> Result<bool, String>;

	/// Get pending server key retrieval tasks range at given block.
	fn server_key_retrieval_tasks(
		&self,
		block_hash: Self::BlockHash,
		range: Range<usize>,
	) -> Result<Self::PendingEvents, String>;
	/// Is server key retrieval request response required?
	fn is_server_key_retrieval_response_required(
		&self,
		key_id: ServerKeyId,
		key_server_id: KeyServerId,
	) -> Result<bool, String>;

	/// Get pending document key store tasks range at given block.
	fn document_key_store_tasks(
		&self,
		block_hash: Self::BlockHash,
		range: Range<usize>,
	) -> Result<Self::PendingEvents, String>;
	/// Is document key store request response required?
	fn is_document_key_store_response_required(
		&self,
		key_id: ServerKeyId,
		key_server_id: KeyServerId,
	) -> Result<bool, String>;

	/// Get pending document key shadow retrieval tasks range at given block.
	fn document_key_shadow_retrieval_tasks(
		&self,
		block_hash: Self::BlockHash,
		range: Range<usize>,
	) -> Result<Self::PendingEvents, String>;
	/// Is document key shadow retrieval request response required?
	fn is_document_key_shadow_retrieval_response_required(
		&self,
		key_id: ServerKeyId,
		requester: Address,
		key_server_id: KeyServerId,
	) -> Result<bool, String>;
}

/// Transaction pool API.
pub trait TransactionPool: Send + Sync + 'static {
	/// Transaction hash.
	type TransactionHash: std::fmt::Display;

	/// Submit transaction to the pool.
	fn submit_transaction(&self, call: SecretStoreCall) -> Result<Self::TransactionHash, String>;
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
//	let config = Arc::new(config);
	let key_server_address = config.self_id;
	let transaction_pool = Arc::new(SubstrateTransactionPool::new(
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
		.map(|err| error!(
			target: "secretstore",
			"Blockhain service future failed: {:?}",
			err,
		))
		.boxed()
	);
	Ok(())
}

impl<B: Blockchain> blockchain_service::Block for SubstrateBlock<B> {
	type NewBlocksIterator = Box<dyn Iterator<Item = BlockchainServiceTask>>;
	type PendingBlocksIterator = Box<dyn Iterator<Item = BlockchainServiceTask>>;

	fn new_tasks(&self) -> Self::NewBlocksIterator {
		Box::new(
			self.blockchain
				.block_events(self.block_hash.clone())
				.into_iter()
				.filter_map(MaybeSecretStoreEvent::as_secret_store_event)
		)
	}

	fn pending_tasks(&self) -> Self::PendingBlocksIterator {
		let (blockchain, block_hash) = (self.blockchain.clone(), self.block_hash.clone());
		let server_key_generation_tasks = move |tasks: &mut VecDeque<BlockchainServiceTask>, range|
			Ok(tasks.extend(
				blockchain
					.server_key_generation_tasks(block_hash.clone(), range)?
					.into_iter()
					.filter_map(MaybeSecretStoreEvent::as_secret_store_event)
			));
		let (blockchain, block_hash) = (self.blockchain.clone(), self.block_hash.clone());
		let server_key_retrieval_tasks = move |tasks: &mut VecDeque<BlockchainServiceTask>, range|
			Ok(tasks.extend(
				blockchain
					.server_key_retrieval_tasks(block_hash.clone(), range)?
					.into_iter()
					.filter_map(MaybeSecretStoreEvent::as_secret_store_event)
			));
		let (blockchain, block_hash) = (self.blockchain.clone(), self.block_hash.clone());
		let document_key_store_tasks = move |tasks: &mut VecDeque<BlockchainServiceTask>, range|
			Ok(tasks.extend(
				blockchain
					.document_key_store_tasks(block_hash.clone(), range)?
					.into_iter()
					.filter_map(MaybeSecretStoreEvent::as_secret_store_event)
			));
		let (blockchain, block_hash) = (self.blockchain.clone(), self.block_hash.clone());
		let document_key_shadow_retrieval_tasks = move |tasks: &mut VecDeque<BlockchainServiceTask>, range|
			Ok(tasks.extend(
				blockchain
					.document_key_shadow_retrieval_tasks(block_hash.clone(), range)?
					.into_iter()
					.filter_map(MaybeSecretStoreEvent::as_secret_store_event)
			));

		Box::new(
			PendingTasksIterator {
				pending: VecDeque::new(),
				range: 0..std::usize::MAX,
				get_pending_tasks: server_key_generation_tasks,
			}.chain(PendingTasksIterator {
				pending: VecDeque::new(),
				range: 0..std::usize::MAX,
				get_pending_tasks: server_key_retrieval_tasks,
			}).chain(PendingTasksIterator {
				pending: VecDeque::new(),
				range: 0..std::usize::MAX,
				get_pending_tasks: document_key_store_tasks,
			}).chain(PendingTasksIterator {
				pending: VecDeque::new(),
				range: 0..std::usize::MAX,
				get_pending_tasks: document_key_shadow_retrieval_tasks,
			})
		)
	}

	fn current_key_servers_set(&self) -> BTreeSet<KeyServerId> {
		self.blockchain.current_key_servers_set()
	}
}

struct PendingTasksIterator<F> {
	pending: VecDeque<BlockchainServiceTask>,
	range: Range<usize>,
	get_pending_tasks: F,
}

impl<F> Iterator for PendingTasksIterator<F>
	where
		F: Fn(&mut VecDeque<BlockchainServiceTask>, Range<usize>) -> Result<(), String>,
{
	type Item = BlockchainServiceTask;

	fn next(&mut self) -> Option<Self::Item> {
		const PENDING_RANGE_LENGTH: usize = 16;

		loop {
			if let Some(pending_task) = self.pending.pop_front() {
				return Some(pending_task);
			}

			if self.range.start == self.range.end {
				return None;
			}

			let next_range_start = self.range.start + PENDING_RANGE_LENGTH;
			let pending_range = self.range.start..next_range_start;
			if let Err(error) = (self.get_pending_tasks)(&mut self.pending, pending_range) {
				error!(
					target: "secretstore",
					"Failed to read pending tasks: {}",
					error,
				);
			}

			if self.pending.len() == PENDING_RANGE_LENGTH {
				self.range = next_range_start..self.range.end;
			} else {
				self.range = self.range.end..self.range.end;
			}
		}
	}
}
