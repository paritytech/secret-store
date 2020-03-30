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
	collections::BTreeSet,
	future::Future,
	pin::Pin,
	sync::Arc,
};
use futures::{Stream, StreamExt};
use ethabi::RawLog;
use ethereum_types::{Address, H256};
use parity_bytes::Bytes;
use parking_lot::RwLock;
use primitives::{
	KeyServerId,
	error::Error,
	executor::Executor,
	key_server::KeyServer,
	key_storage::KeyStorage,
	service::ServiceTasksListenerRegistrar,
};
use crate::{
	document_key_shadow_retrieval::DocumentKeyShadowRetrievalService,
	document_key_store::DocumentKeyStoreService,
	server_key_generation::ServerKeyGenerationService,
	server_key_retrieval::ServerKeyRetrievalService,
	services::{prepare_topics_filter, try_parse_contract_log},
	transaction_pool::EthereumTransactionPool,
};

// hide blockchain-service dependency
pub use blockchain_service::{
	Configuration as BlockchainServiceConfiguration,
};

pub type BlockchainServiceTask = blockchain_service::BlockchainServiceTask;

mod document_key_shadow_retrieval;
mod document_key_store;
mod server_key_generation;
mod server_key_retrieval;
mod services;
mod transaction_pool;

/// Ethereum block provided by the caller.
pub struct Block {
	/// Block number.
	pub number: u32,
	/// Block hash.
	pub hash: H256,
}

/// Ethereum block id.
pub enum BlockId {
	/// Use block referenced by the hash.
	Hash(H256),
	/// Use best known block.
	Best,
}

/// Ethereum blockchain.
pub trait Blockchain: 'static + Send + Sync {
	/// Future that returns address of contract at given block.
	type ContractAddressFuture: Future<Output = Option<Address>> + Send;
	/// Future that returns logs of contract at given block.
	type LogsFuture: Future<Output = Vec<RawLog>> + Send;
	/// Future that returns result of contract call at given block.
	type ContractCallFuture: Future<Output = Result<Bytes, String>> + Send;
	/// Future that returns current key servers set.
	type CurrentKeyServersSetFuture: Future<Output = BTreeSet<KeyServerId>> + Send;

	/// Get address of given contract by its name.
	fn contract_address(&self, block_id: H256, name: &str) -> Self::ContractAddressFuture;
	/// Get logs of given contract at given block.
	fn contract_logs(&self, block_id: H256, address: Address, topics_filter: &[H256]) -> Self::LogsFuture;
	/// Call contract function with given arguments.
	fn contract_call(&self, block_id: BlockId, address: Address, data: Bytes) -> Self::ContractCallFuture;
	/// Get current key servers set. This should return current key servers set at the best
	/// known (finalized) block. That's because we use this to determine key server which
	/// will should start corresponding session AND the session starts at the time when
	/// current set should have been read from the best block.
	fn current_key_servers_set(&self) -> Self::CurrentKeyServersSetFuture;
}

/// Transaction pool API.
pub trait TransactionPool: Send + Sync + 'static {
	/// Future that results in submitted transaction hash.
	type SubmitTransactionFuture: Future<Output = Result<H256, String>> + Send;

	/// Submit transaction to the pool.
	fn submit_transaction(&self, transaction: Bytes) -> Self::SubmitTransactionFuture;
}

/// Contract address.
pub enum ContractAddress {
	/// Contract address is hardcoded.
	Address(Address),
	/// Contract address is read from the registry under given name.
	Registry(&'static str),
}

/// Ethereum service configuration.
pub struct Configuration {
	/// Address of the service contract.
	pub contract_address: ContractAddress,
	/// Accept server key generation requests.
	pub server_key_generation_requests: bool,
	/// Accept server key retrieval requests.
	pub server_key_retrieval_requests: bool,
	/// Accept document key store requests.
	pub document_key_store_requests: bool,
	/// Accept document key shadow retrieval requests.
	pub document_key_shadow_retrieval_requests: bool,
	/// Blockchain service configuration.
	pub blockchain_service_config: BlockchainServiceConfiguration,
}

/// Ethereum block passed to the blockchain service.
struct EthereumBlock<B> {
	/// Origin block.
	pub block: Block,
	/// Service configuration.
	pub config: Arc<Configuration>,
	/// Topics filter.
	pub topics_filter: Arc<Vec<H256>>,
	/// Shared blockchain reference.
	pub blockchain: Arc<B>,
	/// This server key address.
	pub key_server_address: Address,
	/// Contract address. Some if has been read for this block already.
	pub cached_contract_address: Arc<RwLock<Option<Option<Address>>>>,
}

/// Start listening requests from given contract.
pub async fn start_service<B, E, TP, KSrv, KStr, LR>(
	key_server: Arc<KSrv>,
	key_storage: Arc<KStr>,
	listener_registrar: Arc<LR>,
	blockchain: Arc<B>,
	executor: Arc<E>,
	transaction_pool: Arc<TP>,
	config: Configuration,
	new_blocks_stream: impl Stream<Item = Block>,
) -> Result<(), Error> where
	B: Blockchain,
	E: Executor,
	TP: TransactionPool,
	LR: ServiceTasksListenerRegistrar + 'static,
	KSrv: KeyServer,
	KStr: KeyStorage,
{
	let topics_filter = Arc::new(prepare_topics_filter(&config));
	let config = Arc::new(config);
	let key_server_address = config.blockchain_service_config.self_id;
	let transaction_pool = Arc::new(EthereumTransactionPool::new(
		executor.clone(),
		blockchain.clone(),
		transaction_pool,
		key_server_address.clone(),
	));
	blockchain_service::start_service(
		key_server,
		key_storage,
		listener_registrar,
		executor,
		transaction_pool,
		config.blockchain_service_config.clone(),
		new_blocks_stream
			.map(|block| EthereumBlock {
				block,
				config: config.clone(),
				topics_filter: topics_filter.clone(),
				blockchain: blockchain.clone(),
				key_server_address: key_server_address.clone(),
				cached_contract_address: Arc::new(RwLock::new(None)),
			})
	).await
}

impl<B: Blockchain> std::fmt::Display for EthereumBlock<B> {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
		write!(f, "{}", self.block.hash)
	}
}

impl<B: Blockchain> blockchain_service::Block for EthereumBlock<B> {
	type NewTasksStream = Pin<Box<dyn Stream<Item = BlockchainServiceTask> + Send>>;
	type PendingTasksStream = Pin<Box<dyn Stream<Item = BlockchainServiceTask> + Send>>;
	type CurrentKeyServersSetFuture = B::CurrentKeyServersSetFuture;

	fn new_tasks(&self) -> Self::NewTasksStream {
		let blockchain = self.blockchain.clone();
		let block_hash = self.block.hash.clone();
		let topics_filter = self.topics_filter.clone();
		let config = self.config.clone();
		let cached_contract_address = self.cached_contract_address.clone();
		let stream_future = async move {
			let future_contract_address = read_contract_address(
				config.clone(),
				blockchain.clone(),
				block_hash,
				cached_contract_address,
			);
			let contract_address = match future_contract_address.await {
				Some(contract_address) => contract_address,
				None => return futures::stream::empty().boxed(),
			};

			futures::stream::iter(
				blockchain
					.contract_logs(
						block_hash,
						contract_address,
						&*topics_filter,
					)
					.await
					.into_iter()
					.filter_map(move |log| try_parse_contract_log(
						&*config,
						&contract_address,
						log,
					))
			).boxed()
		};

		futures::stream::once(stream_future)
			.flatten()
			.boxed()
	}

	fn pending_tasks(&self) -> Self::PendingTasksStream {
		let contract_address = read_contract_address(
			self.config.clone(),
			self.blockchain.clone(),
			self.block.hash.clone(),
			self.cached_contract_address.clone(),
		);

		let blockchain = self.blockchain.clone();
		let config = self.config.clone();
		let block = self.block.hash.clone();
		let key_server_address = self.key_server_address;
		futures::stream::once(contract_address)
			.map(move |contract_address| match contract_address {
				Some(contract_address) => ServerKeyGenerationService::create_pending_requests_iterator(
					blockchain.clone(),
					config.clone(),
					block.clone(),
					contract_address,
					key_server_address,
				).chain(ServerKeyRetrievalService::create_pending_requests_iterator(
					blockchain.clone(),
					config.clone(),
					block.clone(),
					contract_address,
					key_server_address,
				)).chain(DocumentKeyStoreService::create_pending_requests_iterator(
					blockchain.clone(),
					config.clone(),
					block.clone(),
					contract_address,
					key_server_address,
				)).chain(DocumentKeyShadowRetrievalService::create_pending_requests_iterator(
					blockchain.clone(),
					config.clone(),
					block.clone(),
					contract_address,
					key_server_address,
				)).boxed(),
				None => futures::stream::empty().boxed(),
			})
			.flatten()
			.boxed()
	}

	fn current_key_servers_set(&self) -> Self::CurrentKeyServersSetFuture {
		self.blockchain.current_key_servers_set()
	}
}

/// Read service contract address.
async fn read_contract_address<B: Blockchain>(
	config: Arc<Configuration>,
	blockchain: Arc<B>,
	block_hash: H256,
	cached_contract_address: Arc<RwLock<Option<Option<Address>>>>,
) -> Option<Address> {
	if let Some(contract_address) = cached_contract_address.read().clone() {
		return contract_address;
	}

	let contract_address = match config.contract_address {
		ContractAddress::Address(contract_address) => Some(contract_address),
		ContractAddress::Registry(contract_name) =>
			blockchain.contract_address(
				block_hash,
				contract_name,
			).await,
	};
	*cached_contract_address.write() = Some(contract_address);
	contract_address
}
