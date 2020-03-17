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
	ops::Range,
	pin::Pin,
	sync::Arc,
};
use futures::{
	FutureExt, Stream, StreamExt,
	future::{Ready, TryFutureExt, ready},
};
use log::error;
use codec::Encode;
use primitives::{
	Address, KeyServerId, ServerKeyId,
	key_server_set::KeyServerSet,
	requester::Requester,
	service::ServiceTask,
};
use substrate_service::{
	Blockchain, BlockchainServiceTask, MaybeSecretStoreEvent,
};
use crate::{
	key_server_set::OnChainKeyServerSet,
	substrate_client::{BlockRef, Client},
};

/// Substrate-based blockhain that runs SecretStore module.
pub struct SecretStoreBlockchain {
	/// RPC client that can call RPC on full (presumably archive node) that
	/// is synching the blockhain.
	client: Client,
	/// On-chain key server set.
	key_server_set: Arc<OnChainKeyServerSet>,
}

/// Substrate runtime event wrapper.
#[derive(Debug)]
pub enum SubstrateServiceTaskWrapper {
	/// Variant for new tasks.
	Event(crate::runtime::Event),
	/// Variant for pending tasks.
	Task(runtime_primitives::service::ServiceTask),
}

impl SecretStoreBlockchain {
	/// Create new blockchain.
	pub fn new(client: Client, key_server_set: Arc<OnChainKeyServerSet>) -> SecretStoreBlockchain {
		SecretStoreBlockchain {
			client,
			key_server_set,
		}
	}

	/// Read pending tasks using given method.
	fn pending_tasks(
		&self,
		block_hash: crate::runtime::BlockHash,
		method: &'static str,
		range: Range<usize>,
	) -> impl Stream<Item = SubstrateServiceTaskWrapper> {
		self.client.call_runtime_method(
			BlockRef::Hash(block_hash),
			method,
			serialize_range(range),
		).then(|result: Result<Vec<runtime_primitives::service::ServiceTask>, crate::substrate_client::Error>|
			ready(match result {
				Ok(tasks) => futures::stream::iter(
					tasks.into_iter().map(SubstrateServiceTaskWrapper::Task)
				).boxed(),
				Err(error) => {
					error!(
						target: "secretstore",
						"Failed to read pending tasks: {:?}",
						error,
					);

					futures::stream::empty().boxed()
				}
			})
		).flatten_stream()
	}

	/// Is response required?
	fn is_response_required(
		&self,
		method: &'static str,
		arguments: Vec<u8>,
	) -> impl Future<Output = Result<bool, String>> {
		self.client.call_runtime_method(
			BlockRef::RemoteBest,
			method,
			arguments,
		).map_err(|error| format!("{:?}", error))
	}
}

impl Blockchain for SecretStoreBlockchain {
	type BlockHash = crate::runtime::BlockHash;
	type Event = SubstrateServiceTaskWrapper;
	type BlockEventsStream = Pin<Box<dyn Stream<Item = Self::Event> + Send>>;
	type PendingEventsStream = Pin<Box<dyn Stream<Item = Self::Event> + Send>>;
	type CurrentKeyServersSetFuture = Ready<BTreeSet<KeyServerId>>;
	type ResponseRequiredFuture = Pin<Box<dyn Future<Output = Result<bool, String>> + Send>>;

	fn block_events(&self, block_hash: Self::BlockHash) -> Self::BlockEventsStream {
		self.client
			.header_events(block_hash)
			.map(move |events| match events {
				Ok(events) => futures::stream::iter(
					events.into_iter().map(|event| SubstrateServiceTaskWrapper::Event(event.event))
				).boxed(),
				Err(error) => {
					error!(
						target: "secretstore",
						"Failed to read block {} events: {:?}",
						block_hash,
						error,
					);

					futures::stream::empty().boxed()
				}
			})
			.flatten_stream()
			.boxed()
	}

	fn current_key_servers_set(&self) -> Self::CurrentKeyServersSetFuture {
		ready(self.key_server_set.snapshot().current_set.keys().cloned().collect())
	}

	fn server_key_generation_tasks(
		&self,
		block_hash: Self::BlockHash,
		range: Range<usize>,
	) -> Self::PendingEventsStream {
		self.pending_tasks(
			block_hash,
			"SecretStoreServiceApi_server_key_generation_tasks",
			range,
		).boxed()
	}

	fn is_server_key_generation_response_required(
		&self,
		key_id: ServerKeyId,
		key_server_id: KeyServerId,
	) -> Self::ResponseRequiredFuture {
		self.is_response_required(
			"SecretStoreServiceApi_is_server_key_generation_response_required",
			(key_server_id, key_id).encode(),
		).boxed()
	}

	fn server_key_retrieval_tasks(
		&self,
		block_hash: Self::BlockHash,
		range: Range<usize>,
	) -> Self::PendingEventsStream {
		self.pending_tasks(
			block_hash,
			"SecretStoreServiceApi_server_key_retrieval_tasks",
			range,
		).boxed()
	}

	fn is_server_key_retrieval_response_required(
		&self,
		key_id: ServerKeyId,
		key_server_id: KeyServerId,
	) -> Self::ResponseRequiredFuture {
		self.is_response_required(
			"SecretStoreServiceApi_is_server_key_retrieval_response_required",
			(key_server_id, key_id).encode(),
		).boxed()
	}

	fn document_key_store_tasks(
		&self,
		block_hash: Self::BlockHash,
		range: Range<usize>,
	) -> Self::PendingEventsStream {
		self.pending_tasks(
			block_hash,
			"SecretStoreServiceApi_document_key_store_tasks",
			range,
		).boxed()
	}

	fn is_document_key_store_response_required(
		&self,
		key_id: ServerKeyId,
		key_server_id: KeyServerId,
	) -> Self::ResponseRequiredFuture {
		self.is_response_required(
			"SecretStoreServiceApi_is_document_key_store_response_required",
			(key_server_id, key_id).encode(),
		).boxed()
	}

	fn document_key_shadow_retrieval_tasks(
		&self,
		block_hash: Self::BlockHash,
		range: Range<usize>,
	) -> Self::PendingEventsStream {
		self.pending_tasks(
			block_hash,
			"SecretStoreServiceApi_document_key_shadow_retrieval_tasks",
			range,
		).boxed()
	}

	fn is_document_key_shadow_retrieval_response_required(
		&self,
		key_id: ServerKeyId,
		requester: Address,
		key_server_id: KeyServerId,
	) -> Self::ResponseRequiredFuture {
		self.is_response_required(
			"SecretStoreServiceApi_is_document_key_shadow_retrieval_response_required",
			(key_server_id, key_id, requester).encode(),
		).boxed()
	}
}

impl MaybeSecretStoreEvent for SubstrateServiceTaskWrapper {
	fn as_secret_store_event(self) -> Option<BlockchainServiceTask> {
		let origin = Default::default();

		match self {
			SubstrateServiceTaskWrapper::Event(
				crate::runtime::Event::secretstore_runtime_module(
					runtime_module::Event::ServerKeyGenerationRequested(
						key_id, requester_address, threshold,
					),
				)
			) => Some(BlockchainServiceTask::Regular(
				origin,
				ServiceTask::GenerateServerKey(
					key_id, Requester::Address(requester_address), threshold as usize,
				)
			)),
			SubstrateServiceTaskWrapper::Task(
				runtime_primitives::service::ServiceTask::GenerateServerKey(
					key_id, requester_address, threshold,
				)
			) => Some(BlockchainServiceTask::Regular(
				origin,
				ServiceTask::GenerateServerKey(
					key_id, Requester::Address(requester_address), threshold as usize,
				)
			)),
			SubstrateServiceTaskWrapper::Event(
				crate::runtime::Event::secretstore_runtime_module(
					runtime_module::Event::ServerKeyRetrievalRequested(
						key_id,
					),
				)
			) => Some(BlockchainServiceTask::Regular(
				origin,
				ServiceTask::RetrieveServerKey(
					key_id, None,
				)
			)),
			SubstrateServiceTaskWrapper::Task(
				runtime_primitives::service::ServiceTask::RetrieveServerKey(
					key_id,
				)
			) => Some(BlockchainServiceTask::Regular(
				origin,
				ServiceTask::RetrieveServerKey(
					key_id, None,
				)
			)),
			SubstrateServiceTaskWrapper::Event(
				crate::runtime::Event::secretstore_runtime_module(
					runtime_module::Event::DocumentKeyStoreRequested(
						key_id, author, common_point, encrypted_point,
					),
				)
			) => Some(BlockchainServiceTask::Regular(
				origin,
				ServiceTask::StoreDocumentKey(
					key_id, Requester::Address(author), common_point, encrypted_point,
				)
			)),
			SubstrateServiceTaskWrapper::Task(
				runtime_primitives::service::ServiceTask::StoreDocumentKey(
					key_id, author, common_point, encrypted_point,
				)
			) => Some(BlockchainServiceTask::Regular(
				origin,
				ServiceTask::StoreDocumentKey(
					key_id, Requester::Address(author), common_point, encrypted_point,
				)
			)),
			SubstrateServiceTaskWrapper::Event(
				crate::runtime::Event::secretstore_runtime_module(
					runtime_module::Event::DocumentKeyShadowRetrievalRequested(
						key_id, requester_address,
					),
				)
			) => Some(BlockchainServiceTask::RetrieveShadowDocumentKeyCommon(
				origin,
				key_id,
				Requester::Address(requester_address),
			)),
			SubstrateServiceTaskWrapper::Task(
				runtime_primitives::service::ServiceTask::RetrieveShadowDocumentKeyCommon(
					key_id, requester_address,
				)
			) => Some(BlockchainServiceTask::RetrieveShadowDocumentKeyCommon(
				origin,
				key_id,
				Requester::Address(requester_address),
			)),
			SubstrateServiceTaskWrapper::Event(
				crate::runtime::Event::secretstore_runtime_module(
					runtime_module::Event::DocumentKeyPersonalRetrievalRequested(
						key_id, requester_public,
					),
				)
			) => Some(BlockchainServiceTask::RetrieveShadowDocumentKeyPersonal(
				origin,
				key_id,
				Requester::Public(requester_public),
			)),
			SubstrateServiceTaskWrapper::Task(
				runtime_primitives::service::ServiceTask::RetrieveShadowDocumentKeyPersonal(
					key_id, requester_public,
				)
			) => Some(BlockchainServiceTask::RetrieveShadowDocumentKeyPersonal(
				origin,
				key_id,
				Requester::Public(requester_public),
			)),
			_ => None,
		}
	}
}

fn serialize_range(range: Range<usize>) -> Vec<u8> {
	(range.start as u32, range.end as u32).encode()
}
