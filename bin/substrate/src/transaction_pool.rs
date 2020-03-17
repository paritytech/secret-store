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
	collections::HashMap,
	future::Future,
	pin::Pin,
};
use futures::{FutureExt, TryFutureExt};
use primitives::KeyServerId;
use substrate_service::{TransactionPool, SecretStoreCall};
use crate::{
	runtime::TransactionHash,
	substrate_client::{BlockRef, Client},
};

/// Transaction pool of Substrate node that runs blockchain with Secret Store module.
pub struct SecretStoreTransactionPool {
	client: Client,
}

impl SecretStoreTransactionPool {
	/// Create new transaction pool.
	pub fn new(client: Client) -> SecretStoreTransactionPool {
		SecretStoreTransactionPool { client }
	}
}

impl TransactionPool for SecretStoreTransactionPool {
	type TransactionHash = TransactionHash;
	type SubmitTransactionFuture = Pin<Box<dyn Future<Output = Result<Self::TransactionHash, String>> + Send>>;

	fn submit_transaction(&self, call: SecretStoreCall) -> Self::SubmitTransactionFuture {
		let client = self.client.clone();
		async move {
			client.submit_transaction(crate::runtime::Call::SecretStore(
				match call {
					SecretStoreCall::ServerKeyGenerated(key_id, key) =>
						crate::runtime::SecretStoreCall::server_key_generated(
							key_id,
							key,
						),
					SecretStoreCall::ServerKeyGenerationError(key_id) =>
						crate::runtime::SecretStoreCall::server_key_generation_error(
							key_id,
						),
					SecretStoreCall::ServerKeyRetrieved(key_id, key, threshold) =>
						crate::runtime::SecretStoreCall::server_key_retrieved(
							key_id,
							key,
							threshold,
						),
					SecretStoreCall::ServerKeyRetrievalError(key_id) =>
						crate::runtime::SecretStoreCall::server_key_retrieval_error(
							key_id,
						),
					SecretStoreCall::DocumentKeyStored(key_id) =>
						crate::runtime::SecretStoreCall::document_key_stored(
							key_id,
						),
					SecretStoreCall::DocumentKeyStoreError(key_id) =>
						crate::runtime::SecretStoreCall::document_key_store_error(
							key_id,
						),
					SecretStoreCall::DocumentKeyCommonRetrieved(key_id, requester, common_point, threshold) =>
						crate::runtime::SecretStoreCall::document_key_common_retrieved(
							key_id,
							requester,
							common_point,
							threshold,
						),
					SecretStoreCall::DocumentKeyPersonalRetrieved(key_id, requester, participants, decrypted_secret, shadow) => {
						// we're checking confirmation in Latest block, because tx is applied to the latest state
						let current_set_with_indices: Vec<(KeyServerId, u8)> = futures::executor::block_on(async {
							client.call_runtime_method(
								BlockRef::RemoteBest,
								"SecretStoreKeyServerSetApi_current_set_with_indices",
								Vec::new(),
							).await
						}).map_err(|err| format!("{:?}", err))?;
						let current_set_with_indices = current_set_with_indices.into_iter().collect::<HashMap<_, _>>();

						let mut participants_mask = runtime_primitives::KeyServersMask::default();
						for participant in participants {
							let index = current_set_with_indices.get(&participant)
								.ok_or_else(|| format!("Missing index for key server {}", participant))?;
							participants_mask = participants_mask.union(runtime_primitives::KeyServersMask::from_index(*index));
						}

						crate::runtime::SecretStoreCall::document_key_personal_retrieved(
							key_id,
							requester,
							participants_mask,
							decrypted_secret,
							shadow,
						)
					},
					SecretStoreCall::DocumentKeyShadowRetrievalError(key_id, requester) =>
						crate::runtime::SecretStoreCall::document_key_shadow_retrieval_error(
							key_id,
							requester,
						),
				}
			)).map_err(|err| format!("{:?}", err)).await
		}.boxed()
	}
}
