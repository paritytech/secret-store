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

use std::sync::Arc;
use log::{error, trace};
use primitives::{
	Address, ServerKeyId,
	key_server::{
		ServerKeyGenerationArtifacts, ServerKeyRetrievalArtifacts,
		DocumentKeyCommonRetrievalArtifacts, DocumentKeyShadowRetrievalArtifacts,
	},
	requester::Requester,
};
use crate::{
	Blockchain, SecretStoreCall, TransactionPool,
};

/// Substrate transction pool.
pub struct SubstrateTransactionPool<B, P> {
	/// Shared blockchain reference.
	blockchain: Arc<B>,
	/// Shared reference to actual transaction pool.
	transaction_pool: Arc<P>,
	/// This key server address.
	key_server_address: Address,
}

impl<B, P> SubstrateTransactionPool<B, P>
	where
		B: Blockchain,
		P: TransactionPool,
{
	/// Create new transaction pool.
	pub fn new(
		blockchain: Arc<B>,
		transaction_pool: Arc<P>,
		key_server_address: Address,
	) -> Self {
		SubstrateTransactionPool {
			blockchain,
			transaction_pool,
			key_server_address,
		}
	}

	/// Send response transaction if required.
	fn submit_response_transaction(
		&self,
		format_request: impl Fn() -> String,
		is_response_required: impl FnOnce() -> Result<bool, String>,
		prepare_response: impl FnOnce() -> Result<SecretStoreCall, String>,
	) {
		match is_response_required() {
			Ok(true) => (),
			Ok(false) => {
				trace!(
					target: "secretstore",
					"Response {} is not required. Transaction is not submitted.",
					format_request(),
				);

				return
			},
			Err(error) => error!(
				target: "secretstore",
				"Failed to check if response {} is required: {}",
				format_request(),
				error,
			),
		}

		let submit_result = prepare_response()
			.and_then(|transaction| self
				.transaction_pool
				.submit_transaction(transaction)
			);

		match submit_result {
			Ok(transaction_hash) => trace!(
				target: "secretstore",
				"Submitted response {}: {}",
				format_request(),
				transaction_hash,
			),
			Err(error) => error!(
				target: "secretstore",
				"Failed to submit response {}: {}",
				format_request(),
				error,
			),
		}
	}
}

impl<B, P> blockchain_service::TransactionPool
	for
		SubstrateTransactionPool<B, P>
	where
		B: Blockchain,
		P: TransactionPool,
{
	fn publish_generated_server_key(
		&self,
		_origin: Address,
		key_id: ServerKeyId,
		artifacts: ServerKeyGenerationArtifacts,
	) {
		self.submit_response_transaction(
			|| format!("ServerKeyGenerationSuccess({})", key_id),
			|| self.blockchain.is_server_key_generation_response_required(key_id, self.key_server_address),
			|| Ok(SecretStoreCall::ServerKeyGenerated(key_id, artifacts.key)),
		)
	}

	fn publish_server_key_generation_error(&self, _origin: Address, key_id: ServerKeyId) {
		self.submit_response_transaction(
			|| format!("ServerKeyGenerationFailure({})", key_id),
			|| self.blockchain.is_server_key_generation_response_required(key_id, self.key_server_address),
			|| Ok(SecretStoreCall::ServerKeyGenerationError(key_id)),
		)
	}

	fn publish_retrieved_server_key(
		&self,
		_origin: Address,
		key_id: ServerKeyId,
		artifacts: ServerKeyRetrievalArtifacts,
	) {
		self.submit_response_transaction(
			|| format!("ServerKeyRetrievalSuccess({})", key_id),
			|| self.blockchain.is_server_key_retrieval_response_required(key_id, self.key_server_address),
			|| serialize_threshold(artifacts.threshold)
				.map(|threshold| SecretStoreCall::ServerKeyRetrieved(key_id, artifacts.key, threshold)),
		)
	}

	fn publish_server_key_retrieval_error(&self, _origin: Address, key_id: ServerKeyId) {
		self.submit_response_transaction(
			|| format!("ServerKeyRetrievalFailure({})", key_id),
			|| self.blockchain.is_server_key_retrieval_response_required(key_id, self.key_server_address),
			|| Ok(SecretStoreCall::ServerKeyRetrievalError(key_id)),
		)
	}

	fn publish_stored_document_key(&self, _origin: Address, key_id: ServerKeyId) {
		self.submit_response_transaction(
			|| format!("DocumentKeyStoreSuccess({})", key_id),
			|| self.blockchain.is_document_key_store_response_required(key_id, self.key_server_address),
			|| Ok(SecretStoreCall::DocumentKeyStored(key_id)),
		)
	}

	fn publish_document_key_store_error(&self, _origin: Address, key_id: ServerKeyId) {
		self.submit_response_transaction(
			|| format!("DocumentKeyStoreFailure({})", key_id),
			|| self.blockchain.is_document_key_store_response_required(key_id, self.key_server_address),
			|| Ok(SecretStoreCall::DocumentKeyStoreError(key_id)),
		)
	}

	fn publish_retrieved_document_key_common(
		&self,
		_origin: Address,
		key_id: ServerKeyId,
		requester: Requester,
		artifacts: DocumentKeyCommonRetrievalArtifacts,
	) {
		self.submit_response_transaction(
			|| format!("DocumentKeyCommonRetrievalSuccess({}, {})", key_id, requester),
			|| requester
				.address(&key_id)
				.map_err(Into::into)
				.and_then(|requester|
					self.blockchain
						.is_document_key_shadow_retrieval_response_required(
							key_id,
							requester,
							self.key_server_address,
						)
				),
			|| serialize_threshold(artifacts.threshold)
				.and_then(|threshold|
					requester
						.address(&key_id)
						.map_err(Into::into)
						.map(|requester| (threshold, requester))
				)
				.map(|(threshold, requester)| SecretStoreCall::DocumentKeyCommonRetrieved(
					key_id,
					requester,
					artifacts.common_point,
					threshold,
				)),
		)
	}

	fn publish_document_key_common_retrieval_error(
		&self,
		_origin: Address,
		key_id: ServerKeyId,
		requester: Requester,
	) {
		self.submit_response_transaction(
			|| format!("DocumentKeyCommonRetrievalFailure({}, {})", key_id, requester),
			|| requester
				.address(&key_id)
				.map_err(Into::into)
				.and_then(|requester|
					self.blockchain
						.is_document_key_shadow_retrieval_response_required(
							key_id,
							requester,
							self.key_server_address,
						)
				),
			|| requester
				.address(&key_id)
				.map_err(Into::into)
				.map(|requester| SecretStoreCall::DocumentKeyShadowRetrievalError(
					key_id,
					requester,
				)),
		)
	}

	fn publish_retrieved_document_key_personal(
		&self,
		_origin: Address,
		key_id: ServerKeyId,
		requester: Requester,
		artifacts: DocumentKeyShadowRetrievalArtifacts,
	) {
		self.submit_response_transaction(
			|| format!("DocumentKeyPersonalRetrievalSuccess({}, {})", key_id, requester),
			|| requester
				.address(&key_id)
				.map_err(Into::into)
				.and_then(|requester|
					self.blockchain
						.is_document_key_shadow_retrieval_response_required(
							key_id,
							requester,
							self.key_server_address,
						)
				),
			|| {
				let self_coefficient = artifacts
					.participants_coefficients
					.get(&self.key_server_address)
					.cloned()
					.ok_or_else(|| String::from(
						"DocumentKeyPersonalRetrieval session has completed without self coefficient",
					))?;

				requester
					.address(&key_id)
					.map_err(Into::into)
					.map(|requester| SecretStoreCall::DocumentKeyPersonalRetrieved(
						key_id,
						requester,
						artifacts.participants_coefficients.keys().cloned().collect::<Vec<_>>(),
						artifacts.encrypted_document_key,
						self_coefficient,
					))
			},
		)
	}

	fn publish_document_key_personal_retrieval_error(
		&self,
		_origin: Address,
		key_id: ServerKeyId,
		requester: Requester,
	) {
		self.submit_response_transaction(
			|| format!("DocumentKeyPersonalRetrievalFailure({}, {})", key_id, requester),
			|| requester
				.address(&key_id)
				.map_err(Into::into)
				.and_then(|requester|
					self.blockchain
						.is_document_key_shadow_retrieval_response_required(
							key_id,
							requester,
							self.key_server_address,
						)
				),
			|| requester
				.address(&key_id)
				.map_err(Into::into)
				.map(|requester| SecretStoreCall::DocumentKeyShadowRetrievalError(
					key_id,
					requester,
				)),
		)
	}
}

/// Serialize threshold (we only support 256 KS at max).
pub fn serialize_threshold(threshold: usize) -> Result<u8, String> {
	if threshold > ::std::u8::MAX as usize {
		return Err(format!("invalid threshold to use in service contract: {}", threshold));
	}
	Ok(threshold as _)
}
