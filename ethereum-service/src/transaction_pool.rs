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
use futures::future::{Future, FutureExt, TryFutureExt, lazy, ready};
use log::{error, trace};
use ethereum_types::Address;
use parity_bytes::Bytes;
use primitives::{
	ServerKeyId,
	executor::Executor,
	key_server::{
		ServerKeyGenerationArtifacts, ServerKeyRetrievalArtifacts,
		DocumentKeyCommonRetrievalArtifacts, DocumentKeyShadowRetrievalArtifacts,
	},
	requester::Requester,
};
use crate::{
	Blockchain, TransactionPool,
	document_key_shadow_retrieval::DocumentKeyShadowRetrievalService,
	document_key_store::DocumentKeyStoreService,
	server_key_generation::ServerKeyGenerationService,
	server_key_retrieval::ServerKeyRetrievalService,
	services::serialize_threshold,
};

/// Ethereum transction pool.
pub struct EthereumTransactionPool<E, B, P> {
	/// Futures executor.
	executor: Arc<E>,
	/// Shared blockchain reference.
	blockchain: Arc<B>,
	/// Shared reference to actual transaction pool.
	transaction_pool: Arc<P>,
	/// This key server address.
	key_server_address: Address,
}

impl<E, B, P> EthereumTransactionPool<E, B, P>
	where
		E: Executor,
		B: Blockchain,
		P: TransactionPool,
{
	/// Create new transaction pool.
	pub fn new(
		executor: Arc<E>,
		blockchain: Arc<B>,
		transaction_pool: Arc<P>,
		key_server_address: Address,
	) -> Self {
		EthereumTransactionPool {
			executor,
			blockchain,
			transaction_pool,
			key_server_address,
		}
	}

	/// Send response transaction if required.
	fn submit_response_transaction(
		&self,
		contract_address: Address,
		formatted_request: String,
		is_response_required: impl Future<Output = Result<bool, String>> + Send + 'static,
		prepare_response: impl Future<Output = Result<Bytes, String>> + Send + 'static,
	) {
		let transaction_pool = self.transaction_pool.clone();
		let submit_transaction_future = async move {
			match is_response_required.await {
				Ok(true) => (),
				Ok(false) => return,
				Err(error) => {
					error!(
						target: "secretstore",
						"Failed to check if response {} at {} is required: {}",
						formatted_request,
						contract_address,
						error,
					);

					return
				},
			}

			let submit_result = prepare_response
				.and_then(|transaction| transaction_pool.submit_transaction(transaction))
				.await;
			match submit_result {
				Ok(transaction_hash) => trace!(
					target: "secretstore",
					"Submitted response {} at {}: {}",
					formatted_request,
					contract_address,
					transaction_hash,
				),
				Err(error) => error!(
					target: "secretstore",
					"Failed to submit response {} at {}: {}",
					formatted_request,
					contract_address,
					error,
				),
			}
		};

		self.executor.spawn(submit_transaction_future.boxed());
	}
}

impl<E, B, P> blockchain_service::TransactionPool
	for
		EthereumTransactionPool<E, B, P>
	where
		E: Executor,
		B: Blockchain,
		P: TransactionPool,
{
	fn publish_generated_server_key(
		&self,
		contract_address: Address,
		key_id: ServerKeyId,
		artifacts: ServerKeyGenerationArtifacts,
	) {
		self.submit_response_transaction(
			contract_address,
			format!("ServerKeyGenerationSuccess({})", key_id),
			ServerKeyGenerationService::is_response_required(
				self.blockchain.clone(),
				contract_address,
				key_id,
				self.key_server_address,
			),
			lazy(move |_| Ok(ServerKeyGenerationService::prepare_pubish_tx_data(
				&key_id,
				&artifacts.key,
			))),
		)
	}

	fn publish_server_key_generation_error(&self, contract_address: Address, key_id: ServerKeyId) {
		self.submit_response_transaction(
			contract_address,
			format!("ServerKeyGenerationFailure({})", key_id),
			ServerKeyGenerationService::is_response_required(
				self.blockchain.clone(),
				contract_address,
				key_id,
				self.key_server_address,
			),
			lazy(move |_| Ok(ServerKeyGenerationService::prepare_error_tx_data(
				&key_id,
			))),
		)
	}

	fn publish_retrieved_server_key(
		&self,
		contract_address: Address,
		key_id: ServerKeyId,
		artifacts: ServerKeyRetrievalArtifacts,
	) {
		self.submit_response_transaction(
			contract_address,
			format!("ServerKeyRetrievalSuccess({})", key_id),
			ServerKeyRetrievalService::is_response_required(
				self.blockchain.clone(),
				contract_address,
				key_id,
				self.key_server_address,
			),
			lazy(move |_| serialize_threshold(artifacts.threshold)
				.map(|threshold| ServerKeyRetrievalService::prepare_pubish_tx_data(
					&key_id,
					&artifacts.key,
					threshold)
				)
			),
		)
	}

	fn publish_server_key_retrieval_error(&self, contract_address: Address, key_id: ServerKeyId) {
		self.submit_response_transaction(
			contract_address,
			format!("ServerKeyRetrievalFailure({})", key_id),
			ServerKeyRetrievalService::is_response_required(
				self.blockchain.clone(),
				contract_address,
				key_id,
				self.key_server_address,
			),
			lazy(move |_| Ok(ServerKeyRetrievalService::prepare_error_tx_data(
				&key_id,
			))),
		)
	}

	fn publish_stored_document_key(&self, contract_address: Address, key_id: ServerKeyId) {
		self.submit_response_transaction(
			contract_address,
			format!("DocumentKeyStoreSuccess({})", key_id),
			DocumentKeyStoreService::is_response_required(
				self.blockchain.clone(),
				contract_address,
				key_id,
				self.key_server_address,
			),
			lazy(move |_| Ok(DocumentKeyStoreService::prepare_pubish_tx_data(
				&key_id,
			))),
		)
	}

	fn publish_document_key_store_error(&self, contract_address: Address, key_id: ServerKeyId) {
		self.submit_response_transaction(
			contract_address,
			format!("DocumentKeyStoreFailure({})", key_id),
			DocumentKeyStoreService::is_response_required(
				self.blockchain.clone(),
				contract_address,
				key_id,
				self.key_server_address,
			),
			lazy(move |_| Ok(DocumentKeyStoreService::prepare_error_tx_data(
				&key_id,
			))),
		)
	}

	fn publish_retrieved_document_key_common(
		&self,
		contract_address: Address,
		key_id: ServerKeyId,
		requester: Requester,
		artifacts: DocumentKeyCommonRetrievalArtifacts,
	) {
		let blockchain = self.blockchain.clone();
		let key_server_address = self.key_server_address;
		self.submit_response_transaction(
			contract_address,
			format!("DocumentKeyCommonRetrievalSuccess({}, {})", key_id, requester),
			ready(requester.address(&key_id).map_err(Into::into))
				.and_then(move |requester| DocumentKeyShadowRetrievalService::is_response_required(
					blockchain,
					contract_address,
					key_id,
					requester,
					key_server_address,
				)),
			lazy(move |_| serialize_threshold(artifacts.threshold)
				.and_then(|threshold| requester
					.address(&key_id)
					.map_err(Into::into)
					.map(|requester| (threshold, requester))
				)
				.map(|(threshold, requester)| DocumentKeyShadowRetrievalService::prepare_pubish_common_tx_data(
					&key_id,
					&requester,
					&artifacts.common_point,
					threshold,
				))),
		)
	}

	fn publish_document_key_common_retrieval_error(
		&self,
		contract_address: Address,
		key_id: ServerKeyId,
		requester: Requester,
	) {
		let blockchain = self.blockchain.clone();
		let key_server_address = self.key_server_address;
		self.submit_response_transaction(
			contract_address,
			format!("DocumentKeyCommonRetrievalFailure({}, {})", key_id, requester),
			ready(requester.address(&key_id).map_err(Into::into))
				.and_then(move |requester| DocumentKeyShadowRetrievalService::is_response_required(
					blockchain,
					contract_address,
					key_id,
					requester,
					key_server_address,
				)),
			lazy(move |_| requester
				.address(&key_id)
				.map_err(Into::into)
				.map(|requester|
					DocumentKeyShadowRetrievalService::prepare_error_tx_data(&key_id, &requester)
				)),
		)
	}

	fn publish_retrieved_document_key_personal(
		&self,
		contract_address: Address,
		key_id: ServerKeyId,
		requester: Requester,
		artifacts: DocumentKeyShadowRetrievalArtifacts,
	) {
		let blockchain = self.blockchain.clone();
		let key_server_address = self.key_server_address;
		let blockchain_copy = blockchain.clone();
		let artifacts_copy = artifacts.clone();
		self.submit_response_transaction(
			contract_address,
			format!("DocumentKeyPersonalRetrievalSuccess({}, {})", key_id, requester),
			ready(requester.address(&key_id).map_err(Into::into))
				.and_then(move |requester| DocumentKeyShadowRetrievalService::is_response_required(
					blockchain,
					contract_address,
					key_id,
					requester,
					key_server_address,
				)),
			lazy(move |_| artifacts
				.participants_coefficients
				.get(&key_server_address)
				.cloned()
				.ok_or_else(|| String::from(
					"DocumentKeyPersonalRetrieval session has completed without self coefficient",
				)))
			.and_then(move |self_coefficient| ready(requester
				.address(&key_id)
				.map(|requester| (self_coefficient, requester))
				.map_err(Into::into))
			)
			.and_then(move |(self_coefficient, requester)| DocumentKeyShadowRetrievalService::prepare_pubish_personal_tx_data(
				blockchain_copy,
				contract_address,
				key_id,
				requester,
				artifacts_copy.participants_coefficients.keys().cloned().collect(),
				artifacts_copy.encrypted_document_key,
				self_coefficient,
			)),
		)
	}

	fn publish_document_key_personal_retrieval_error(
		&self,
		contract_address: Address,
		key_id: ServerKeyId,
		requester: Requester,
	) {
		let blockchain = self.blockchain.clone();
		let key_server_address = self.key_server_address;
		self.submit_response_transaction(
			contract_address,
			format!("DocumentKeyPersonalRetrievalFailure({}, {})", key_id, requester),
			ready(requester.address(&key_id).map_err(Into::into))
				.and_then(move |requester| DocumentKeyShadowRetrievalService::is_response_required(
					blockchain,
					contract_address,
					key_id,
					requester,
					key_server_address,
				)),
			lazy(move |_| requester
				.address(&key_id)
				.map_err(Into::into)
				.map(|requester|
					DocumentKeyShadowRetrievalService::prepare_error_tx_data(&key_id, &requester)
				)
			),
		)
	}
}
