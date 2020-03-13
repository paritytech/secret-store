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
use futures::{Stream, StreamExt};
use ethabi::{FunctionOutputDecoder, RawLog};
use ethereum_types::{Address, H256, U256};
use keccak_hash::keccak;
use lazy_static::lazy_static;
use parity_bytes::Bytes;
use primitives::{
	Public, ServerKeyId,
	requester::Requester,
	service::ServiceTask,
};
use crate::{
	BlockId, Blockchain, BlockchainServiceTask, Configuration,
	services::{service, parse_threshold, create_typed_pending_requests_iterator},
};

/// Server key generation has been requested.
const SERVER_KEY_GENERATION_REQUESTED_EVENT_NAME: &'static [u8] =
	&*b"ServerKeyGenerationRequested(bytes32,address,uint8)";

lazy_static! {
	pub static ref SERVER_KEY_GENERATION_REQUESTED_EVENT_NAME_HASH: H256 =
		keccak(SERVER_KEY_GENERATION_REQUESTED_EVENT_NAME);
}

/// Server key generation related functions.
pub struct ServerKeyGenerationService;

impl ServerKeyGenerationService {
	/// Prepare topics filter for server key generation events.
	pub fn prepare_topics_filter() -> impl Iterator<Item=H256> {
		std::iter::once(*SERVER_KEY_GENERATION_REQUESTED_EVENT_NAME_HASH)
	}

	/// Returns true if log corresponds to service key generation event.
	pub fn is_service_event_log(raw_log: &RawLog) -> bool {
		raw_log.topics[0] == *SERVER_KEY_GENERATION_REQUESTED_EVENT_NAME_HASH
	}

	/// Parse request log entry.
	pub fn parse_log(contract_address: &Address, raw_log: RawLog) -> Result<BlockchainServiceTask, String> {
		match service::events::server_key_generation_requested::parse_log(raw_log) {
			Ok(event) => Ok(BlockchainServiceTask::Regular(
				*contract_address,
				ServiceTask::GenerateServerKey(
					event.server_key_id,
					Requester::Address(event.author),
					parse_threshold(event.threshold)?,
				),
			)),
			Err(error) => Err(error.to_string()),
		}
	}

	/// Create iterator over pending server key retrieval requests.
	pub fn create_pending_requests_iterator<B: Blockchain>(
		blockchain: Arc<B>,
		config: Arc<Configuration>,
		block: H256,
		contract_address: Address,
		key_server_address: Address,
	) -> impl Stream<Item=BlockchainServiceTask> + Send {
		let iterator = match config.server_key_generation_requests {
			true => create_typed_pending_requests_iterator(
				blockchain,
				block,
				contract_address,
				key_server_address,
				&Self::read_pending_requests_count,
				&Self::read_pending_request,
			).boxed(),
			false => futures::stream::empty().boxed(),
		};

		iterator
	}

	/// Check if response from key server is required.
	pub async fn is_response_required<B: Blockchain>(
		blockchain: Arc<B>,
		contract_address: Address,
		key_id: ServerKeyId,
		key_server_address: Address,
	) -> Result<bool, String> {
		// we're checking confirmation in Latest block, because we're interested in latest contract state here
		let (encoded, decoder) = service::functions::is_server_key_generation_response_required::call(
			key_id,
			key_server_address,
		);
		let call_result = blockchain.contract_call(BlockId::Best, contract_address, encoded).await?;
		decoder.decode(&call_result).map_err(|e| e.to_string())
	}

	/// Prepare publish key transaction data.
	pub fn prepare_pubish_tx_data(key_id: &ServerKeyId, server_key: &Public) -> Bytes {
		service::functions::server_key_generated::encode_input(
			*key_id,
			server_key.as_bytes().to_vec(),
		)
	}

	/// Prepare error transaction data.
	pub fn prepare_error_tx_data(key_id: &ServerKeyId) -> Bytes {
		service::functions::server_key_generation_error::encode_input(*key_id)
	}

	/// Read pending requests count.
	async fn read_pending_requests_count<B: Blockchain>(
		blockchain: Arc<B>,
		block: H256,
		contract_address: Address,
	) -> Result<U256, String> {
		let (encoded, decoder) = service::functions::server_key_generation_requests_count::call();
		let call_result = blockchain.contract_call(BlockId::Hash(block), contract_address, encoded).await?;
		decoder.decode(&call_result).map_err(|e| e.to_string())
	}

	/// Read pending request.
	async fn read_pending_request<B: Blockchain>(
		blockchain: Arc<B>,
		block: H256,
		key_server_address: Address,
		contract_address: Address,
		index: U256,
	) -> Result<(bool, BlockchainServiceTask), String> {
		let (encoded, decoder) = service::functions::get_server_key_generation_request::call(index);
		let call_result = blockchain.contract_call(BlockId::Hash(block), contract_address, encoded).await?;
		let (key_id, author, threshold) = decoder.decode(&call_result).map_err(|e| e.to_string())?;
		let threshold = parse_threshold(threshold)?;

		let (encoded, decoder) = service::functions::is_server_key_generation_response_required::call(
			key_id,
			key_server_address,
		);
		let call_result = blockchain.contract_call(BlockId::Hash(block), contract_address, encoded).await?;
		let not_confirmed = decoder.decode(&call_result).map_err(|e| e.to_string())?;

		let task = BlockchainServiceTask::Regular(
			contract_address,
			ServiceTask::GenerateServerKey(
				key_id,
				Requester::Address(author),
				threshold,
			),
		);

		Ok((not_confirmed, task))
	}
}
