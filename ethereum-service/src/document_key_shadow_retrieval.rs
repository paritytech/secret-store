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
use ethabi::{FunctionOutputDecoder, RawLog};
use ethereum_types::{Address, H256, U256};
use keccak_hash::keccak;
use lazy_static::lazy_static;
use parity_bytes::Bytes;
use parity_crypto::publickey::{Public, public_to_address};
use primitives::{
	ServerKeyId,
	requester::Requester,
};
use crate::{
	BlockId, Blockchain, BlockchainServiceTask, Configuration,
	services::{service, create_typed_pending_requests_iterator},
};

/// Document key common part retrieval has been requested.
const DOCUMENT_KEY_COMMON_PART_RETRIEVAL_REQUESTED_EVENT_NAME: &'static [u8] =
	&*b"DocumentKeyCommonRetrievalRequested(bytes32,address)";
/// Document key personal part retrieval has been requested.
const DOCUMENT_KEY_PERSONAL_PART_RETRIEVAL_REQUESTED_EVENT_NAME: &'static [u8] =
	&*b"DocumentKeyPersonalRetrievalRequested(bytes32,bytes)";

lazy_static! {
	pub static ref DOCUMENT_KEY_COMMON_PART_RETRIEVAL_REQUESTED_EVENT_NAME_HASH: H256 =
		keccak(DOCUMENT_KEY_COMMON_PART_RETRIEVAL_REQUESTED_EVENT_NAME);
	pub static ref DOCUMENT_KEY_PERSONAL_PART_RETRIEVAL_REQUESTED_EVENT_NAME_HASH: H256 =
		keccak(DOCUMENT_KEY_PERSONAL_PART_RETRIEVAL_REQUESTED_EVENT_NAME);
}

/// Document key shadow retrievalrelated functions.
pub struct DocumentKeyShadowRetrievalService;

impl DocumentKeyShadowRetrievalService {
	/// Prepare topics filter for document key shadow retrieval events.
	pub fn prepare_topics_filter() -> impl Iterator<Item=H256> {
		std::iter::once(*DOCUMENT_KEY_COMMON_PART_RETRIEVAL_REQUESTED_EVENT_NAME_HASH)
			.chain(std::iter::once(*DOCUMENT_KEY_PERSONAL_PART_RETRIEVAL_REQUESTED_EVENT_NAME_HASH))
	}

	/// Returns true if log corresponds to document key shadow retrieval events.
	pub fn is_service_event_log(raw_log: &RawLog) -> bool {
		raw_log.topics[0] == *DOCUMENT_KEY_COMMON_PART_RETRIEVAL_REQUESTED_EVENT_NAME_HASH
			|| raw_log.topics[0] == *DOCUMENT_KEY_PERSONAL_PART_RETRIEVAL_REQUESTED_EVENT_NAME_HASH
	}

	/// Parse request log entry.
	pub fn parse_log(contract_address: &Address, raw_log: RawLog) -> Result<BlockchainServiceTask, String> {
		if raw_log.topics[0] == *DOCUMENT_KEY_COMMON_PART_RETRIEVAL_REQUESTED_EVENT_NAME_HASH {
			return match service::events::document_key_common_retrieval_requested::parse_log(raw_log) {
				Ok(event) => Ok(BlockchainServiceTask::RetrieveShadowDocumentKeyCommon(
					*contract_address,
					event.server_key_id,
					Requester::Address(event.requester),
				)),
				Err(error) => Err(error.to_string()),
			}
		}

		match service::events::document_key_personal_retrieval_requested::parse_log(raw_log) {
			Ok(event) => Ok(BlockchainServiceTask::RetrieveShadowDocumentKeyPersonal(
				*contract_address,
				event.server_key_id,
				Requester::Public(Public::from_slice(&*event.requester_public)),
			)),
			Err(error) => Err(error.to_string()),
		}
	}

	/// Create iterator over pending document key shadow retrieval requests.
	pub fn create_pending_requests_iterator<B: Blockchain>(
		blockchain: &Arc<B>,
		config: &Arc<Configuration>,
		block: &H256,
		contract_address: &Address,
		key_server_address: &Address,
	) -> impl Iterator<Item=BlockchainServiceTask> {
		let iterator = match config.document_key_shadow_retrieval_requests {
			true => Box::new(create_typed_pending_requests_iterator(
				&blockchain,
				&block,
				&contract_address,
				&key_server_address,
				&Self::read_pending_requests_count,
				&Self::read_pending_request,
			)) as Box<dyn Iterator<Item=BlockchainServiceTask>>,
			false => Box::new(::std::iter::empty()),
		};

		iterator
	}

	/// Check if response from key server is required.
	pub fn is_response_required<B: Blockchain>(
		blockchain: &B,
		contract_address: &Address,
		key_id: &ServerKeyId,
		requester: &Address,
		key_server_address: &Address,
	) -> Result<bool, String> {
		// we're checking confirmation in Latest block, because we're interested in latest contract state here
		let (encoded, decoder) = service::functions::is_document_key_shadow_retrieval_response_required::call(
			*key_id,
			*requester,
			*key_server_address,
		);
		blockchain
			.contract_call(BlockId::Best, *contract_address, encoded)
			.and_then(|encoded| decoder.decode(&encoded).map_err(|e| e.to_string()))
	}

	/// Prepare publish common key transaction data.
	pub fn prepare_pubish_common_tx_data(
		key_id: &ServerKeyId,
		requester: &Address,
		common_point: &Public,
		threshold: U256,
	) -> Bytes {
		service::functions::document_key_common_retrieved::encode_input(
			*key_id,
			*requester,
			common_point.as_bytes().to_vec(),
			threshold,
		)
	}

	/// Prepare publish personal key transaction data.
	pub fn prepare_pubish_personal_tx_data<B: Blockchain>(
		blockchain: &B,
		contract_address: &Address,
		key_id: &ServerKeyId,
		requester: &Address,
		participants: &[Address],
		decrypted_secret: Public,
		shadow: Vec<u8>,
	) -> Result<Bytes, String> {
		let mut participants_mask = U256::default();
		for participant in participants {
			let participant_index = Self::map_key_server_address(blockchain, contract_address, participant)
				.map_err(|error| format!("Error searching for {} participant: {}", participant, error))?;
			participants_mask = participants_mask | (U256::one() << participant_index);
		}
		Ok(service::functions::document_key_personal_retrieved::encode_input(
			*key_id,
			*requester,
			participants_mask,
			decrypted_secret.as_bytes().to_vec(),
			shadow,
		))
	}

	/// Prepare error transaction data.
	pub fn prepare_error_tx_data(key_id: &ServerKeyId, requester: &Address) -> Bytes {
		service::functions::document_key_shadow_retrieval_error::encode_input(
			*key_id,
			*requester,
		)
	}

	/// Read pending requests count.
	fn read_pending_requests_count<B: Blockchain>(
		blockchain: &B,
		block: &H256,
		contract_address: &Address,
	) -> Result<U256, String> {
		let (encoded, decoder) = service::functions::document_key_shadow_retrieval_requests_count::call();
		decoder.decode(&blockchain.contract_call(BlockId::Hash(*block), *contract_address, encoded)?)
			.map_err(|e| e.to_string())
	}

	/// Read pending request.
	fn read_pending_request<B: Blockchain>(
		blockchain: &B,
		block: &H256,
		key_server_address: &Address,
		contract_address: &Address,
		index: U256,
	) -> Result<(bool, BlockchainServiceTask), String> {
		let (encoded, decoder) = service::functions::get_document_key_shadow_retrieval_request::call(index);
		let (key_id, requester, is_common_retrieval_completed) = decoder
			.decode(&blockchain.contract_call(BlockId::Hash(*block), *contract_address, encoded)?)
			.map_err(|e| e.to_string())?;

		let requester = Public::from_slice(&requester);
		let (encoded, decoder) = service::functions::is_document_key_shadow_retrieval_response_required::call(
			key_id,
			public_to_address(&requester),
			*key_server_address,
		);
		let not_confirmed = decoder
			.decode(&blockchain.contract_call(BlockId::Hash(*block), *contract_address, encoded)?)
			.map_err(|e| e.to_string())?;

		let task = match is_common_retrieval_completed {
			true => BlockchainServiceTask::RetrieveShadowDocumentKeyPersonal(
				*contract_address,
				key_id,
				Requester::Public(requester),
			),
			false => BlockchainServiceTask::RetrieveShadowDocumentKeyCommon(
				*contract_address,
				key_id,
				Requester::Address(public_to_address(&requester)),
			),
		};

		Ok((not_confirmed, task))
	}

	/// Map from key server address to key server index.
	fn map_key_server_address<B: Blockchain>(
		blockchain: &B,
		contract_address: &Address,
		participant: &Address,
	) -> Result<u8, String> {
		// we're checking confirmation in Latest block, because tx is applied to the latest state
		let (encoded, decoder) = service::functions::require_key_server::call(*participant);
		let index = decoder.decode(&blockchain.contract_call(BlockId::Best, *contract_address, encoded)?)
			.map_err(|e| e.to_string())?;

		if index > u8::max_value().into() {
			Err(format!("Key server index is too big: {}", index))
		} else {
			Ok(index.low_u32() as _)
		}
	}
}
