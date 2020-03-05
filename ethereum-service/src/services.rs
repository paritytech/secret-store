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
use ethabi::RawLog;
use ethabi_contract::use_contract;
use ethereum_types::{Address, H256, U256};
use log::error;
use crate::{
	Blockchain, BlockchainServiceTask, Configuration,
	document_key_shadow_retrieval::DocumentKeyShadowRetrievalService,
	document_key_store::DocumentKeyStoreService,
	server_key_generation::ServerKeyGenerationService,
	server_key_retrieval::ServerKeyRetrievalService,
};

use_contract!(service, "res/service.json");

/// Prepare topics filter for contract.
pub fn prepare_topics_filter(config: &Configuration) -> Vec<H256> {
	let mut topics = Vec::new();
	if config.server_key_generation_requests {
		topics.extend(ServerKeyGenerationService::prepare_topics_filter());
	}
	if config.server_key_retrieval_requests {
		topics.extend(ServerKeyRetrievalService::prepare_topics_filter());
	}
	if config.document_key_store_requests {
		topics.extend(DocumentKeyStoreService::prepare_topics_filter());
	}
	if config.document_key_shadow_retrieval_requests {
		topics.extend(DocumentKeyShadowRetrievalService::prepare_topics_filter())
	}
	topics
}

/// Parse service contract log.
pub fn try_parse_contract_log(
	config: &Configuration,
	contract_address: &Address,
	raw_log: RawLog,
) -> Option<BlockchainServiceTask> {
	let service_task = if ServerKeyGenerationService::is_service_event_log(&raw_log) {
		if config.server_key_generation_requests {
			ServerKeyGenerationService::parse_log(contract_address, raw_log)
		} else {
			return None
		}
	} else if ServerKeyRetrievalService::is_service_event_log(&raw_log) {
		if config.server_key_retrieval_requests {
			ServerKeyRetrievalService::parse_log(contract_address, raw_log)
		} else {
			return None
		}
	} else if DocumentKeyStoreService::is_service_event_log(&raw_log) {
		if config.document_key_store_requests {
			DocumentKeyStoreService::parse_log(contract_address, raw_log)
		} else {
			return None
		}
	} else if DocumentKeyShadowRetrievalService::is_service_event_log(&raw_log) {
		if config.document_key_shadow_retrieval_requests {
			DocumentKeyShadowRetrievalService::parse_log(contract_address, raw_log)
		} else {
			return None
		}
	} else {
		return None
	};
	
	match service_task {
		Ok(service_task) => Some(service_task),
		Err(error) => {
			error!(
				target: "secretstore",
				"Failed to parse service contract event: {}",
				error,
			);

			None
		},
	}
}

/// Create task-specific pending requests iterator.
pub fn create_typed_pending_requests_iterator<B: Blockchain>(
	blockchain: &Arc<B>,
	block: &H256,
	contract_address: &Address,
	key_server_address: &Address,
	get_count: impl Fn(&B, &H256, &Address) -> Result<U256, String> + 'static,
	read_item: impl Fn(&B, &H256, &Address, &Address, U256) -> Result<(bool, BlockchainServiceTask), String> + 'static,
) -> impl Iterator<Item=BlockchainServiceTask>
{
	get_count(&*blockchain, block, contract_address)
		.map(|count| {
			let blockchain = blockchain.clone();
			let block = block.clone();
			let key_server_address = key_server_address.clone();
			let contract_address = contract_address.clone();
			Box::new(PendingRequestsIterator {
				read_request: move |index| read_item(&blockchain, &block, &key_server_address, &contract_address, index)
					.map_err(|error| {
						error!(
							target: "secretstore",
							"{}: reading pending request failed: {}",
							key_server_address,
							error,
						);

						error
					})
					.ok(),
				index: 0.into(),
				length: count,
			}) as Box<dyn Iterator<Item=_>>
		})
		.map_err(|error| {
			error!(
				target: "secretstore",
				"{}: creating pending requests iterator failed: {}",
				key_server_address,
				error,
			);
			error
		})
		.ok()
		.unwrap_or_else(|| Box::new(::std::iter::empty()))
}

/// Pending requests iterator.
struct PendingRequestsIterator<F: Fn(U256) -> Option<(bool, BlockchainServiceTask)>> {
	/// Pending request read function.
	read_request: F,
	/// Current request index.
	index: U256,
	/// Requests length.
	length: U256,
}

impl<F> Iterator for PendingRequestsIterator<F> where
	F: Fn(U256) -> Option<(bool, BlockchainServiceTask)>
{
	type Item = BlockchainServiceTask;

	fn next(&mut self) -> Option<BlockchainServiceTask> {
		loop {
			if self.index >= self.length {
				return None;
			}

			let index = self.index.clone();
			self.index = self.index + 1;

			let (is_response_required, task) = (self.read_request)(index)?;
			match is_response_required {
				true => return Some(task),
				false => (),
			}
		}
	}
}

/// Parse threshold (we only support 256 KS at max).
pub fn parse_threshold(threshold: U256) -> Result<usize, String> {
	let threshold_num = threshold.low_u64();
	if threshold != threshold_num.into() || threshold_num >= ::std::u8::MAX as u64 {
		return Err(format!("invalid threshold to use in service contract: {}", threshold));
	}

	Ok(threshold_num as usize)
}

/// Serialize threshold (we only support 256 KS at max).
pub fn serialize_threshold(threshold: usize) -> Result<U256, String> {
	if threshold > ::std::u8::MAX as usize {
		return Err(format!("invalid threshold to use in service contract: {}", threshold));
	}
	Ok(threshold.into())
}
