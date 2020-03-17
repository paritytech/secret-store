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

use std::{future::Future, sync::Arc};
use codec::{Decode, Encode};
use parking_lot::RwLock;
use sp_core::crypto::Pair as _;
use crate::runtime::{
	SYSTEM_EVENTS_KEY,
	AccountId, BlockHash, Call, Event, Header,
	Index, Pair, TransactionHash,
	create_transaction,
};

/// All possible errors that can occur during interacting with Substrate node.
#[derive(Debug)]
pub enum Error {
	/// Client creation has failed.
	ClientCreationFailed(jsonrpsee::transport::ws::WsNewDnsError),
	/// Request has failed.
	RequestFailed(jsonrpsee::client::RequestError),
	/// Response decode has failed.
	DecodeFailed(codec::Error),
	/// Failed to get best finalized header.
	MissingBestFinalizedHeader,
}

/// Block reference.
pub enum BlockRef {
	/// Points at block with given hash.
	Hash(crate::runtime::BlockHash),
	/// Points at best block known to use (i.e. best finalized block).
	/// We use this when we need to deal with the best trusted state of chain
	/// (i.e. when asking for permissions).
	LocalBest,
	/// Points at best block known to Substrate node (i.e. best block of the chain).
	/// We use this when we need to update chain (i.e. submit transaction).
	RemoteBest,
}

/// Substrate client type.
#[derive(Clone)]
pub struct Client {
	/// Substrate RPC client.
	rpc_client: jsonrpsee::Client,
	/// Transactions signer.
	signer: Pair,
	/// Genesis block hash.
	genesis_hash: BlockHash,
	/// Runtime version.
	runtime_version: u32,
	/// Best local (finalized) block.
	best_block: Arc<RwLock<(crate::runtime::BlockNumber, crate::runtime::BlockHash)>>,
}

impl Client {
	/// Create new client.
	pub async fn new(
		uri: &str,
		signer: Pair,
	) -> Result<Self, Error> {
		let rpc_client = jsonrpsee::ws_client(uri).await.map_err(Error::ClientCreationFailed)?;
		let genesis_hash = rpc_client.request(
			"chain_getBlockHash",
			jsonrpsee::common::Params::Array(vec![
				serde_json::to_value(0u32).unwrap(),
			]),
		).await.map_err(Error::RequestFailed)?;
		let finalized_hash: crate::runtime::BlockHash = rpc_client.request(
			"chain_getFinalizedHead",
			jsonrpsee::common::Params::None,
		).await.map_err(Error::RequestFailed)?;
		let finalized_header: Option<crate::runtime::Header> = rpc_client.request(
			"chain_getHeader",
			jsonrpsee::common::Params::Array(vec![
				serde_json::to_value(finalized_hash).unwrap(),
			]),
		).await.map_err(Error::RequestFailed)?;
		let finalized_header = finalized_header.ok_or(Error::MissingBestFinalizedHeader)?;
		let runtime_version: sp_version::RuntimeVersion = rpc_client.request(
			"state_getRuntimeVersion",
			jsonrpsee::common::Params::None,
		).await.map_err(Error::RequestFailed)?;

		Ok(Client {
			rpc_client,
			signer,
			genesis_hash,
			runtime_version: runtime_version.spec_version,
			best_block: Arc::new(RwLock::new((finalized_header.number, finalized_hash))),
		})
	}

	/// Update best known block.
	pub fn set_best_block(&self, best_block: (crate::runtime::BlockNumber, crate::runtime::BlockHash)) {
		*self.best_block.write() = best_block;
	}

	/// Return best known block.
	pub fn best_block(&self) -> (crate::runtime::BlockNumber, crate::runtime::BlockHash) {
		self.best_block.read().clone()
	}

	/// Subscribe to new blocks.
	pub async fn subscribe_finalized_heads(&self) -> Result<jsonrpsee::client::Subscription<Header>, Error> {
		self.rpc_client.subscribe(
			"chain_subscribeFinalizedHeads",
			jsonrpsee::common::Params::None,
			"chain_unsubscribeFinalizedHeads",
		).await.map_err(Error::RequestFailed)
	}

	/// Read events of the header.
	pub fn header_events(
		&self,
		hash: BlockHash,
	) -> impl Future<Output = Result<Vec<frame_system::EventRecord<Event, BlockHash>>, Error>> {
		let rpc_client = self.rpc_client.clone();
		// making fn async doesn't make it return 'static future :/
		async move {
			let events_storage: Option<sp_core::Bytes> = rpc_client.clone().request(
				"state_getStorage",
				jsonrpsee::common::Params::Array(vec![
					serde_json::to_value(format!("0x{}", SYSTEM_EVENTS_KEY)).unwrap(),
					serde_json::to_value(hash).unwrap(),
				]),
			).await.map_err(Error::RequestFailed)?;
			match events_storage {
				Some(events_storage) => Decode::decode(&mut &events_storage[..])
					.map_err(Error::DecodeFailed),
				None => Ok(Vec::new())
			}
		}
	}

	/// Call runtime method.
	pub fn call_runtime_method<Ret: Decode>(
		&self,
		block: BlockRef,
		method: &'static str,
		arguments: Vec<u8>,
	) -> impl Future<Output = Result<Ret, Error>> {
		let rpc_client = self.rpc_client.clone();
		let best_block = self.best_block.clone();
		// making fn async doesn't make it return 'static future :/
		async move {
			let arguments = format!("0x{}", hex::encode(arguments));
			rpc_client.request(
				"state_call",
				match block {
					BlockRef::Hash(hash) => jsonrpsee::common::Params::Array(vec![
						serde_json::to_value(method).unwrap(),
						serde_json::to_value(arguments).unwrap(),
						serde_json::to_value(hash).unwrap(),
					]),
					BlockRef::LocalBest => jsonrpsee::common::Params::Array(vec![
						serde_json::to_value(method).unwrap(),
						serde_json::to_value(arguments).unwrap(),
						serde_json::to_value(best_block.read().1).unwrap(),
					]),
					BlockRef::RemoteBest => jsonrpsee::common::Params::Array(vec![
						serde_json::to_value(method).unwrap(),
						serde_json::to_value(arguments).unwrap(),
					]),
				},
			)
			.await
			.map_err(Error::RequestFailed)
			.and_then(|ret: sp_core::Bytes| Ret::decode(&mut &ret.0[..]).map_err(Error::DecodeFailed))
		}
	}

	/// Submit runtime transaction.
	pub async fn submit_transaction(&self, call: Call) -> Result<TransactionHash, Error> {
		let index = self.next_account_index().await?;
		let transaction = create_transaction(
			call,
			&self.signer,
			index,
			self.genesis_hash,
			self.runtime_version,
		);
		let hex_transaction = format!("0x{}", hex::encode(transaction.encode()));
		self.rpc_client.request(
			"author_submitExtrinsic",
			jsonrpsee::common::Params::Array(vec![
				serde_json::to_value(hex_transaction).unwrap(),
			]),
		).await.map_err(Error::RequestFailed)
	}

	/// Get substrate account nonce.
	async fn next_account_index(&self) -> Result<Index, Error> {
		use sp_core::crypto::Ss58Codec;

		let account_id: AccountId = self.signer.public().as_array_ref().clone().into();
		self.rpc_client.request(
			"system_accountNextIndex",
			jsonrpsee::common::Params::Array(vec![
				serde_json::to_value(account_id.to_ss58check()).unwrap(),
			]),
		).await.map_err(Error::RequestFailed)
	}
}
