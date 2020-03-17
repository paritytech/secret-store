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

use codec::Encode;
use primitives::{
	Address, ServerKeyId,
	acl_storage::AclStorage,
	error::Error,
};
use crate::substrate_client::{BlockRef, Client};

pub struct OnChainAclStorage {
	client: Client,
}

impl OnChainAclStorage {
	/// Crate new on-chain ACL storage.
	pub fn new(client: Client) -> Self {
		OnChainAclStorage {
			client,
		}
	}
}

impl AclStorage for OnChainAclStorage {
	fn check(&self, requester_address: Address, server_key_id: &ServerKeyId) -> Result<bool, Error> {
		// we always check at best block - there's no need to use deprecated ACLs
		futures::executor::block_on(async {
			self.client.call_runtime_method(
				BlockRef::LocalBest,
				"SecretStoreAclApi_check",
				(requester_address, server_key_id).encode(),
			).await.map_err(|err| Error::Internal(format!("{:?}", err)))
		})
	}
}
