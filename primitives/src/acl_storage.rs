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

use std::collections::{HashMap, HashSet};
use parking_lot::RwLock;
use ethereum_types::Address;
use crate::{ServerKeyId, error::Error};

/// ACL storage of Secret Store.
pub trait AclStorage: Send + Sync {
	/// Check if owner of `requester_address` can run any operations that are
	/// touching private data associated with given server key.
	///
	/// The private data is either private portion of server key, or document
	/// key associated with this server key.
	fn check(&self, requester_address: Address, key_id: &ServerKeyId) -> Result<bool, Error>;
}

/// In-memory ACL storage implementation.
///
/// By default everyone has access to all keys.
#[derive(Default, Debug)]
pub struct InMemoryPermissiveAclStorage {
	forbidden: RwLock<HashMap<Address, HashSet<ServerKeyId>>>,
}

impl InMemoryPermissiveAclStorage {
	/// Forbid access to given documents.
	pub fn forbid(&self, requester: Address, document: ServerKeyId) {
		self.forbidden.write()
			.entry(requester)
			.or_insert_with(Default::default)
			.insert(document);
	}
}

impl AclStorage for InMemoryPermissiveAclStorage {
	fn check(&self, requester: Address, document: &ServerKeyId) -> Result<bool, Error> {
		Ok(self.forbidden.read()
			.get(&requester)
			.map(|docs| !docs.contains(document))
			.unwrap_or(true))
	}
}
