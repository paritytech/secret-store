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

use std::collections::{BTreeMap, HashMap};
use parking_lot::RwLock;
use tiny_keccak::{Hasher, Keccak};
use ethereum_types::H256;
use parity_crypto::publickey::{Address, Public, Secret};
use crate::{error::Error, KeyServerId, ServerKeyId};

/// Encrypted key share, stored by key storage on the single key server.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct KeyShare {
	/// Author of the entry.
	pub author: Address,
	/// Decryption threshold (at least threshold + 1 nodes are required to decrypt data).
	pub threshold: usize,
	/// Server public key.
	pub public: Public,
	/// Doument key: common (shared) encryption point.
	pub common_point: Option<Public>,
	/// Doument key: encrypted point.
	pub encrypted_point: Option<Public>,
	/// Key share versions.
	pub versions: Vec<KeyShareVersion>,
}

/// Versioned portion of key share.
#[derive(Debug, Clone, PartialEq)]
pub struct KeyShareVersion {
	/// Version hash (Keccak(time + id_numbers)).
	pub hash: H256,
	/// Nodes ids numbers.
	pub id_numbers: BTreeMap<KeyServerId, Secret>,
	/// Secret share of secret portion of server key, valid within this version.
	pub secret_share: Secret,
}


/// Secret Store key storage.
pub trait KeyStorage: Send + Sync + 'static {
	/// Insert new key share.
	fn insert(&self, key_id: ServerKeyId, key: KeyShare) -> Result<(), Error>;
	/// Update existing key share.
	fn update(&self, key_id: ServerKeyId, key: KeyShare) -> Result<(), Error>;
	/// Get existing key share.
	fn get(&self, key_id: &ServerKeyId) -> Result<Option<KeyShare>, Error>;
	/// Remove key share.
	fn remove(&self, key_id: &ServerKeyId) -> Result<(), Error>;
	/// Clears the database.
	fn clear(&self) -> Result<(), Error>;
	/// Check if storage contains encryption key
	fn contains(&self, key_id: &ServerKeyId) -> bool;
	/// Iterate through storage.
	fn iter<'a>(&'a self) -> Box<dyn Iterator<Item=(ServerKeyId, KeyShare)> + 'a>;
}

/// In-memory key storage implementation.
#[derive(Debug, Default)]
pub struct InMemoryKeyStorage {
	keys: RwLock<HashMap<ServerKeyId, KeyShare>>,
}

impl KeyStorage for InMemoryKeyStorage {
	fn insert(&self, key_id: ServerKeyId, key: KeyShare) -> Result<(), Error> {
		self.keys.write().insert(key_id, key);
		Ok(())
	}

	fn update(&self, key_id: ServerKeyId, key: KeyShare) -> Result<(), Error> {
		self.keys.write().insert(key_id, key);
		Ok(())
	}

	fn get(&self, key_id: &ServerKeyId) -> Result<Option<KeyShare>, Error> {
		Ok(self.keys.read().get(key_id).cloned())
	}

	fn remove(&self, key_id: &ServerKeyId) -> Result<(), Error> {
		self.keys.write().remove(key_id);
		Ok(())
	}

	fn clear(&self) -> Result<(), Error> {
		self.keys.write().clear();
		Ok(())
	}

	fn contains(&self, key_id: &ServerKeyId) -> bool {
		self.keys.read().contains_key(key_id)
	}

	fn iter<'a>(&'a self) -> Box<dyn Iterator<Item=(ServerKeyId, KeyShare)> + 'a> {
		Box::new(self.keys.read().clone().into_iter())
	}
}

impl KeyShare {
	/// Get last version reference.
	pub fn last_version(&self) -> Result<&KeyShareVersion, Error> {
		self.versions
			.last()
			.ok_or_else(|| Error::Database("key version is not found".into()))
	}

	/// Get given version reference.
	pub fn version(&self, version: &H256) -> Result<&KeyShareVersion, Error> {
		self.versions
			.iter()
			.rev()
			.find(|v| &v.hash == version)
			.ok_or_else(|| Error::Database("key version is not found".into()))
	}
}

impl KeyShareVersion {
	/// Create new version.
	pub fn new(id_numbers: BTreeMap<KeyServerId, Secret>, secret_share: Secret) -> Self {
		KeyShareVersion {
			hash: Self::data_hash(id_numbers.iter().map(|(k, v)| (k.as_bytes(), v.as_bytes()))),
			id_numbers: id_numbers,
			secret_share: secret_share,
		}
	}

	/// Calculate hash of given version data.
	pub fn data_hash<'a, I>(id_numbers: I) -> H256 where I: Iterator<Item=(&'a [u8], &'a [u8])> {
		let mut nodes_keccak = Keccak::v256();

		for (node, node_number) in id_numbers {
			nodes_keccak.update(node);
			nodes_keccak.update(node_number);
		}

		let mut nodes_keccak_value = [0u8; 32];
		nodes_keccak.finalize(&mut nodes_keccak_value);

		nodes_keccak_value.into()
	}
}
