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

use std::collections::BTreeMap;
use std::sync::Arc;
use serde::{Serialize, Deserialize};
use serde_json;
use kvdb::KeyValueDB;
use primitives::{
	error::Error, ServerKeyId,
	key_storage::{KeyStorage, KeyShare, KeyShareVersion},
	serialization::{SerializablePublic, SerializableSecret, SerializableH256, SerializableAddress},
};

/// Persistent document encryption keys storage
pub struct PersistentKeyStorage {
	db: Arc<dyn KeyValueDB>,
}

/// Persistent document encryption keys storage iterator
pub struct PersistentKeyStorageIterator<'a> {
	iter: Box<dyn Iterator<Item=(Box<[u8]>, Box<[u8]>)> + 'a>,
}

/// V3 of encrypted key share, as it is stored by key storage on the single key server.
#[derive(Serialize, Deserialize)]
struct SerializableKeyShareV3 {
	/// Author of the entry.
	pub author: SerializableAddress,
	/// Decryption threshold (at least threshold + 1 nodes are required to decrypt data).
	pub threshold: usize,
	/// Server public.
	pub public: SerializablePublic,
	/// Common (shared) encryption point.
	pub common_point: Option<SerializablePublic>,
	/// Encrypted point.
	pub encrypted_point: Option<SerializablePublic>,
	/// Versions.
	pub versions: Vec<SerializableKeyShareVersionV3>
}

/// V3 of encrypted key share version, as it is stored by key storage on the single key server.
#[derive(Serialize, Deserialize)]
struct SerializableKeyShareVersionV3 {
	/// Version hash.
	pub hash: SerializableH256,
	/// Nodes ids numbers.
	pub id_numbers: BTreeMap<SerializableAddress, SerializableSecret>,
	/// Node secret share.
	pub secret_share: SerializableSecret,
}

impl PersistentKeyStorage {
	/// Crate new persistent keys storage at given path.
	pub fn new(db_path: &std::path::Path) -> Result<Self, Error> {
		let db_path = db_path
			.to_str()
			.ok_or_else(|| Error::Database("Invalid secretstore path".to_string()))?;

		let config = kvdb_rocksdb::DatabaseConfig::with_columns(1);
		let db = kvdb_rocksdb::Database::open(&config, &db_path)
			.map_err(|e| Error::Database(format!("Error opening database: {:?}", e)))?;
		Ok(PersistentKeyStorage {
			db: Arc::new(db),
		})
	}
}

impl KeyStorage for PersistentKeyStorage {
	fn insert(&self, document: ServerKeyId, key: KeyShare) -> Result<(), Error> {
		let key: SerializableKeyShareV3 = key.into();
		let key = serde_json::to_vec(&key).map_err(|e| Error::Database(e.to_string()))?;
		let mut batch = self.db.transaction();
		batch.put(0, document.as_bytes(), &key);
		self.db.write(batch).map_err(Into::into)
	}

	fn update(&self, document: ServerKeyId, key: KeyShare) -> Result<(), Error> {
		self.insert(document, key)
	}

	fn get(&self, document: &ServerKeyId) -> Result<Option<KeyShare>, Error> {
		self.db.get(0, document.as_bytes())
			.map_err(|e| Error::Database(e.to_string()))
			.and_then(|key| match key {
				None => Ok(None),
				Some(key) => serde_json::from_slice::<SerializableKeyShareV3>(&key)
					.map_err(|e| Error::Database(e.to_string()))
					.map(Into::into)
					.map(Some),
			})
	}

	fn remove(&self, document: &ServerKeyId) -> Result<(), Error> {
		let mut batch = self.db.transaction();
		batch.delete(0, document.as_bytes());
		self.db.write(batch).map_err(Into::into)
	}

	fn clear(&self) -> Result<(), Error> {
		let mut batch = self.db.transaction();
		for (key, _) in self.iter() {
			batch.delete(0, key.as_bytes());
		}
		self.db.write(batch)
			.map_err(|e| Error::Database(e.to_string()))
	}

	fn contains(&self, document: &ServerKeyId) -> bool {
		self.db.get(0, document.as_bytes())
			.map(|k| k.is_some())
			.unwrap_or(false)
	}

	fn iter<'a>(&'a self) -> Box<dyn Iterator<Item=(ServerKeyId, KeyShare)> + 'a> {
		Box::new(PersistentKeyStorageIterator {
			iter: self.db.iter(0),
		})
	}
}

impl<'a> Iterator for PersistentKeyStorageIterator<'a> {
	type Item = (ServerKeyId, KeyShare);

	fn next(&mut self) -> Option<(ServerKeyId, KeyShare)> {
		self.iter.as_mut().next()
			.and_then(|(db_key, db_val)| serde_json::from_slice::<SerializableKeyShareV3>(&db_val)
					  .ok()
					  .map(|key| (ServerKeyId::from_slice(&*db_key), key.into())))
	}
}

impl From<KeyShare> for SerializableKeyShareV3 {
	fn from(key: KeyShare) -> Self {
		SerializableKeyShareV3 {
			author: key.author.into(),
			threshold: key.threshold,
			public: key.public.into(),
			common_point: key.common_point.map(Into::into),
			encrypted_point: key.encrypted_point.map(Into::into),
			versions: key.versions.into_iter().map(Into::into).collect(),
		}
	}
}

impl From<KeyShareVersion> for SerializableKeyShareVersionV3 {
	fn from(version: KeyShareVersion) -> Self {
		SerializableKeyShareVersionV3 {
			hash: version.hash.into(),
			id_numbers: version.id_numbers.into_iter().map(|(k, v)| (k.into(), v.into())).collect(),
			secret_share: version.secret_share.into(),
		}
	}
}

impl From<SerializableKeyShareV3> for KeyShare {
	fn from(key: SerializableKeyShareV3) -> Self {
		KeyShare {
			author: key.author.into(),
			threshold: key.threshold,
			public: key.public.into(),
			common_point: key.common_point.map(Into::into),
			encrypted_point: key.encrypted_point.map(Into::into),
			versions: key.versions.into_iter()
				.map(|v| KeyShareVersion {
					hash: v.hash.into(),
					id_numbers: v.id_numbers.into_iter().map(|(k, v)| (k.into(), v.into())).collect(),
					secret_share: v.secret_share.into(),
				})
				.collect(),
		}
	}
}

#[cfg(test)]
pub mod tests {
	use std::collections::HashMap;
	use parking_lot::RwLock;
	use tempdir::TempDir;
	use parity_crypto::publickey::{Random, Generator, Public, public_to_address};
	use primitives::{error::Error, ServerKeyId};
	use super::{KeyStorage, PersistentKeyStorage, KeyShare, KeyShareVersion};

	/// In-memory document encryption keys storage
	#[derive(Default)]
	pub struct DummyKeyStorage {
		keys: RwLock<HashMap<ServerKeyId, KeyShare>>,
	}

	impl KeyStorage for DummyKeyStorage {
		fn insert(&self, document: ServerKeyId, key: KeyShare) -> Result<(), Error> {
			self.keys.write().insert(document, key);
			Ok(())
		}

		fn update(&self, document: ServerKeyId, key: KeyShare) -> Result<(), Error> {
			self.keys.write().insert(document, key);
			Ok(())
		}

		fn get(&self, document: &ServerKeyId) -> Result<Option<KeyShare>, Error> {
			Ok(self.keys.read().get(document).cloned())
		}

		fn remove(&self, document: &ServerKeyId) -> Result<(), Error> {
			self.keys.write().remove(document);
			Ok(())
		}

		fn clear(&self) -> Result<(), Error> {
			self.keys.write().clear();
			Ok(())
		}

		fn contains(&self, document: &ServerKeyId) -> bool {
			self.keys.read().contains_key(document)
		}

		fn iter<'a>(&'a self) -> Box<dyn Iterator<Item=(ServerKeyId, KeyShare)> + 'a> {
			Box::new(self.keys.read().clone().into_iter())
		}
	}

	#[test]
	fn persistent_key_storage() {
		let tempdir = TempDir::new("").unwrap();
		let key1 = ServerKeyId::from_low_u64_be(1);
		let value1 = KeyShare {
			author: Default::default(),
			threshold: 100,
			public: Public::default(),
			common_point: Some(Random.generate().public().clone()),
			encrypted_point: Some(Random.generate().public().clone()),
			versions: vec![KeyShareVersion {
				hash: Default::default(),
				id_numbers: vec![
					(
						public_to_address(Random.generate().public()),
						Random.generate().secret().clone(),
					)
				].into_iter().collect(),
				secret_share: Random.generate().secret().clone(),
			}],
		};
		let key2 = ServerKeyId::from_low_u64_be(2);
		let value2 = KeyShare {
			author: Default::default(),
			threshold: 200,
			public: Public::default(),
			common_point: Some(Random.generate().public().clone()),
			encrypted_point: Some(Random.generate().public().clone()),
			versions: vec![KeyShareVersion {
				hash: Default::default(),
				id_numbers: vec![
					(
						public_to_address(Random.generate().public()),
						Random.generate().secret().clone(),
					)
				].into_iter().collect(),
				secret_share: Random.generate().secret().clone(),
			}],
		};
		let key3 = ServerKeyId::from_low_u64_be(3);

		let key_storage = PersistentKeyStorage::new(tempdir.path()).unwrap();
		key_storage.insert(key1.clone(), value1.clone()).unwrap();
		key_storage.insert(key2.clone(), value2.clone()).unwrap();
		assert_eq!(key_storage.get(&key1), Ok(Some(value1.clone())));
		assert_eq!(key_storage.get(&key2), Ok(Some(value2.clone())));
		assert_eq!(key_storage.get(&key3), Ok(None));
		drop(key_storage);

		let key_storage = PersistentKeyStorage::new(tempdir.path()).unwrap();
		assert_eq!(key_storage.get(&key1), Ok(Some(value1)));
		assert_eq!(key_storage.get(&key2), Ok(Some(value2)));
		assert_eq!(key_storage.get(&key3), Ok(None));
	}
}
