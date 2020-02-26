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

// to avoid extra dependencies if you're using primitives
pub use ethereum_types::H256;
pub use parity_bytes::Bytes;
pub use parity_crypto::publickey::{Address, Public, Signature};

/// Every key server owns a key. This type is used where we need to encrypt
/// message to this server key.
pub type KeyServerPublic = Public;
/// Key server address is derived from its own public key. This type is used
/// when we need to identify server key.
pub type KeyServerId = Address;

/// Every server key has its own id. This could be a hash of some document
/// that should be encrypted by this key.
pub type ServerKeyId = H256;

pub mod acl_storage;
pub mod error;
pub mod executor;
pub mod key_server;
pub mod key_server_key_pair;
pub mod key_server_set;
pub mod key_storage;
pub mod requester;
pub mod serialization;
pub mod service;

/// Encrypt given data using Elliptic Curve Integrated Encryption Scheme.
pub fn ecies_encrypt(
	public: &Public,
	data: &[u8],
) -> Result<Bytes, crate::error::Error> {
	parity_crypto::publickey::ecies::encrypt(public, &parity_crypto::DEFAULT_MAC, data)
		.map_err(|error| crate::error::Error::Internal(
			format!("Error encrypting data (ECIES): {}", error),
		))
}
