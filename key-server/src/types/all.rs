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

use parity_crypto::publickey::Address;

/// Node id.
pub type NodeId = primitives::KeyServerId;
/// Server key id. When key is used to encrypt document, it could be document contents hash.
pub type ServerKeyId = ethereum_types::H256;
/// Encrypted document key type.
pub type EncryptedDocumentKey = parity_bytes::Bytes;
/// Request signature type.
pub type RequestSignature = parity_crypto::publickey::Signature;
/// Public key type.
pub use parity_crypto::publickey::Public;

/// Secret store configuration
#[derive(Debug, Clone)]
pub struct NodeAddress {
	/// IP address.
	pub address: String,
	/// IP port.
	pub port: u16,
}

/// Key server cluster configuration
#[derive(Debug)]
pub struct ClusterConfiguration {
	/// Administrator public key.
	pub admin_address: Option<Address>,
	/// Should key servers set change session should be started when servers set changes.
	/// This will only work when servers set is configured using KeyServerSet contract.
	pub auto_migrate_enabled: bool,
}

/// Shadow decryption result.
#[derive(Clone, Debug, PartialEq)]
pub struct EncryptedDocumentKeyShadow {
	/// Decrypted secret point. It is partially decrypted if shadow decryption was requested.
	pub decrypted_secret: parity_crypto::publickey::Public,
	/// Shared common point.
	pub common_point: Option<parity_crypto::publickey::Public>,
	/// If shadow decryption was requested: shadow decryption coefficients, encrypted with requestor public.
	pub decrypt_shadows: Option<Vec<Vec<u8>>>,
}

pub use primitives::requester::Requester;