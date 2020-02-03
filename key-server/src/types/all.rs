// Copyright 2015-2019 Parity Technologies (UK) Ltd.
// This file is part of Parity Ethereum.

// Parity Ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity Ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity Ethereum.  If not, see <http://www.gnu.org/licenses/>.

use std::collections::BTreeMap;

use crate::blockchain::ContractAddress;

/// Node id.
pub type NodeId = parity_crypto::publickey::Public;
/// Server key id. When key is used to encrypt document, it could be document contents hash.
pub type ServerKeyId = ethereum_types::H256;
/// Encrypted document key type.
pub type EncryptedDocumentKey = parity_bytes::Bytes;
/// Message hash.
pub type MessageHash = ethereum_types::H256;
/// Message signature.
pub type EncryptedMessageSignature = parity_bytes::Bytes;
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

/// Secret store configuration
#[derive(Debug)]
pub struct ServiceConfiguration {
	/// HTTP listener address. If None, HTTP API is disabled.
	pub listener_address: Option<NodeAddress>,
	/// Service contract address.
	pub service_contract_address: Option<ContractAddress>,
	/// Server key generation service contract address.
	pub service_contract_srv_gen_address: Option<ContractAddress>,
	/// Server key retrieval service contract address.
	pub service_contract_srv_retr_address: Option<ContractAddress>,
	/// Document key store service contract address.
	pub service_contract_doc_store_address: Option<ContractAddress>,
	/// Document key shadow retrieval service contract address.
	pub service_contract_doc_sretr_address: Option<ContractAddress>,
	/// ACL check contract address. If None, everyone has access to all keys. Useful for tests only.
	pub acl_check_contract_address: Option<ContractAddress>,
	/// Cluster configuration.
	pub cluster_config: ClusterConfiguration,
	// Allowed CORS domains
	pub cors: Option<Vec<String>>,
}

/// Key server cluster configuration
#[derive(Debug)]
pub struct ClusterConfiguration {
	/// This node address.
	pub listener_address: NodeAddress,
	/// All cluster nodes addresses.
	pub nodes: BTreeMap<parity_crypto::publickey::Public, NodeAddress>,
	/// Key Server Set contract address. If None, servers from 'nodes' map are used.
	pub key_server_set_contract_address: Option<ContractAddress>,
	/// Allow outbound connections to 'higher' nodes.
	/// This is useful for tests, but slower a bit for production.
	pub allow_connecting_to_higher_nodes: bool,
	/// Administrator public key.
	pub admin_public: Option<Public>,
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

pub use parity_secretstore_primitives::requester::Requester;