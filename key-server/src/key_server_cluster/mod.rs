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

use super::types::ServerKeyId;

pub use super::types::{Error, NodeId, Requester, EncryptedDocumentKeyShadow};
pub use super::serialization::{SerializableSignature, SerializableH256, SerializableSecret, SerializablePublic,
	SerializableRequester, SerializableMessageHash, SerializableAddress};
pub use self::cluster::{ClusterCore, ClusterClient, create_cluster};
pub use self::cluster_sessions::{ClusterSession, ClusterSessionsListener, WaitableSession};
#[cfg(test)]
pub use self::cluster::tests::DummyClusterClient;

pub type SessionId = ServerKeyId;

/// Session metadata.
#[derive(Debug, Clone)]
pub struct SessionMeta {
	/// Key id.
	pub id: SessionId,
	/// Id of node, which has started this session.
	pub master_node_id: NodeId,
	/// Id of node, on which this session is running.
	pub self_node_id: NodeId,
	/// Session threshold.
	pub threshold: usize,
	/// Count of all configured key server nodes (valid at session start time).
	pub configured_nodes_count: usize,
	/// Count of all connected key server nodes (valid at session start time).
	pub connected_nodes_count: usize,
}

mod admin_sessions;
mod client_sessions;

pub use self::admin_sessions::key_version_negotiation_session;
pub use self::admin_sessions::servers_set_change_session;
pub use self::admin_sessions::share_add_session;
pub use self::admin_sessions::share_change_session;

pub use self::client_sessions::decryption_session;
pub use self::client_sessions::encryption_session;
pub use self::client_sessions::generation_session;
pub use self::client_sessions::random_point_generation_session;
pub use self::client_sessions::signing_session_ecdsa;
pub use self::client_sessions::signing_session_schnorr;

pub mod cluster;
pub mod cluster_message_processor;
pub mod cluster_sessions;
mod cluster_sessions_creator;
pub mod connection_trigger;
pub mod connection_trigger_with_migration;
pub mod io;
pub mod jobs;
pub mod math;
pub mod message;
