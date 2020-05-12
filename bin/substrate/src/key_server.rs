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
use primitives::{
	error::Error,
	executor::TokioHandle,
	key_server_set::KeyServerSet,
	key_server_key_pair::KeyServerKeyPair,
};
use key_server::{ClusterConfiguration, KeyServerImpl, db_key_storage::PersistentKeyStorage};
use crate::{
	acl_storage::OnChainAclStorage,
};

/// Start Secret Store key server.
pub fn start(
	executor: TokioHandle,
	key_server_key_pair: Arc<dyn KeyServerKeyPair>,
	listen_port: u16,
	key_storage: Arc<PersistentKeyStorage>,
	acl_storage: Arc<OnChainAclStorage>,
	key_server_set: Arc<dyn KeyServerSet<NetworkAddress=std::net::SocketAddr>>,
) -> Result<Arc<KeyServerImpl>, Error> {
	let key_server_config = ClusterConfiguration {
		admin_address: None,
		auto_migrate_enabled: true,
	};
	key_server::Builder::new()
		.with_self_key_pair(key_server_key_pair)
		.with_acl_storage(acl_storage)
		.with_key_storage(key_storage)
		.with_config(key_server_config)
		.build_for_tcp(
			executor,
			key_server::network::tcp::NodeAddress {
				address: "127.0.0.1".into(),
				port: listen_port,
			},
			key_server_set,
		)
}
