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

use std::{
	collections::BTreeMap,
	fmt::Debug,
	net::SocketAddr,
};
use ethereum_types::H256;
use crate::KeyServerId;

/// Every migration process has its own unique id.
pub type MigrationId = H256;

/// Key Server Set state.
#[derive(Default, Debug, Clone, PartialEq)]
pub struct KeyServerSetSnapshot<Address> {
	/// Current set of key servers.
	pub current_set: BTreeMap<KeyServerId, Address>,
	/// New set of key servers. If it differs from the current set, then
	/// the migration should be started.
	pub new_set: BTreeMap<KeyServerId, Address>,
	/// Current migration data. None if migration isn't started.
	pub migration: Option<KeyServerSetMigration<Address>>,
}

/// Key Server set migration.
#[derive(Default, Debug, Clone, PartialEq)]
pub struct KeyServerSetMigration<Address> {
	/// Migration id.
	pub id: MigrationId,
	/// Migration set of key servers. It is the new_set at the moment when
	/// migration has been started.
	pub set: BTreeMap<KeyServerId, Address>,
	/// Master node of the migration process.
	pub master: KeyServerId,
	/// Is migration confirmed by this node?
	pub is_confirmed: bool,
}

/// Key Server Set.
pub trait KeyServerSet: Send + Sync {
	/// Type of address we need to know to connect remote key servers.
	type NetworkAddress: Send + Sync;

	/// Is this node currently isolated from the set?
	fn is_isolated(&self) -> bool;
	/// Get server set state.
	fn snapshot(&self) -> KeyServerSetSnapshot<Self::NetworkAddress>;
	/// Start migration.
	fn start_migration(&self, migration_id: MigrationId);
	/// Confirm migration.
	fn confirm_migration(&self, migration_id: MigrationId);
}

/// In-memory key server set implementation.
#[derive(Default)]
pub struct InMemoryKeyServerSet {
	is_isolated: bool,
	nodes: BTreeMap<KeyServerId, SocketAddr>,
}

impl InMemoryKeyServerSet {
	/// Create new in-memory key server set.
	pub fn new(is_isolated: bool, nodes: BTreeMap<KeyServerId, SocketAddr>) -> Self {
		InMemoryKeyServerSet {
			is_isolated: is_isolated,
			nodes: nodes,
		}
	}
}

impl KeyServerSet for InMemoryKeyServerSet {
	type NetworkAddress = SocketAddr;

	fn is_isolated(&self) -> bool {
		self.is_isolated
	}

	fn snapshot(&self) -> KeyServerSetSnapshot<Self::NetworkAddress> {
		KeyServerSetSnapshot {
			current_set: self.nodes.clone(),
			new_set: self.nodes.clone(),
			migration: None,
		}
	}

	fn start_migration(&self, _migration_id: MigrationId) {
		// nothing to do here
	}

	fn confirm_migration(&self, _migration_id: MigrationId) {
		// nothing to do here
	}
}
