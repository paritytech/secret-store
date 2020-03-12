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
use parking_lot::RwLock;
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
pub struct InMemoryKeyServerSet {
	support_migration: bool,
	self_id: KeyServerId,
	data: RwLock<InMemoryKeyServerSetData>,
}

struct InMemoryKeyServerSetData {
	current_set: BTreeMap<KeyServerId, SocketAddr>,
	new_set: BTreeMap<KeyServerId, SocketAddr>,
	migration: Option<KeyServerSetMigration<SocketAddr>>,
}

impl InMemoryKeyServerSet {
	/// Create new in-memory key server set WITHOUT migration support.
	pub fn new(
		support_migration: bool,
		key_server_id: KeyServerId,
		nodes: BTreeMap<KeyServerId, SocketAddr>,
	) -> Self {
		InMemoryKeyServerSet {
			support_migration,
			self_id: key_server_id,
			data: RwLock::new(InMemoryKeyServerSetData {
				current_set: nodes.clone(),
				new_set: nodes,
				migration: None,
			}),
		}
	}

	/// Add new key server to the set.
	pub fn add_key_server(&self, id: KeyServerId, address: SocketAddr) {
		let mut data = self.data.write();
		data.new_set.insert(id, address);
		if !self.support_migration {
			data.current_set.insert(id, address);
		}
	}

	/// 'Receive' migration signal from other node.
	pub fn receive_migration_signal(&self, id: MigrationId, master: KeyServerId) {
		let mut data = self.data.write();
		data.migration = Some(KeyServerSetMigration {
			id,
			set: data.new_set.clone(),
			master,
			is_confirmed: false,
		});
	}

	/// Complete migration.
	pub fn complete_migration(&self) {
		let mut data = self.data.write();
		data.current_set = data.migration.take().unwrap().set;
	}
}

impl KeyServerSet for InMemoryKeyServerSet {
	type NetworkAddress = SocketAddr;

	fn is_isolated(&self) -> bool {
		self.data.read().current_set.contains_key(&self.self_id)
	}

	fn snapshot(&self) -> KeyServerSetSnapshot<Self::NetworkAddress> {
		let data = self.data.read();
		KeyServerSetSnapshot {
			current_set: data.current_set.clone(),
			new_set: data.new_set.clone(),
			migration: data.migration.clone(),
		}
	}

	fn start_migration(&self, migration_id: MigrationId) {
		debug_assert!(self.support_migration);

		let mut data = self.data.write();
		debug_assert!(data.migration.is_none());
		data.migration = Some(KeyServerSetMigration {
			id: migration_id,
			set: data.new_set.clone(),
			master: self.self_id,
			is_confirmed: false,
		});
	}

	fn confirm_migration(&self, migration_id: MigrationId) {
		debug_assert!(self.support_migration);

		let mut data = self.data.write();
		let migration = data.migration.as_mut().unwrap();
		debug_assert_eq!(migration.id, migration_id);
		debug_assert!(migration.set.contains_key(&self.self_id));
		migration.is_confirmed = true;
	}
}
