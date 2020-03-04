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

use std::collections::{BTreeSet, VecDeque};
use std::sync::Arc;
use parking_lot::Mutex;
use crate::key_server_cluster::{Error, NodeId};
use crate::key_server_cluster::message::Message;
use crate::network::{ConnectionProvider, ConnectionManager, Connection};

/// Shared messages queue.
pub type InMemoryMessagesQueue = Arc<Mutex<VecDeque<(NodeId, NodeId, Message)>>>;

/// Single node connections.
pub struct InMemoryConnections {
	core: Arc<Mutex<InMemoryConnectionsData>>,
}

pub struct InMemoryConnectionsManager {
	core: Arc<Mutex<InMemoryConnectionsData>>,
}

pub struct InMemoryConnectionsData {
	node: NodeId,
	is_isolated: bool,
	connected_nodes: BTreeSet<NodeId>,
	disconnected_nodes: BTreeSet<NodeId>,
	messages: InMemoryMessagesQueue,
}

/// Single connection.
pub struct InMemoryConnection {
	from: NodeId,
	to: NodeId,
	messages: InMemoryMessagesQueue,
}

impl InMemoryConnections {
	pub fn manager(&self) -> Arc<InMemoryConnectionsManager> {
		Arc::new(InMemoryConnectionsManager { core: self.core.clone() })
	}
}

impl InMemoryConnectionsManager {
	pub fn isolate(&self) {
		let mut core = self.core.lock();
		let connected_nodes = ::std::mem::replace(&mut core.connected_nodes, Default::default());
		core.is_isolated = true;
		core.disconnected_nodes.extend(connected_nodes)
	}

	pub fn disconnect(&self, node: NodeId) {
		self.core.lock().connected_nodes.remove(&node);
		self.core.lock().disconnected_nodes.insert(node);
	}

	pub fn exclude(&self, node: NodeId) {
		self.core.lock().connected_nodes.remove(&node);
		self.core.lock().disconnected_nodes.remove(&node);
	}

	pub fn include(&self, node: NodeId) {
		self.core.lock().connected_nodes.insert(node);
	}
}

impl ConnectionManager for InMemoryConnectionsManager {
	fn provider(&self) -> Arc<dyn ConnectionProvider> {
		Arc::new(InMemoryConnections { core: self.core.clone() })
	}

	fn connect(&self) {}
}

impl ConnectionProvider for InMemoryConnections {
	fn connected_nodes(&self) -> Result<BTreeSet<NodeId>, Error> {
		let core = self.core.lock();
		match core.is_isolated {
			false => Ok(core.connected_nodes.clone()),
			true => Err(Error::NodeDisconnected),
		}
	}

	fn disconnected_nodes(&self) -> BTreeSet<NodeId> {
		self.core.lock().disconnected_nodes.clone()
	}

	fn connection(&self, node: &NodeId) -> Option<Arc<dyn Connection>> {
		let core = self.core.lock();
		match core.connected_nodes.contains(node) {
			true => Some(Arc::new(InMemoryConnection {
				from: core.node,
				to: *node,
				messages: core.messages.clone(),
			})),
			false => None,
		}
	}
}

impl Connection for InMemoryConnection {
	fn is_inbound(&self) -> bool {
		false
	}

	fn node_id(&self) -> &NodeId {
		&self.to
	}

	fn node_address(&self) -> String {
		format!("{}", self.to)
	}

	fn send_message(&self, message: Message) {
		self.messages.lock().push_back((self.from, self.to, message))
	}
}

pub fn new_in_memory_connections(
	messages: InMemoryMessagesQueue,
	node: NodeId,
	mut nodes: BTreeSet<NodeId>
) -> Arc<InMemoryConnections> {
	let is_isolated = !nodes.remove(&node);
	Arc::new(InMemoryConnections {
		core: Arc::new(Mutex::new(InMemoryConnectionsData {
			node,
			is_isolated,
			connected_nodes: nodes,
			disconnected_nodes: Default::default(),
			messages,
		})),
	})
}
