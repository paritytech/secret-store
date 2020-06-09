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
	collections::{BTreeMap, BTreeSet},
	fmt::{Debug, Formatter, Error as FmtError},
	sync::Arc,
};
use parity_crypto::publickey::{Generator, Random, Public, KeyPair};
use crate::key_server_cluster::{
	{Error, NodeId},
	math,
	io::{encrypt_data, decrypt_data},
	message::{
		RandomPointGenerationMessage,
		RandomPointGenerationEncryptedShare, RandomPointGenerationDecryptionKey,
	},
};

/// Random point generation session transport.
///
/// This session is always wrapped, so we don't care about nonces and session IDs.
pub trait SessionTransport: Send + Sync {
	/// Send message to given node.
	fn send(&self, node: &NodeId, message: RandomPointGenerationMessage) -> Result<(), Error>;
}

/// Random point generation session.
/// Based on EC-Rand() from "Secure Multi-Party Computation for Elliptic Curves":
/// 1) all nodes (i within [1; n]) generate random points Pi and random key pair Ei;
/// 2) all nodes encrypt Pi with Ei.Public and broadcast encrypted(Pi);
/// 3) when node has received encrypted(Pi) from all other nodes, it broadcasts its Ei.private;
/// 4) when node receives Ei.private from all nodes, it decrypts shares Ei;
/// 5) Sum(Ei) is the random EC point with corresponding provate key unknown to all other nodes.
///
/// The broadcast of Sum(Ei) (and verification that it is the same on all nodes) is supposed to
/// happen outside of this session.
pub struct SessionImpl {
	/// This node id.
	self_node_id: NodeId,
	/// Session transport.
	transport: Arc<dyn SessionTransport>,
	/// Current state of the session.
	state: SessionState,
	/// Nodes-specific data.
	nodes: BTreeMap<NodeId, NodeData>,
	/// Session result.
	result: Option<Public>,
}

/// Mutable node-specific data.
#[derive(Debug, Default)]
struct NodeData {
	/// Encrypted (ECIES) share.
	encrypted_share: Option<Vec<u8>>,
	/// Decryption key pair.
	decryption_key: Option<KeyPair>,
}

/// Distributed key generation session state.
#[derive(Debug, Clone, PartialEq)]
enum SessionState {
	/// Session isn't yet started.
	WaitingForStart,
	/// Node has broadcasted encrypted share and waits for other nodes encrypted shares.
	WaitingForEncryptedShares,
	/// Node has broadcasted decryption key and waits for other nodes decryption keys.
	WaitingForDecryptionKeys,
	/// Session has completed successfully.
	Finished,
}

impl SessionImpl {
	/// Create new generation session.
	pub fn new(self_node_id: NodeId, transport: Arc<dyn SessionTransport>) -> Self {
		SessionImpl {
			self_node_id,
			transport,
			state: SessionState::WaitingForStart,
			nodes: BTreeMap::new(),
			result: None,
		}
	}

	/// Returns true if session has been started.
	pub fn is_started(&self) -> bool {
		self.state != SessionState::WaitingForStart
	}

	/// Returns generated random point.
	pub fn generated_point(&self) -> Option<Public> {
		self.result.clone()
	}

	/// 'Complete' session with given point. To be used in tests only.
	#[cfg(test)]
	pub fn complete_with(&mut self, point: Public) {
		self.result = Some(point);
		self.state = SessionState::Finished;
	}

	/// Starts this session.
	pub fn start(&mut self, nodes: BTreeSet<NodeId>) -> Result<(), Error> {
		match self.state {
			SessionState::WaitingForStart => (),
			_ => return Err(Error::InvalidStateForRequest),
		}

		// fill nodes
		assert!(nodes.contains(&self.self_node_id));
		self.nodes = nodes
			.into_iter()
			.map(|node_id| (node_id, NodeData {
				encrypted_share: None,
				decryption_key: None,
			}))
			.collect();

		// generate and encrypt own share
		let self_decryption_key = Random.generate();
		let self_share = math::generate_random_point()?;
		let self_encrypted_share = encrypt_data(
			&self_decryption_key,
			self_share.as_bytes(),
		)?;
		let self_node_data = self.nodes
			.get_mut(&self.self_node_id)
			.expect("inserted above; qed");
		self_node_data.encrypted_share = Some(self_encrypted_share.clone());
		self_node_data.decryption_key = Some(self_decryption_key);

		// if we are single node, just compute generated point
		if self.nodes.len() == 1 {
			self.state = SessionState::WaitingForDecryptionKeys;
			return self.compute_generated_point();
		}

		// else broadcast encrypted share
		for node in self.nodes.keys().filter(|n| **n != self.self_node_id) {
			self.transport.send(&node, RandomPointGenerationMessage::EncryptedShare(
				RandomPointGenerationEncryptedShare {
					encrypted_share: self_encrypted_share.clone(),
				}
			))?;
		}

		self.state = SessionState::WaitingForEncryptedShares;

		Ok(())
	}

	/// Process single message.
	pub fn process_message(&mut self, sender: &NodeId, message: &RandomPointGenerationMessage) -> Result<(), Error> {
		match message {
			&RandomPointGenerationMessage::EncryptedShare(ref message) =>
				self.on_encrypted_share(sender, message),
			&RandomPointGenerationMessage::DecryptionKey(ref message) =>
				self.on_decryption_key(sender, message),
		}
	}

	/// When encrypted share is received.
	pub fn on_encrypted_share(&mut self, sender: &NodeId, message: &RandomPointGenerationEncryptedShare) -> Result<(), Error> {
		match self.state {
			SessionState::WaitingForStart => return Err(Error::TooEarlyForRequest),
			SessionState::WaitingForEncryptedShares => (),
			_ => return Err(Error::InvalidStateForRequest),
		}

		{
			let node_data = self.nodes.get_mut(sender).ok_or(Error::InvalidMessage)?;
			if node_data.encrypted_share.is_some() {
				return Err(Error::InvalidMessage);
			}

			node_data.encrypted_share = Some(message.encrypted_share.clone());
		}

		if self.nodes.values().any(|n| n.encrypted_share.is_none()) {
			return Ok(());
		}

		let self_decryption_key = self.nodes
			.get(&self.self_node_id)
			.expect("inserted when session is started and never deleted; qed")
			.decryption_key
			.clone()
			.expect("initialized when session is started and never deleted; qed");
		self.state = SessionState::WaitingForDecryptionKeys;
		for node in self.nodes.keys().filter(|n| **n != self.self_node_id) {
			self.transport.send(&node, RandomPointGenerationMessage::DecryptionKey(
				RandomPointGenerationDecryptionKey {
					decryption_key: self_decryption_key.secret().clone().into(),
				}
			))?;
		}

		Ok(())
	}

	/// When decryption key is received.
	pub fn on_decryption_key(&mut self, sender: &NodeId, message: &RandomPointGenerationDecryptionKey) -> Result<(), Error> {
		match self.state {
			SessionState::WaitingForStart | SessionState::WaitingForEncryptedShares =>
				return Err(Error::TooEarlyForRequest),
			SessionState::WaitingForDecryptionKeys => (),
			_ => return Err(Error::InvalidStateForRequest),
		}

		{
			let node_data = self.nodes.get_mut(sender).ok_or(Error::InvalidMessage)?;
			if node_data.decryption_key.is_some() {
				return Err(Error::InvalidMessage);
			}

			node_data.decryption_key = Some(KeyPair::from_secret(message.decryption_key.clone().into())?);
		}

		if self.nodes.values().any(|n| n.decryption_key.is_none()) {
			return Ok(());
		}

		self.compute_generated_point()
	}

	/// Compute generated point.
	fn compute_generated_point(&mut self) -> Result<(), Error> {
		let mut shares = Vec::with_capacity(self.nodes.len());
		for (node_id,node_data) in &self.nodes {
			let raw_share = decrypt_data(
				node_data.decryption_key.as_ref().expect("checked above; qed"),
				&node_data.encrypted_share.as_ref().expect("we are in WaitingForDecryptionKeys state;
					WaitingForDecryptionKeys follows WaitingForEncryptedShares state;
					WaitingForEncryptedShares -> WaitingForDecryptionKeys only happens when all encrypted shares are reqceived;
					qed"),
			)?;
			if raw_share.len() != 64 {
				return Err(Error::Internal(format!("Invalid share is provided by {}", node_id)));
			}
			shares.push(Public::from_slice(&raw_share));
		}

		self.result = Some(math::compute_public_sum(shares.iter())?);
		self.state = SessionState::Finished;
	
		Ok(())
	}
}

impl Debug for SessionImpl {
	fn fmt(&self, f: &mut Formatter) -> Result<(), FmtError> {
		write!(f, "Random point generation session on {}", self.self_node_id)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	struct DummyTransport;

	impl SessionTransport for DummyTransport {
		fn send(&self, _: &NodeId, _: RandomPointGenerationMessage) -> Result<(), Error> {
			Ok(())
		}
	}

	fn node(index: u8) -> NodeId {
		[index; 20].into()
	}

	fn single_node() -> BTreeSet<NodeId> {
		vec![node(1)].into_iter().collect()
	}

	fn dummy_nodes() -> BTreeSet<NodeId> {
		vec![node(1), node(2), node(3)].into_iter().collect()
	}

	fn dummy_session(nodes: BTreeSet<NodeId>) -> SessionImpl {
		SessionImpl::new(nodes.into_iter().next().unwrap(), Arc::new(DummyTransport))
	}

	#[test]
	fn rpg_session_rejects_to_start_twice() {
		let mut session = dummy_session(dummy_nodes());
		assert_eq!(session.start(dummy_nodes()), Ok(()));
		assert_eq!(session.start(dummy_nodes()), Err(Error::InvalidStateForRequest));
	}

	#[test]
	fn rpg_session_on_single_node_completes_instantly() {
		let mut session = dummy_session(single_node());
		assert_eq!(session.start(single_node()), Ok(()));
		assert_eq!(session.state, SessionState::Finished);
		assert!(session.generated_point().is_some());
	}

	#[test]
	fn rpg_session_rejects_encrypted_share() {
		let mut session = dummy_session(dummy_nodes());
		let message = RandomPointGenerationMessage::EncryptedShare(
			RandomPointGenerationEncryptedShare {
				encrypted_share: vec![42],
			},
		);
		// before start
		assert_eq!(session.process_message(&node(2), &message), Err(Error::TooEarlyForRequest));
		// after receiving all shares
		session.state = SessionState::WaitingForDecryptionKeys;
		assert_eq!(session.process_message(&node(2), &message), Err(Error::InvalidStateForRequest));
		// after finish
		session.state = SessionState::Finished;
		assert_eq!(session.process_message(&node(2), &message), Err(Error::InvalidStateForRequest));
		// after receving share from the same node
		session.state = SessionState::WaitingForEncryptedShares;
		session.nodes.entry(node(2)).or_default().encrypted_share = Some(vec![42]);
		assert_eq!(session.process_message(&node(2), &message), Err(Error::InvalidMessage));
	}

	#[test]
	fn rpg_session_accepts_encrypted_shares() {
		let mut session = dummy_session(dummy_nodes());
		let message = RandomPointGenerationMessage::EncryptedShare(
			RandomPointGenerationEncryptedShare {
				encrypted_share: vec![42],
			},
		);
		session.start(dummy_nodes()).unwrap();
		assert_eq!(session.state, SessionState::WaitingForEncryptedShares);

		assert_eq!(session.process_message(&node(2), &message), Ok(()));
		assert_eq!(session.state, SessionState::WaitingForEncryptedShares);
		assert_eq!(session.process_message(&node(3), &message), Ok(()));
		assert_eq!(session.state, SessionState::WaitingForDecryptionKeys);
	}

	#[test]
	fn rpg_session_rejects_decryption_keys() {
		let mut session = dummy_session(dummy_nodes());
		let message = RandomPointGenerationMessage::DecryptionKey(
			RandomPointGenerationDecryptionKey {
				decryption_key: [1u8; 32].into(),
			},
		);

		// before start
		assert_eq!(session.process_message(&node(2), &message), Err(Error::TooEarlyForRequest));
		// when receiving shares
		session.state = SessionState::WaitingForEncryptedShares;
		assert_eq!(session.process_message(&node(2), &message), Err(Error::TooEarlyForRequest));
		// after finish
		session.state = SessionState::Finished;
		assert_eq!(session.process_message(&node(2), &message), Err(Error::InvalidStateForRequest));
		// after receving key from the same node
		session.state = SessionState::WaitingForDecryptionKeys;
		session.nodes.entry(node(2)).or_default().decryption_key = Some(KeyPair::from_secret_slice(&[1u8; 32]).unwrap());
		assert_eq!(session.process_message(&node(2), &message), Err(Error::InvalidMessage));
	}

	#[test]
	fn rpg_session_works() {
		let decryption_key = Random.generate();
		let share = math::generate_random_point().unwrap();
		let encrypted_share = encrypt_data(&decryption_key, share.as_bytes()).unwrap();

		let mut session = dummy_session(dummy_nodes());
		let message = RandomPointGenerationMessage::EncryptedShare(
			RandomPointGenerationEncryptedShare {
				encrypted_share,
			},
		);
		session.start(dummy_nodes()).unwrap();
		assert_eq!(session.state, SessionState::WaitingForEncryptedShares);

		assert_eq!(session.process_message(&node(2), &message), Ok(()));
		assert_eq!(session.state, SessionState::WaitingForEncryptedShares);
		assert_eq!(session.process_message(&node(3), &message), Ok(()));
		assert_eq!(session.state, SessionState::WaitingForDecryptionKeys);

		let message = RandomPointGenerationMessage::DecryptionKey(
			RandomPointGenerationDecryptionKey {
				decryption_key: decryption_key.secret().clone().into(),
			},
		);

		assert_eq!(session.process_message(&node(2), &message), Ok(()));
		assert_eq!(session.state, SessionState::WaitingForDecryptionKeys);
		assert_eq!(session.process_message(&node(3), &message), Ok(()));
		assert_eq!(session.state, SessionState::Finished);
		assert!(session.generated_point().is_some());
	}
}
