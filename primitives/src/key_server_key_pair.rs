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

use ethereum_types::H256;
use parity_crypto::publickey::{Address, KeyPair, Public, Signature, public_to_address, sign};
use crate::error::Error;

/// Key Server key pair.
///
/// Every key server owns a key pair that it is used to encrypt its private data and
/// sign its messages.
pub trait KeyServerKeyPair: Send + Sync {
	/// Get public portion of key.
	fn public(&self) -> &Public;
	/// Get address of key owner.
	fn address(&self) -> Address;
	/// Sign data with the key.
	fn sign(&self, data: &H256) -> Result<Signature, Error>;
}

/// In-memory implementation of server key pair.
pub struct InMemoryKeyServerKeyPair {
	key_pair: KeyPair,
}

impl InMemoryKeyServerKeyPair {
	/// Create new key server key pair using given key pair.
	pub fn new(key_pair: KeyPair) -> Self {
		InMemoryKeyServerKeyPair {
			key_pair: key_pair,
		}
	}

	/// Get key pair reference.
	pub fn key_pair(&self) -> &KeyPair {
		&self.key_pair
	}
}

impl KeyServerKeyPair for InMemoryKeyServerKeyPair {
	fn public(&self) -> &Public {
		self.key_pair.public()
	}

	fn address(&self) -> Address {
		public_to_address(self.key_pair.public())
	}

	fn sign(&self, data: &H256) -> Result<Signature, Error> {
		sign(self.key_pair.secret(), data).map_err(Into::into)
	}
}
