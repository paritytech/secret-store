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

use parity_crypto::publickey::{Address, Public, Signature, public_to_address, recover};
use crate::{error::Error, ServerKeyId};

/// Requester identification data.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Requester {
	/// Requested with server key id signature.
	Signature(Signature),
	/// Requested with public key.
	Public(Public),
	/// Requested with verified address.
	Address(Address),
}

impl Requester {
	/// Return requester public key.
	pub fn public(&self, server_key_id: &ServerKeyId) -> Result<Public, Error> {
		match *self {
			Requester::Signature(ref signature) => recover(signature, server_key_id)
				.map_err(|e| Error::Internal(format!("bad signature: {}", e))),
			Requester::Public(ref public) => Ok(public.clone()),
			Requester::Address(_) => Err(Error::InsufficientRequesterData("cannot recover public from address".into())),
		}
	}

	/// Return requester address.
	pub fn address(&self, server_key_id: &ServerKeyId) -> Result<Address, Error> {
		match *self {
			Requester::Address(address) => Ok(address),
			_ => self.public(server_key_id).map(|p| public_to_address(&p)),
		}
	}
}

impl From<Signature> for Requester {
	fn from(signature: Signature) -> Requester {
		Requester::Signature(signature)
	}
}

impl From<Public> for Requester {
	fn from(public: Public) -> Requester {
		Requester::Public(public)
	}
}

impl From<Address> for Requester {
	fn from(address: Address) -> Requester {
		Requester::Address(address)
	}
}

impl std::fmt::Display for Requester {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
		write!(f, "{:?}", self)
	}
}
