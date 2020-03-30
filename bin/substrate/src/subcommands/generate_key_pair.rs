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

use clap::ArgMatches;
use log::info;
use parity_crypto::publickey::{Generator, Random, public_to_address};

/// Generate Secp256k1 key pair.
pub fn run(_matches: &ArgMatches) {
	let key_pair = Random.generate();

	info!(target: "secretstore", "Address: {:?}", public_to_address(key_pair.public()));
	info!(target: "secretstore", "Public: {:?}", key_pair.public());
	info!(target: "secretstore", "Secret: {:?}", key_pair.secret());
}
