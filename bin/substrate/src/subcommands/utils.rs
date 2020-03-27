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

use std::str::FromStr;
use clap::ArgMatches;
use parity_crypto::publickey::{Public, Secret};
use rand::{RngCore, rngs::OsRng};

/// Proof that argument exists.
const REQUIRED_ARG_PROOF: &'static str = "ArgMatches are only created when arguments are validated;\
	this argument is required;\
	qed";

/// Initialization vector length.
pub const INIT_VEC_LEN: usize = 16;

/// Convert decrypted document key into actual key for symmetric encryption.
pub fn into_document_key(key: Vec<u8>) -> Result<Vec<u8>, String> {
	// key is a previously distributely generated Public
	if key.len() != 64 {
		return Err(format!("Invalid document key length: {}", key.len()));
	}

	// use x coordinate of distributely generated point as encryption key
	Ok(key[..INIT_VEC_LEN].into())
}

/// Return random initialization vector.
pub fn initialization_vector() -> [u8; INIT_VEC_LEN] {
	let mut result = [0u8; INIT_VEC_LEN];
	let mut rng = OsRng;
	rng.fill_bytes(&mut result);
	result
}

/// Parse required hex-encoded Vec<u8> arg.
pub fn require_bytes_arg(matches: &ArgMatches, arg: &str) -> Result<Vec<u8>, String> {
	hex::decode(
		matches
			.value_of(arg)
			.expect(REQUIRED_ARG_PROOF)
			.trim_start_matches("0x")
	).map_err(|err| format!("Failed to parse {} argument: {}", arg, err))
}

/// Parse required hex-encoded Vec<Vec<u8>> arg.
pub fn require_multiple_bytes_arg(matches: &ArgMatches, arg: &str) -> Result<Vec<Vec<u8>>, String> {
	matches
		.values_of(arg)
		.expect(REQUIRED_ARG_PROOF)
		.into_iter()
		.map(|sbytes| hex::decode(
			sbytes
				.trim_start_matches("0x"))
				.map_err(|err| format!("Failed to parse {} argument: {}", arg, err))
		)
		.collect::<Result<Vec<_>, _>>()
}

/// Parse required hex-encoded Public arg.
pub fn require_public_arg(matches: &ArgMatches, arg: &str) -> Result<Public, String> {
	Public::from_str(
		matches
			.value_of(arg)
			.expect(REQUIRED_ARG_PROOF)
			.trim_start_matches("0x")
	).map_err(|err| format!("Failed to parse {} argument: {}", arg, err))
}

/// Parse required hex-encoded Secret arg.
pub fn require_secret_arg(matches: &ArgMatches, arg: &str) -> Result<Secret, String> {
	Secret::from_str(
		matches
			.value_of(arg)
			.expect(REQUIRED_ARG_PROOF)
			.trim_start_matches("0x")
	).map_err(|err| format!("Failed to parse {} argument: {}", arg, err))
}

/// Parse required string argument.
pub fn require_string_arg<'a>(matches: &'a ArgMatches, arg: &str) -> Result<&'a str, String> {
	Ok(matches.value_of(arg).expect(REQUIRED_ARG_PROOF))
}
