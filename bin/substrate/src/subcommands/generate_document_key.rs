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
use log::{error, info};
use parity_crypto::publickey::{Generator, Random};
use crate::subcommands::utils::require_public_arg;

/// Generate document key.
pub fn run(matches: &ArgMatches) {
	let parse_arguments = || {
		let server_key = require_public_arg(matches, "server-key")?;
		let author_key = require_public_arg(matches, "author-key")?;
		Ok((server_key, author_key))
	};

	let generate_document_key = move |(server_key, author_key)| -> Result<(), String> {
		// generate plain document key
		let document_key = Random.generate();

		// encrypt document key using server key
		let distributed_encrypted_key = key_server::math::encrypt_secret(
			document_key.public(),
			&server_key,
		).map_err(|err| format!("Error generating document key: {}", err))?;

		// ..and now encrypt document key with author public
		let encrypted_key = parity_crypto::publickey::ecies::encrypt(
			&author_key,
			&parity_crypto::DEFAULT_MAC,
			document_key.public().as_bytes(),
		).map_err(|err| format!("Error encrypting document key: {}", err))?;

		info!(target: "secretstore", "Common point: {:?}", distributed_encrypted_key.common_point);
		info!(target: "secretstore", "Encrypted point: {:?}", distributed_encrypted_key.encrypted_point);
		info!(target: "secretstore", "Encrypted key: 0x{}", hex::encode(encrypted_key));

		Ok(())
	};

	let result = parse_arguments().and_then(generate_document_key);
	if let Err(error) = result {
		error!(target: "secretstore", "Failed to generate document key: {}", error);
	}
}
