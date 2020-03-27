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
use parity_crypto::publickey::Secret;
use crate::subcommands::utils::{
	into_document_key, initialization_vector,
	require_bytes_arg, require_secret_arg, require_string_arg,
};

/// Encrypt message using encrypted document key.
pub fn run(matches: &ArgMatches) {
	let parse_arguments = || {
		let encrypted_document_key = require_bytes_arg(matches, "encrypted-document-key")?;
		let author_secret = require_secret_arg(matches, "author-secret")?;
		let message = require_string_arg(matches, "message")?.as_bytes().to_vec();
		Ok((encrypted_document_key, author_secret, message))
	};

	let encrypt_message = move |
		(encrypted_document_key, author_secret, message): (Vec<u8>, Secret, Vec<u8>)
	| -> Result<(), String> {
		// decrypt document key with author secret
		let key = parity_crypto::publickey::ecies::decrypt(
			&author_secret,
			&parity_crypto::DEFAULT_MAC,
			&encrypted_document_key[..],
		)
		.map_err(|err| format!("Error decrypting document key: {}", err))
		.and_then(into_document_key)?;

		// use symmetric encryption to encrypt message
		let iv = initialization_vector();
		let mut encrypted_message = vec![0; message.len() + iv.len()];
		{
			let (mut encryption_buffer, iv_buffer) = encrypted_message.split_at_mut(message.len());

			parity_crypto::aes::encrypt_128_ctr(&key, &iv, &message, &mut encryption_buffer)
				.map_err(|err| format!("Error encrypting message: {}", err))?;
			iv_buffer.copy_from_slice(&iv);
		}

		info!(target: "secretstore", "Encrypted message: 0x{}", hex::encode(encrypted_message));

		Ok(())
	};

	let result = parse_arguments().and_then(encrypt_message);
	if let Err(error) = result {
		error!(target: "secretstore", "Failed to encrypt message: {}", error);
	}
}
