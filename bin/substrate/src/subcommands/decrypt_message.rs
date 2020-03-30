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
use crate::subcommands::utils::{INIT_VEC_LEN, into_document_key, require_bytes_arg, require_secret_arg};

/// Decrypt message using encrypted document key.
pub fn run(matches: &ArgMatches) {
	let parse_arguments = || -> Result<_, String> {
		let encrypted_document_key = require_bytes_arg(matches, "encrypted-document-key")?;
		let requester_secret = require_secret_arg(matches, "requester-secret")?;
		let encrypted_message = require_bytes_arg(matches, "encrypted-message")?;
		Ok((encrypted_document_key, requester_secret, encrypted_message))
	};

	let decrypt_message = move |
		(encrypted_document_key, requester_secret, mut encrypted_message): (Vec<u8>, Secret, Vec<u8>)
	| -> Result<(), String> {
		// decrypt document key with requester secret
		let key = parity_crypto::publickey::ecies::decrypt(
			&requester_secret,
			&parity_crypto::DEFAULT_MAC,
			&encrypted_document_key[..],
		)
		.map_err(|err| format!("Error decrypting document key: {}", err))
		.and_then(into_document_key)?;

		// initialization vector takes INIT_VEC_LEN bytes
		let encrypted_message_len = encrypted_message.len();
		if encrypted_message_len < INIT_VEC_LEN {
			return Err(format!("Invalid encrypted message length: {}", encrypted_message_len));
		}

		// use symmetric decryption to decrypt document
		let iv = encrypted_message.split_off(encrypted_message_len - INIT_VEC_LEN);
		let mut message = vec![0; encrypted_message_len - INIT_VEC_LEN];
		parity_crypto::aes::decrypt_128_ctr(&key, &iv, &encrypted_message, &mut message)
			.map_err(|err| format!("Error decrypting message: {}", err))?;

		let sdocument = std::str::from_utf8(&message)
			.map_err(|err| format!("Error decoding message: {} (supposed to be UTF8-encoded string)", err))?;

		info!(target: "secretstore", "Decrypted message: {:?}", sdocument);

		Ok(())
	};

	let result = parse_arguments().and_then(decrypt_message);
	if let Err(error) = result {
		error!(target: "secretstore", "Failed to decrypt message: {}", error);
	}
}
