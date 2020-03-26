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

use std::{collections::HashMap, str::FromStr};
use clap::ArgMatches;
use log::{error, info};
use parity_crypto::publickey::{public_to_address, Public};
use primitives::ServerKeyId;
use crate::substrate_client::Client;

/// All possible SecretStore transactions we support.
pub enum SecretStoreTransaction {
	// === Meta calls ===

	/// Change owner.
//	ChangeOwner(crate::runtime::AccountId),
	/// Claim id.
//	ClaimId(Address),
	/// Claim key.
	ClaimKey(ServerKeyId),
	/// Transfer key ownership.
//	TransferKey(ServerKeyId, Address),

	// === Key Server Set calls ===

	/// Complete key server set initialization.
//	CompleteInitialization,
	/// Add key server to the set.
//	AddKeyServer(KeyServerId, String, u16),
	/// Update key server from the set.
//	UpdateKeyServer(KeyServerId, String, u16),
	/// Remove key server from the set.
//	UpdateKeyServer(KeyServerId),

	// === Key Server calls ===

	/// Generate server key.
	GenerateServerKey(ServerKeyId, u8),
	/// Retrieve server key.
	RetrieveServerKey(ServerKeyId),
	/// Store document key.
	StoreDocumentKey(ServerKeyId, Public, Public),
	/// Retrieve document key shadow.
	RetrieveDocumentKeyShadow(ServerKeyId, Public),
}

/// Submit Substrate transaction.
pub fn run(matches: &ArgMatches) {
	let is_wait_mined = true;
	let is_wait_finalized = true;
	let is_wait_processed = true;
	let transaction = match parse_transaction(
		matches.value_of("sub-call").expect("TODO")
	) {
		Ok(transaction) => transaction,
		Err(error) => {
			error!(
				target: "secretstore",
				"Failed to parse call: {}",
				error,
			);
			return;
		},
	};

	let mut pool = futures::executor::LocalPool::new();

	let client = pool.run_until(
		Client::new(
			"ws://127.0.0.1:9944",
			crate::runtime::create_transaction_signer("//Alice", None).expect("TODO"),
		)
	).expect("TODO");

	let result = pool.run_until(
		process_transaction(
			client,
			is_wait_mined,
			is_wait_finalized,
			is_wait_processed,
			transaction,
		),
	);
	if let Err(error) = result {
		error!(
			target: "secretstore",
			"Failed to submit Substrate transaction: {:?}",
			error,
		);
	}
}

/// Parse transaction.
fn parse_transaction(stransaction: &str) -> Result<SecretStoreTransaction, String> {
	// to claim key, we only need to provide key id
	let claim_key_regex = regex::Regex::new(r"ClaimKey\((.*)\)").expect("TODO");
	if let Some(captures) = claim_key_regex.captures(stransaction) {
		let key_id = ServerKeyId::from_str(captures.get(1).expect("TODO").as_str().trim_start_matches("0x"))
			.map_err(|err| format!("{}", err))?;
		return Ok(SecretStoreTransaction::ClaimKey(key_id));
	}

	// to generate server key, caller must provide: key id and threshold
	let generate_server_key_regex = regex::Regex::new(r"GenerateServerKey\((.*),[ /t]*(.*)\)").expect("TODO");
	if let Some(captures) = generate_server_key_regex.captures(stransaction) {
		let key_id = ServerKeyId::from_str(captures.get(1).expect("TODO").as_str().trim_start_matches("0x"))
			.map_err(|err| format!("{}", err))?;
		let threshold = u8::from_str(captures.get(2).expect("TODO").as_str().trim_start_matches("0x"))
			.map_err(|err| format!("{}", err))?;
		return Ok(SecretStoreTransaction::GenerateServerKey(key_id, threshold));
	}

	// to retrieve server key, caller must provide: key id
	let retrieve_server_key_regex = regex::Regex::new(r"RetrieveServerKey\((.*)\)").expect("TODO");
	if let Some(captures) = retrieve_server_key_regex.captures(stransaction) {
		let key_id = ServerKeyId::from_str(captures.get(1).expect("TODO").as_str().trim_start_matches("0x"))
			.map_err(|err| format!("{}", err))?;
		return Ok(SecretStoreTransaction::RetrieveServerKey(key_id));
	}

	// to store document key, caller must provide: key id, common point and encrypted point
	let store_document_key_regex = regex::Regex::new(r"StoreDocumentKey\((.*),[ /t]*(.*),[ /t]*(.*)\)")
		.expect("TODO");
	if let Some(captures) = store_document_key_regex.captures(stransaction) {
		let key_id = ServerKeyId::from_str(captures.get(1).expect("TODO").as_str().trim_start_matches("0x"))
			.map_err(|err| format!("{}", err))?;
		let common_point = Public::from_str(captures.get(2).expect("TODO").as_str().trim_start_matches("0x"))
			.map_err(|err| format!("{}", err))?;
		let encrypted_point = Public::from_str(captures.get(3).expect("TODO").as_str().trim_start_matches("0x"))
			.map_err(|err| format!("{}", err))?;
		return Ok(SecretStoreTransaction::StoreDocumentKey(key_id, common_point, encrypted_point));
	}

	// to retrieve document key shadow, caller must provide: key id and its (requester) public key
	let retrieve_document_key_shadow_regex = regex::Regex::new(r"RetrieveDocumentKeyShadow\((.*),[ /t]*(.*)\)")
		.expect("TODO");
	if let Some(captures) = retrieve_document_key_shadow_regex.captures(stransaction) {
		let key_id = ServerKeyId::from_str(captures.get(1).expect("TODO").as_str().trim_start_matches("0x"))
			.map_err(|err| format!("{}", err))?;
		let requester_public = Public::from_str(captures.get(2).expect("TODO").as_str().trim_start_matches("0x"))
			.map_err(|err| format!("{}", err))?;
		return Ok(SecretStoreTransaction::RetrieveDocumentKeyShadow(key_id, requester_public));
	}

	Err("unknown call".into())
}

/// Submit and wait for transaction.
async fn process_transaction(
	client: Client,
	is_wait_mined: bool,
	is_wait_finalized: bool,
	is_wait_processed: bool,
	transaction: SecretStoreTransaction,
) -> Result<(), String> {
	// TODO: even if ClaimKey fails, we still consider it successful
	// TODO: we consider ClaimKey finalized even if it is not
	
	match transaction {
		SecretStoreTransaction::ClaimKey(id) => process_generic_transaction(
			&client,
			is_wait_mined,
			false,
			false,
			crate::runtime::SecretStoreCall::claim_key(id),
			|_| true,
			|_| true,
		).await,
		SecretStoreTransaction::GenerateServerKey(id, threshold) => process_generic_transaction(
			&client,
			is_wait_mined,
			is_wait_finalized,
			is_wait_processed,
			crate::runtime::SecretStoreCall::generate_server_key(id, threshold),
			move |event| match *event {
				crate::runtime::Event::secretstore_runtime_module(
					runtime_module::Event::ServerKeyGenerationRequested(gen_id, _, gen_threshold),
				) if gen_id == id && gen_threshold == threshold => true,
				_ => false,
			},
			move |event| match *event {
				crate::runtime::Event::secretstore_runtime_module(
					runtime_module::Event::ServerKeyGenerated(gen_id, gen_key),
				) if gen_id == id => {
					info!(
						target: "secretstore",
						"Server key has been generated: {:?}",
						gen_key,
					);
					true
				},
				crate::runtime::Event::secretstore_runtime_module(
					runtime_module::Event::ServerKeyGenerationError(gen_id),
				) if gen_id == id => {
					info!(
						target: "secretstore",
						"Server key generation has failed",
					);
					true
				},
				_ => false,
			},
		).await,
		SecretStoreTransaction::RetrieveServerKey(id) => process_generic_transaction(
			&client,
			is_wait_mined,
			is_wait_finalized,
			is_wait_processed,
			crate::runtime::SecretStoreCall::retrieve_server_key(id),
			move |event| match *event {
				crate::runtime::Event::secretstore_runtime_module(
					runtime_module::Event::ServerKeyRetrievalRequested(req_id),
				) if req_id == id => true,
				_ => false,
			},
			move |event| match *event {
				crate::runtime::Event::secretstore_runtime_module(
					runtime_module::Event::ServerKeyRetrieved(req_id, req_key),
				) if req_id == id => {
					info!(
						target: "secretstore",
						"Server key has been retrieved: {:?}",
						req_key,
					);
					true
				},
				crate::runtime::Event::secretstore_runtime_module(
					runtime_module::Event::ServerKeyRetrievalError(req_id),
				) if req_id == id => {
					info!(
						target: "secretstore",
						"Server key retrieval has failed",
					);
					true
				},
				_ => false,
			},
		).await,
		SecretStoreTransaction::StoreDocumentKey(id, common_point, encrypted_point) => process_generic_transaction(
			&client,
			is_wait_mined,
			is_wait_finalized,
			is_wait_processed,
			crate::runtime::SecretStoreCall::store_document_key(id, common_point, encrypted_point),
			move |event| match *event {
				crate::runtime::Event::secretstore_runtime_module(
					runtime_module::Event::DocumentKeyStoreRequested(req_id, _, req_cp, req_ep),
				) if req_id == id && req_cp == common_point && req_ep == encrypted_point => true,
				_ => false,
			},
			move |event| match *event {
				crate::runtime::Event::secretstore_runtime_module(
					runtime_module::Event::DocumentKeyStored(req_id),
				) if req_id == id => {
					info!(
						target: "secretstore",
						"Document key has been stored",
					);
					true
				},
				crate::runtime::Event::secretstore_runtime_module(
					runtime_module::Event::DocumentKeyStoreError(req_id),
				) if req_id == id => {
					info!(
						target: "secretstore",
						"Document key store has failed",
					);
					true
				},
				_ => false,
			},
		).await,
		SecretStoreTransaction::RetrieveDocumentKeyShadow(id, requester_public) => {
			let mut common_portion_retrieved = false;
			let mut threshold = 0xFFu8;
			let mut personal_portions = HashMap::new();
			let requester_address = public_to_address(&requester_public);

			process_generic_transaction(
				&client,
				is_wait_mined,
				is_wait_finalized,
				is_wait_processed,
				crate::runtime::SecretStoreCall::retrieve_document_key_shadow(id, requester_public),
				move |event| match *event {
					crate::runtime::Event::secretstore_runtime_module(
						runtime_module::Event::DocumentKeyShadowRetrievalRequested(req_id, req_requester),
					) if req_id == id && requester_address == req_requester => true,
					_ => false,
				},
				move |event| match *event {
					crate::runtime::Event::secretstore_runtime_module(
						runtime_module::Event::DocumentKeyCommonRetrieved(
							req_id,
							req_requester,
							req_common_point,
							req_threshold,
						),
					) if req_id == id && requester_address == req_requester => {
						common_portion_retrieved = true;
						threshold = req_threshold;

						info!(
							target: "secretstore",
							"Common portion of document key has been retrieved: threshold = {}, common_point = {:?}",
							req_threshold,
							req_common_point,
						);
						false
					},
					crate::runtime::Event::secretstore_runtime_module(
						runtime_module::Event::DocumentKeyPersonalRetrieved(
							req_id,
							req_requester,
							req_decrypted_point,
							ref req_shadow,
						),
					) if
						common_portion_retrieved &&
						req_id == id &&
						requester_address == req_requester
					=> {
						let shadows = personal_portions
							.entry(req_decrypted_point)
							.or_insert_with(|| {
								info!(
									target: "secretstore",
									"Adding new personal entry candidate: {:?}",
									req_decrypted_point,
								);

								Vec::new()
							});

						shadows.push(req_shadow.clone());
						if shadows.len() == threshold as usize + 1 {
							info!(
								target: "secretstore",
								"Received last required shadow for personal entry: {:?}",
								req_decrypted_point,
							);
							info!(
								target: "secretstore",
								"Finals shadows list: {:?}",
								shadows,
							);

							true
						} else {
							info!(
								target: "secretstore",
								"Received shadow for personal entry: {:?}. {} More required",
								req_decrypted_point,
								threshold as usize + 1 - shadows.len(),
							);

							false
						}
					},
					crate::runtime::Event::secretstore_runtime_module(
						runtime_module::Event::DocumentKeyShadowRetrievalError(req_id, req_requester),
					) if req_id == id && requester_address == req_requester => {
						info!(
							target: "secretstore",
							"Document key shadow retrieval has failed",
						);
						true
					},
					_ => false,
				},
			).await
		},
	}
}

/// Process single generic transaction.
async fn process_generic_transaction(
	client: &Client,
	is_wait_mined: bool,
	is_wait_finalized: bool,
	is_wait_processed: bool,
	call: crate::runtime::SecretStoreCall,
	mut find_request: impl FnMut(&crate::runtime::Event) -> bool,
	mut find_response: impl FnMut(&crate::runtime::Event) -> bool,
) -> Result<(), String> {
	// transaction events stream now (sometimes) missing finality notifications even
	// in --dev mode. It also may miss finality notifications by design (when too many blocks
	// are finalized at once)
	// => we only use it to track Ready+Mined state
	let mut transaction_stream = client.submit_and_watch_transaction(
		crate::runtime::Call::SecretStore(call),
	).await.map_err(|err| format!("{:?}", err))?;
	let mut finalized_headers_stream = client.subscribe_finalized_heads()
		.await
		.map_err(|err| format!("{:?}", err))?;
	let mut best_headers_stream = client.subscribe_best_heads()
		.await
		.map_err(|err| format!("{:?}", err))?;

	// wait until transaction is in the Ready queue
	wait_accepted(&mut transaction_stream).await?;
	// wait until transaction is mined
	if is_wait_mined {
		wait_mined(
			&client,
			&mut transaction_stream,
			&mut find_request,
		).await?;
	}
	// wait until transaction block is finalized
	if is_wait_finalized {
		wait_finalized(
			&client,
			&mut finalized_headers_stream,
			&mut find_request,
		).await?;
	}
	// wait until request is processed
	if is_wait_processed {
		wait_processed(
			&client,
			&mut best_headers_stream,
			&mut find_response,
		).await?;
	}

	Ok(())
}

/// Wait until transaction is accepted to the pool.
async fn wait_accepted(
	stream: &mut jsonrpsee::client::Subscription<crate::runtime::TransactionStatus>,
) -> Result<(), String> {
	loop {
		let status = stream.next().await;
		//trace_transaction_status(&status);
		match status {
			crate::runtime::TransactionStatus::Ready => {
				info!(
					target: "secretstore",
					"Transaction has been accepted to Ready queue",
				);
				return Ok(());
			},
			crate::runtime::TransactionStatus::Usurped(_)
				| crate::runtime::TransactionStatus::Dropped
				| crate::runtime::TransactionStatus::Invalid
				=> return Err("Transaction has been dropped".into()),
			_ => (),
		}
	}
}

/// Wait until transaction is mined.
async fn wait_mined(
	client: &Client,
	stream: &mut jsonrpsee::client::Subscription<crate::runtime::TransactionStatus>,
	filter_event: &mut impl FnMut(&crate::runtime::Event) -> bool,
) -> Result<(), String> {
	loop {
		let status = stream.next().await;
		//trace_transaction_status(&status);
		match status {
			crate::runtime::TransactionStatus::InBlock(block_hash) => {
				match filter_block_events(client, block_hash, filter_event).await? {
					Some(_) => {
						info!(
							target: "secretstore",
							"Transaction is mined in block: {:?}",
							block_hash,
						);
						return Ok(());
					},
					None => return Err("Transaction block is missing required event (Invalid Call?)".into()),
				}
			},
			crate::runtime::TransactionStatus::Usurped(_)
				| crate::runtime::TransactionStatus::Dropped
				| crate::runtime::TransactionStatus::Invalid
				=> return Err("Transaction has been dropped".into()),
			_ => (),
		}
	}
}

/// Wait until transaction is finalized.
async fn wait_finalized(
	client: &Client,
	finalized_headers_stream: &mut jsonrpsee::client::Subscription<crate::runtime::Header>,
	filter_event: &mut impl FnMut(&crate::runtime::Event) -> bool,
) -> Result<(), String> {
	loop {
		let finalized_header = finalized_headers_stream.next().await;
		let finalized_header_hash = finalized_header.hash();
		match filter_block_events(client, finalized_header_hash, filter_event).await? {
			Some(_) => {
				info!(
					target: "secretstore",
					"Transaction block is finalized: {:?}",
					finalized_header_hash,
				);
				return Ok(());
			},
			None => (),
		}
	}
}

/// Wait until transaction is processed.
async fn wait_processed(
	client: &Client,
	best_headers_stream: &mut jsonrpsee::client::Subscription<crate::runtime::Header>,
	filter_event: &mut impl FnMut(&crate::runtime::Event) -> bool,
) -> Result<(), String> {
	loop {
		let best_header = best_headers_stream.next().await;
		let best_header_hash = best_header.hash();
		match filter_block_events(client, best_header_hash, filter_event).await? {
			Some(_) => return Ok(()),
			None => (),
		}
	}
}

/// Filter block events.
async fn filter_block_events(
	client: &Client,
	block_hash: crate::runtime::BlockHash,
	filter_event: &mut impl FnMut(&crate::runtime::Event) -> bool,
) -> Result<Option<()>, String>{
	let events = client
		.header_events(block_hash)
		.await
		.map_err(|err| format!("{:?}", err))?;
	for event in events {
		if filter_event(&event.event) {
			return Ok(Some(()));
		}
	}

	Ok(None)
}
