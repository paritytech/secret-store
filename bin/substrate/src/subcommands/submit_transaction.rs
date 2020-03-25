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
use log::{error, info};
use primitives::ServerKeyId;
use crate::substrate_client::Client;

/// All possible SecretStore transactions we support.
pub enum SecretStoreTransaction {
/*	// === Meta calls ===

	/// Change owner.
	ChangeOwner(crate::runtime::AccountId),
	/// Claim id.
	ClaimId(Address),
	/// Claim key.
	ClaimKey(ServerKeyId),
	/// Transfer key ownership.
	TransferKey(ServerKeyId, Address),

	// === Key Server Set calls ===

	/// Complete key server set initialization.
	CompleteInitialization,
	/// Add key server to the set.
	AddKeyServer(KeyServerId, String, u16),
	/// Update key server from the set.
	UpdateKeyServer(KeyServerId, String, u16),
	/// Remove key server from the set.
	UpdateKeyServer(KeyServerId),

	// === Key Server calls ===
*/
	/// Generate server key.
	GenerateServerKey(ServerKeyId, u8),
/*	/// Retrieve server key.
	RetrieveServerKey(ServerKeyId),
	/// Store document key.
	StoreDocumentKey(ServerKeyId, Public, Public),
	/// Retrieve document key shadow.
	RetrieveDocumentKeyShadow(ServerKeyId, Public),*/
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
	let generate_server_key_regex = regex::Regex::new(r"GenerateServerKey\((.*),[ /t]*(.*)\)").expect("TODO");
	if let Some(captures) = generate_server_key_regex.captures(stransaction) {
		let key_id = ServerKeyId::from_str(captures.get(1).expect("TODO").as_str())
			.map_err(|err| format!("{}", err))?;
		let threshold = u8::from_str(captures.get(2).expect("TODO").as_str())
			.map_err(|err| format!("{}", err))?;
		return Ok(SecretStoreTransaction::GenerateServerKey(key_id, threshold));
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
	match transaction {
		SecretStoreTransaction::GenerateServerKey(id, threshold) => {
			// transaction events stream now (sometimes) missing finality notifications even
			// in --dev mode. It also may miss finality notifications by design (when too many blocks
			// are finalized at once)
			// => we only use it to track Ready+Mined state
			let mut transaction_stream = client.submit_and_watch_transaction(
				crate::runtime::Call::SecretStore(
					crate::runtime::SecretStoreCall::generate_server_key(id, threshold),
				),
			).await.map_err(|err| format!("{:?}", err))?;
			let mut finalized_headers_stream = client.subscribe_finalized_heads()
				.await
				.map_err(|err| format!("{:?}", err))?;
			let mut best_headers_stream = client.subscribe_best_heads()
				.await
				.map_err(|err| format!("{:?}", err))?;
			let find_request = |event: &crate::runtime::Event| match *event {
				crate::runtime::Event::secretstore_runtime_module(
					runtime_module::Event::ServerKeyGenerationRequested(gen_id, _, gen_threshold),
				) if gen_id == id && gen_threshold == threshold => true,
				_ => false,
			};

			// wait until transaction is in the Ready queue
			wait_accepted(&mut transaction_stream).await?;
			// wait until transaction is mined
			if is_wait_mined {
				wait_mined(
					&client,
					&mut transaction_stream,
					find_request,
				).await?;
			}
			// wait until transaction block is finalized
			if is_wait_finalized {
				wait_finalized(
					&client,
					&mut finalized_headers_stream,
					find_request,
				).await?;
			}
			// wait until request is processed
			if is_wait_processed {
				wait_processed(
					&client,
					&mut best_headers_stream,
					|event| match *event {
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
						_ => false,
					},
					|event| match *event {
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
				).await?;
			}

			Ok(())
		},
	}
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
	filter_event: impl Fn(&crate::runtime::Event) -> bool,
) -> Result<(), String> {
	loop {
		let status = stream.next().await;
		//trace_transaction_status(&status);
		match status {
			crate::runtime::TransactionStatus::InBlock(block_hash) => {
				match filter_block_events(client, block_hash, &filter_event, None).await? {
					Some(FilteredEvent::A) => {
						info!(
							target: "secretstore",
							"Transaction is mined in block: {:?}",
							block_hash,
						);
						return Ok(());
					},
					Some(FilteredEvent::B) => unreachable!(
						"FilteredEvent::B may only happen if we pass two filter functions; qed",
					),
					None => return Err("Transaction block is missing required event".into()),
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
	filter_event: impl Fn(&crate::runtime::Event) -> bool,
) -> Result<(), String> {
	loop {
		let finalized_header = finalized_headers_stream.next().await;
		let finalized_header_hash = finalized_header.hash();
		match filter_block_events(client, finalized_header_hash, &filter_event, None).await? {
			Some(FilteredEvent::A) => {
				info!(
					target: "secretstore",
					"Transaction block is finalized: {:?}",
					finalized_header_hash,
				);
				return Ok(());
			},
			Some(FilteredEvent::B) => unreachable!(
				"FilteredEvent::B may only happen if we pass two filter functions; qed",
			),
			None => (),
		}
	}
}

/// Wait until transaction is processed.
async fn wait_processed(
	client: &Client,
	best_headers_stream: &mut jsonrpsee::client::Subscription<crate::runtime::Header>,
	filter_successful_event: impl Fn(&crate::runtime::Event) -> bool,
	filter_failed_event: impl Fn(&crate::runtime::Event) -> bool,
) -> Result<(), String> {
	loop {
		let best_header = best_headers_stream.next().await;
		let best_header_hash = best_header.hash();
		match filter_block_events(
			client,
			best_header_hash,
			&filter_successful_event,
			Some(&filter_failed_event),
		).await? {
			Some(_) => return Ok(()),
			None => (),
		}
	}
}

/// Filter events result.
enum FilteredEvent { A, B }

/// Filter block events.
async fn filter_block_events(
	client: &Client,
	block_hash: crate::runtime::BlockHash,
	filter_event1: &dyn Fn(&crate::runtime::Event) -> bool,
	filter_event2: Option<&dyn Fn(&crate::runtime::Event) -> bool>
) -> Result<Option<FilteredEvent>, String>{
	let events = client
		.header_events(block_hash)
		.await
		.map_err(|err| format!("{:?}", err))?;
	for event in events {
		if filter_event1(&event.event) {
			return Ok(Some(FilteredEvent::A));
		}

		if let Some(filter_event2) = filter_event2 {
			if filter_event2(&event.event) {
				return Ok(Some(FilteredEvent::B));
			}
		}
	}

	Ok(None)
}
