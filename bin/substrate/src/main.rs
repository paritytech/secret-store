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

#![recursion_limit="256"]

mod acl_storage;
mod arguments;
mod blockchain;
mod key_server;
mod key_server_set;
mod runtime;
mod service;
mod substrate_client;
mod transaction_pool;

use std::{
	io::Write,
	sync::Arc,
};
use futures::{FutureExt, TryFutureExt};
use log::error;
use parity_crypto::publickey::{KeyPair, public_to_address};
use primitives::{
	executor::{TokioRuntime, tokio_runtime},
	key_server_key_pair::InMemoryKeyServerKeyPair,
};

fn main() {
	initialize();

	let arguments = match arguments::parse_arguments(None) {
		Ok(arguments) => arguments,
		Err(error) => {
			error!(
				target: "secretstore",
				"Failed to parse arguments: {:?}",
				error,
			);

			return;
		}
	};

	let _ = futures::executor::LocalPool::new()
		.run_until(
			run_key_server(arguments)
				.map_err(|error| {
					error!(
						target: "secretstore",
						"Failed to start: {:?}",
						error,
					);
				})
		);
}

/// Run key server ad blockchain service.
async fn run_key_server(arguments: arguments::Arguments) -> Result<(), String> {
	// we still need tokio 0.1 runtime to run SS :/
	let tokio_runtime = tokio_runtime()
		.map_err(|err| format!("Error creating tokio runtime: {}", err))?;
	// and since not everything in SS is async, we need an additional
	// futures executor that we'll use to run futures in sync functions
	let thread_pool = futures::executor::ThreadPool::new()
		.map_err(|err| format!("Error creating thread pool: {}", err))?;

	// start key server and services
	let (client, key_server_set, best_sender) = start_key_server(
		arguments,
		&tokio_runtime,
		thread_pool,
	).await?;

	let mut fut_finalized_headers = client.subscribe_finalized_heads().await
		.map_err(|err| format!("Failed to subscribe to finalized blocks: {:?}", err))?;

	loop {
		futures::select! {
			finalized_header = fut_finalized_headers.next().fuse() => {
				let finalized_block = (finalized_header.number, finalized_header.hash());
				client.set_best_block(finalized_block);
				key_server_set.set_best_block(finalized_block);
				if let Err(error) = best_sender.unbounded_send(finalized_block.1) {
					error!(
						target: "secretstore",
						"Failed to send finalized block: {:?}",
						error,
					);
				}
			},
		}
	}
}

/// Start key server and blockchain service.
async fn start_key_server(
	arguments: arguments::Arguments,
	tokio_runtime: &TokioRuntime,
	thread_pool: futures::executor::ThreadPool,
) -> Result<(
	substrate_client::Client,
	Arc<key_server_set::OnChainKeyServerSet>,
	futures::channel::mpsc::UnboundedSender<runtime::BlockHash>,
), String> {
	// let's connect to Substrate node first
	let client = substrate_client::Client::new(
		&format!("ws://{}:{}", arguments.sub_host, arguments.sub_port),
		runtime::create_transaction_signer(
			&arguments.sub_signer,
			arguments.sub_signer_password.as_deref(),
		)?,
	).await.map_err(|error| format!("Failed to start substrate client: {:?}", error))?;

	// TODO: use db key storage

	// start key server
	let self_key_pair = KeyPair::from_secret(arguments.self_secret)
		.map_err(|error| format!("{}", error))?;
	let self_id = public_to_address(self_key_pair.public());
	let key_server_key_pair = Arc::new(InMemoryKeyServerKeyPair::new(self_key_pair));
	let acl_storage = Arc::new(acl_storage::OnChainAclStorage::new(client.clone()));
	let key_server_set = Arc::new(key_server_set::OnChainKeyServerSet::new(
		client.clone(),
		self_id.clone(),
		thread_pool,
	));
	let (key_storage, key_server) = key_server::start(
		tokio_runtime.executor(),
		key_server_key_pair.clone(),
		arguments.net_port,
		acl_storage.clone(),
		key_server_set.clone(),
	).map_err(|error| format!("{:?}", error))?;

	// start substrate service
	let (best_sender, best_receiver) = futures::channel::mpsc::unbounded();
	let blockchain = Arc::new(
		blockchain::SecretStoreBlockchain::new(
			client.clone(),
			key_server_set.clone(),
		)
	);
	let transaction_pool = Arc::new(
		transaction_pool::SecretStoreTransactionPool::new(
			client.clone(),
		)
	);
	service::start(
		blockchain,
		transaction_pool,
		tokio_runtime.executor(),
		key_server,
		key_storage,
		key_server_key_pair,
		best_receiver,
	).map_err(|error| format!("{:?}", error))?;

	Ok((client, key_server_set, best_sender))
}

fn initialize() {
	let mut builder = env_logger::Builder::new();

	let filters = match std::env::var("RUST_LOG") {
		Ok(env_filters) => format!("secretstore=info,secretstore_net=info,{}", env_filters),
		Err(_) => "secretstore=info,secretstore_net=info".into(),
	};

	builder.parse_filters(&filters);
	builder.format(move |buf, record| {
		writeln!(buf, "{}", {
			let timestamp = time::strftime("%Y-%m-%d %H:%M:%S %Z", &time::now())
				.expect("Time is incorrectly formatted");
			if cfg!(windows) {
				format!("{} {} {} {}", timestamp, record.level(), record.target(), record.args())
			} else {
				use ansi_term::Colour as Color;
				let log_level = match record.level() {
					log::Level::Error => Color::Fixed(9).bold().paint(record.level().to_string()),
					log::Level::Warn => Color::Fixed(11).bold().paint(record.level().to_string()),
					log::Level::Info => Color::Fixed(10).paint(record.level().to_string()),
					log::Level::Debug => Color::Fixed(14).paint(record.level().to_string()),
					log::Level::Trace => Color::Fixed(12).paint(record.level().to_string()),
				};
				format!("{} {} {} {}"
					, Color::Fixed(8).bold().paint(timestamp)
					, log_level
					, Color::Fixed(8).paint(record.target())
					, record.args())
			}
		})
	});

	builder.init();
}
