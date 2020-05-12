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
mod subcommands;
mod substrate_client;
mod transaction_pool;

use std::{
	io::Write,
	sync::Arc,
};
use futures::{FutureExt, TryFutureExt};
use log::error;
use parity_crypto::publickey::{Address, KeyPair, public_to_address};
use primitives::{
	executor::{TokioRuntime, tokio_runtime},
	key_server_set::{InMemoryKeyServerSet, KeyServerSet},
	key_server_key_pair::InMemoryKeyServerKeyPair,
};

/// Best block receiver.
pub trait BestBlockReceiver {
	/// Called when best block is updated.
	fn set_best_block(&self, number: crate::runtime::BlockNumber, hash: crate::runtime::BlockHash);
}

impl BestBlockReceiver for substrate_client::Client {
	fn set_best_block(&self, number: crate::runtime::BlockNumber, hash: crate::runtime::BlockHash) {
		substrate_client::Client::set_best_block(self, (number, hash))
	}
}

impl BestBlockReceiver for key_server_set::OnChainKeyServerSet {
	fn set_best_block(&self, number: crate::runtime::BlockNumber, hash: crate::runtime::BlockHash) {
		key_server_set::OnChainKeyServerSet::set_best_block(self, (number, hash))
	}
}

impl BestBlockReceiver for futures::channel::mpsc::UnboundedSender<runtime::BlockHash> {
	fn set_best_block(&self, _number: crate::runtime::BlockNumber, hash: crate::runtime::BlockHash) {
		if let Err(error) = self.unbounded_send(hash) {
			error!(
				target: "secretstore",
				"Failed to send finalized block: {:?}",
				error,
			);
		}
	}
}

fn main() {
	initialize();

	let yaml = clap::load_yaml!("cli.yml");
	let clap_app = clap::App::from_yaml(yaml);
	let matches = clap_app.get_matches();

	match matches.subcommand() {
		("generate-key-pair", Some(generate_key_pair_matches)) =>
			return subcommands::generate_key_pair::run(generate_key_pair_matches),
		("generate-document-key", Some(generate_document_key_matches)) =>
			return subcommands::generate_document_key::run(generate_document_key_matches),
		("encrypt-message", Some(encrypt_message_matches)) =>
			return subcommands::encrypt_message::run(encrypt_message_matches),
		("decrypt-message", Some(decrypt_message_matches)) =>
			return subcommands::decrypt_message::run(decrypt_message_matches),
		("shadow-decrypt-message", Some(shadow_decrypt_message_matches)) =>
			return subcommands::shadow_decrypt_message::run(shadow_decrypt_message_matches),
		("submit-transaction", Some(submit_transaction_matches)) =>
			return subcommands::submit_transaction::run(submit_transaction_matches),
		_ => (),
	}

	let arguments = match arguments::parse_arguments(&matches) {
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

	// start key server and services
	let (client, best_block_receivers) = start_key_server(
		arguments,
		&tokio_runtime,
	).await?;

	let mut fut_finalized_headers = client
		.subscribe_finalized_heads()
		.await
		.map_err(|err| format!("Failed to subscribe to finalized blocks: {:?}", err))?;

	loop {
		futures::select! {
			finalized_header = fut_finalized_headers.next().fuse() => {
				let finalized_block = (finalized_header.number, finalized_header.hash());
				// TODO: disable this when node is syncing (any side effects?)
				// (like: maybe always return false in AclStorage when we believe are syncing, ...)
				best_block_receivers.iter().for_each(|bbr| bbr.set_best_block(finalized_block.0, finalized_block.1));
/*				client.set_best_block(finalized_block);
				key_server_set.set_best_block(finalized_block);
				if let Err(error) = best_sender.unbounded_send(finalized_block.1) {
					error!(
						target: "secretstore",
						"Failed to send finalized block: {:?}",
						error,
					);
				}*/
			},
		}
	}
}

/// Start key server and blockchain service.
async fn start_key_server(
	arguments: arguments::Arguments,
	tokio_runtime: &TokioRuntime,
) -> Result<(substrate_client::Client, Vec<Arc<dyn BestBlockReceiver>>), String> {
	let mut best_block_receivers = Vec::with_capacity(3);

	// let's connect to Substrate node first
	let client = substrate_client::Client::new(
		&format!("ws://{}:{}", arguments.sub_host, arguments.sub_port),
		runtime::create_transaction_signer(
			&arguments.sub_signer,
			arguments.sub_signer_password.as_deref(),
		)?,
	).await.map_err(|error| format!("Failed to start substrate client: {:?}", error))?;

	// start key server
	let self_key_pair = KeyPair::from_secret(arguments.self_secret)
		.map_err(|error| format!("{}", error))?;
	let self_id = public_to_address(self_key_pair.public());
	let key_server_key_pair = Arc::new(InMemoryKeyServerKeyPair::new(self_key_pair));
	let acl_storage = Arc::new(acl_storage::OnChainAclStorage::new(client.clone()));
	let key_server_set = prepare_key_server_set(&mut best_block_receivers, &client, self_id, arguments.key_server_set_source)?;
	let key_storage = Arc::new(::key_server::db_key_storage::PersistentKeyStorage::new(
		&std::path::Path::new(&arguments.db_path),
	).map_err(|error| format!("{:?}", error))?);
	let key_server_config = ::key_server::ClusterConfiguration {
		admin_address: arguments.admin,
		auto_migrate_enabled: !arguments.disable_auto_migration,
	};
	let key_server = key_server::start(
		tokio_runtime.executor(),
		key_server_key_pair.clone(),
		arguments.net_port,
		key_server_config,
		key_storage.clone(),
		acl_storage.clone(),
		key_server_set.clone(),
	).map_err(|error| format!("{:?}", error))?;

	// start on-chain substrate service
	if arguments.enable_onchain_service {
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
			key_server.clone(),
			key_storage,
			key_server_key_pair,
			best_receiver,
		).map_err(|error| format!("{:?}", error))?;
	
		best_block_receivers.push(Arc::new(best_sender));
	}

	// start http service
	if arguments.enable_http_service {
		tokio_runtime.executor().spawn_std(
			http_service::start_service(
				arguments.http_service_interface,
				arguments.http_service_port,
				key_server,
				match arguments.http_service_cors.as_str() {
					"none" => Some(Vec::new()),
					"*" | "all" | "any" => None,
					_ => Some(
						arguments
							.http_service_cors
							.split(',')
							.map(Into::into)
							.collect(),
					),
				},
			).map(|err| log::error!(
				target: "secretstore",
				"HTTP service future failed: {:?}",
				err,
			))
			.boxed()
		);
	}

	best_block_receivers.push(Arc::new(client.clone()));

	Ok((client, best_block_receivers))
}

fn prepare_key_server_set(
	best_block_receivers: &mut Vec<Arc<dyn BestBlockReceiver>>,
	client: &substrate_client::Client,
	self_id: Address,
	key_server_set_source: arguments::KeyServerSetSource,
) -> Result<Arc<dyn KeyServerSet<NetworkAddress = std::net::SocketAddr>>, String> {
	Ok(match key_server_set_source {
		arguments::KeyServerSetSource::OnChain => {
			let key_server_set = Arc::new(key_server_set::OnChainKeyServerSet::new(
				client.clone(),
				self_id,
			)?);
			best_block_receivers.push(key_server_set.clone());
			key_server_set as Arc<dyn KeyServerSet<NetworkAddress = std::net::SocketAddr>>
		},
		arguments::KeyServerSetSource::Hardcoded(key_servers) => Arc::new(InMemoryKeyServerSet::new(
			true,
			self_id,
			key_servers
				.into_iter()
				.map(|(id, (host, port))| key_server_set::parse_socket_addr(format!("{}:{}", host, port).as_bytes().to_vec())
					.map(|addr| (id, addr))
				)
				.collect::<Result<_, _>>()?,
		)),
	})
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
