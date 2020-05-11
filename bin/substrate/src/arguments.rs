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
use serde::Deserialize;
use parity_crypto::publickey::{Address, Secret};

/// Default program arguments.
/// Read either from CLI arguments, or from configuration file.
#[derive(Debug, PartialEq)]
pub struct Arguments {
	pub self_secret: Secret,
	pub db_path: String,
	pub net_host: String,
	pub net_port: u16,
	pub sub_host: String,
	pub sub_port: u16,
	pub sub_signer: String,
	pub sub_signer_password: Option<String>,
	pub key_server_set_source: KeyServerSetSource,
	pub disable_auto_migration: bool,
	pub admin: Option<Address>,
	pub enable_onchain_service: bool,
	pub enable_http_service: bool,
	pub http_service_interface: String,
	pub http_service_port: u16,
	pub http_service_cors: String,
}

/// Key server set source.
#[derive(Debug, PartialEq)]
pub enum KeyServerSetSource {
	/// Key server set is stored on-chain and read from Substrate node.
	OnChain,
	/// Key server set is hardcoded.
	Hardcoded(HashMap<Address, (String, u16)>),
}

/// Substrate-related arguments. Used by subcommands.
/// Read either from CLI arguments, or from configuration file.
#[derive(Debug, PartialEq)]
pub struct SubstrateArguments {
	pub sub_host: String,
	pub sub_port: u16,
	pub sub_signer: String,
	pub sub_signer_password: Option<String>,
}

/// Program arguments that may be stored in configuration file.
#[derive(Default, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TomlArguments {
	#[serde(default, rename = "self-secret", with = "opt_secret")]
	self_secret: Option<Secret>,
	#[serde(default, rename = "db-path")]
	db_path: Option<String>,
	#[serde(default, rename = "net-host")]
	net_host: Option<String>,
	#[serde(default, rename = "net-port")]
	net_port: Option<u16>,

	#[serde(default, rename = "sub-host")]
	sub_host: Option<String>,
	#[serde(default, rename = "sub-port")]
	sub_port: Option<u16>,
	#[serde(default, rename = "sub-signer")]
	sub_signer: Option<String>,
	#[serde(default, rename = "sub-signer-password")]
	sub_signer_password: Option<String>,

	#[serde(default, rename = "key-servers")]
	key_servers: Option<String>,
	#[serde(default, rename = "disable-auto-migration")]
	disable_auto_migration: Option<bool>,
	#[serde(default, rename = "admin")]
	admin: Option<String>,

	#[serde(default, rename = "on-chain-service")]
	enable_on_chain_service: Option<bool>,

	#[serde(default, rename = "http-service")]
	enable_http_service: Option<bool>,
	#[serde(default, rename = "http-service-interface")]
	http_service_interface: Option<String>,
	#[serde(default, rename = "http-service-port")]
	http_service_port: Option<u16>,
	#[serde(default, rename = "http-service-cors")]
	http_service_cors: Option<String>,
}

// we can't use `#[serde(with)]` on `Option<>` fields => we need custom deserializer
mod opt_secret {
	use parity_crypto::publickey::Secret;
	use serde::{Deserialize, Deserializer};

	pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Secret>, D::Error>
	where
		D: Deserializer<'de>,
	{
		#[derive(Deserialize)]
		struct Helper(#[serde(with = "serde_with::rust::display_fromstr")] Secret);

		let helper = Option::deserialize(deserializer)?;
		Ok(helper.map(|Helper(secret)| secret))
	}
}

/// Parse command line arguments.
pub fn parse_arguments<'a>(
	matches: &ArgMatches,
) -> Result<Arguments, String> {
	let substrate_arguments = parse_substrate_arguments(matches)?;
	let toml_arguments: TomlArguments = match matches.value_of("config") {
		Some(config_file_path) => std::fs::read_to_string(config_file_path)
			.map_err(|err| format!("{}", err))
			.and_then(|file_contents| toml::from_str(&file_contents)
				.map_err(|err| format!("{}", err))
			)?,
		None => Default::default(),
	};

	Ok(Arguments {
		self_secret: matches.value_of("self-secret")
			.map(|self_secret| Secret::from_str(self_secret)
				.map_err(|err| format!("Invalid 'self-secret' specified: {}", err))
			)
			.or_else(|| toml_arguments.self_secret.clone().map(Ok))
			.ok_or_else(|| String::from("Key server secret key must be specified"))??,
		db_path: matches.value_of("db-path")
			.map(str::to_owned)
			.or_else(|| toml_arguments.db_path.clone())
			.unwrap_or_else(|| "db".into()),
		net_host: matches.value_of("net-host")
			.map(str::to_owned)
			.or_else(|| toml_arguments.net_host.clone())
			.unwrap_or_else(|| "0.0.0.0".into()),
		net_port: matches.value_of("net-port")
			.map(|net_port| u16::from_str(net_port)
				.map_err(|err| format!("Invalid 'net-port' specified: {}", err))
			)
			.or_else(|| toml_arguments.net_port.clone().map(Ok))
			.unwrap_or_else(|| Ok(8083))?,

		sub_host: substrate_arguments.sub_host,
		sub_port: substrate_arguments.sub_port,
		sub_signer: substrate_arguments.sub_signer,
		sub_signer_password: substrate_arguments.sub_signer_password,
	
		key_server_set_source: matches.value_of("key-servers")
			.map(str::to_owned)
			.or_else(|| toml_arguments.key_servers.clone())
			.map(|key_servers| key_servers
				.split(',')
				.filter(|ks| !ks.is_empty())
				.map(|ks| {
					let address_and_net_address = ks.split('@').collect::<Vec<_>>();
					if address_and_net_address.len() != 2 {
						return Err(format!("Invalid 'key-servers' specified: {}", ks));
					}

					let net_ip_and_port = address_and_net_address[1].split(':').collect::<Vec<_>>();
					if net_ip_and_port.len() != 2 {
						return Err(format!("Invalid 'key-servers' specified: {}", ks));
					}

					let address = address_and_net_address[0]
						.parse()
						.map_err(|e| format!("Invalid address in 'key-servers': {} ({:?})", address_and_net_address[0], e))?;
					let port = net_ip_and_port[1]
						.parse()
						.map_err(|e| format!("Invalid port in 'key-servers': {} ({:?})", net_ip_and_port[1], e))?;

					Ok((address, (net_ip_and_port[0].into(), port)))
				})
				.collect::<Result<HashMap<_, _>, _>>()
				.map(KeyServerSetSource::Hardcoded)
			)
			.unwrap_or_else(|| Ok(KeyServerSetSource::OnChain))?,
		disable_auto_migration: matches.is_present("disable-auto-migration")
			|| toml_arguments.disable_auto_migration.unwrap_or(false),
		admin: matches.value_of("admin")
			.map(str::to_owned)
			.or_else(|| toml_arguments.admin.clone())
			.map(|admin| admin
				.parse()
				.map(Some)
				.map_err(|e| format!("Invalid 'admin' specified: {}", e))
			)
			.unwrap_or(Ok(None))?,

		enable_onchain_service: matches.is_present("on-chain-service")
			|| toml_arguments.enable_on_chain_service.unwrap_or(false),

		enable_http_service: matches.is_present("http-service")
			|| toml_arguments.enable_http_service.unwrap_or(false),
		http_service_interface: matches.value_of("http-service-interface")
			.map(str::to_owned)
			.or_else(|| toml_arguments.http_service_interface.clone())
			.unwrap_or_else(|| "localhost".into()),
		http_service_port: matches.value_of("http-service-port")
			.map(|http_service_port| u16::from_str(http_service_port)
				.map_err(|err| format!("Invalid 'http-service-port' specified: {}", err)))
			.or_else(|| toml_arguments.http_service_port.clone().map(Ok))
			.unwrap_or_else(|| Ok(8082))?,
		http_service_cors: matches.value_of("http-service-cors")
			.map(str::to_owned)
			.or_else(|| toml_arguments.http_service_cors.clone())
			.unwrap_or_else(|| "none".into()),
	})
}

/// Parse command line arguments.
pub fn parse_substrate_arguments<'a>(
	matches: &ArgMatches,
) -> Result<SubstrateArguments, String> {
	let toml_arguments: TomlArguments = match matches.value_of("config") {
		Some(config_file_path) => std::fs::read_to_string(config_file_path)
			.map_err(|err| format!("{}", err))
			.and_then(|file_contents| toml::from_str(&file_contents)
				.map_err(|err| format!("{}", err))
			)?,
		None => Default::default(),
	};

	Ok(SubstrateArguments {
		sub_host: matches.value_of("sub-host")
			.map(str::to_owned)
			.or_else(|| toml_arguments.sub_host.clone())
			.unwrap_or_else(|| "localhost".into()),
		sub_port: matches.value_of("sub-port")
			.map(|sub_port| u16::from_str(sub_port).map_err(|err| format!("{}", err)))
			.or_else(|| toml_arguments.sub_port.clone().map(Ok))
			.unwrap_or_else(|| Ok(9944))?,
		sub_signer: matches.value_of("sub-signer")
			.map(str::to_owned)
			.or_else(|| toml_arguments.sub_signer.clone())
			.unwrap_or_else(|| "//Alice".into()),
		sub_signer_password: matches.value_of("sub-signer-password")
			.map(str::to_owned)
			.or_else(|| toml_arguments.sub_signer_password.clone()),
	})
}

#[cfg(test)]
mod tests {
	use std::io::Write;
	use super::*;

	#[test]
	fn arguments_read_some_from_cli() {
		let yaml = clap::load_yaml!("cli.yml");
		let clap_app = clap::App::from_yaml(yaml);
		assert_eq!(
			parse_arguments(&clap_app.get_matches_from(vec![
				"parity-secretstore-substrate",
				"--on-chain-service",
				"--self-secret=0101010101010101010101010101010101010101010101010101010101010101",
				"--net-host=nethost.com",
				"--sub-port=4242",
				"--sub-signer=//Bob",
			])),
			Ok(Arguments {
				self_secret: Secret::from([1u8; 32]),
				db_path: "db".into(),
				net_host: "nethost.com".into(),
				net_port: 8083,
				sub_host: "localhost".into(),
				sub_port: 4242,
				sub_signer: "//Bob".into(),
				sub_signer_password: None,
				key_server_set_source: KeyServerSetSource::OnChain,
				disable_auto_migration: false,
				admin: None,
				enable_onchain_service: true,
				enable_http_service: false,
				http_service_interface: "localhost".into(),
				http_service_port: 8082,
				http_service_cors: "none".into(),
			}),
		);
	}

	#[test]
	fn arguments_read_full_from_cli() {
		let yaml = clap::load_yaml!("cli.yml");
		let clap_app = clap::App::from_yaml(yaml);
		assert_eq!(
			parse_arguments(&clap_app.get_matches_from(vec![
				"parity-secretstore-substrate",
				"--self-secret=0101010101010101010101010101010101010101010101010101010101010101",
				"--db-path=mydb",
				"--net-host=nethost.com",
				"--net-port=42",
				"--sub-host=subhost.com",
				"--sub-port=4242",
				"--sub-signer=//Bob",
				"--sub-signer-password=password",
				"--key-servers=0101010101010101010101010101010101010101@7.7.7.7:33,0202020202020202020202020202020202020202@8.8.8.8:44",
				"--admin=0303030303030303030303030303030303030303",
				"--on-chain-service",
				"--http-service",
				"--http-service-interface=9.9.9.9",
				"--http-service-port=55",
				"--http-service-cors=all",
			])),
			Ok(Arguments {
				self_secret: Secret::from([1u8; 32]),
				db_path: "mydb".into(),
				net_host: "nethost.com".into(),
				net_port: 42,
				sub_host: "subhost.com".into(),
				sub_port: 4242,
				sub_signer: "//Bob".into(),
				sub_signer_password: Some("password".into()),
				key_server_set_source: KeyServerSetSource::Hardcoded(vec![
					([1u8; 20].into(), ("7.7.7.7".into(), 33)),
					([2u8; 20].into(), ("8.8.8.8".into(), 44))
				].into_iter().collect()),
				disable_auto_migration: false,
				admin: Some([3u8; 20].into()),
				enable_onchain_service: true,
				enable_http_service: true,
				http_service_interface: "9.9.9.9".into(),
				http_service_port: 55,
				http_service_cors: "all".into(),
			}),
		);
	}

	#[test]
	fn arguments_read_some_from_file() {
		let yaml = clap::load_yaml!("cli.yml");
		let clap_app = clap::App::from_yaml(yaml);
		let temp_dir = tempdir::TempDir::new("arguments_read_from_file").unwrap();
		let temp_file_path = temp_dir.path().join("config.toml");
		std::fs::File::create(temp_file_path.clone()).unwrap().write_all(r#"
net-host = "nethost.com"
sub-port = 4242
sub-signer = "//Bob"
disable-auto-migration = true
admin = "0303030303030303030303030303030303030303"
http-service = true
		"#.as_bytes()).unwrap();

		assert_eq!(
			parse_arguments(&clap_app.get_matches_from(vec![
				"parity-secretstore-substrate",
				"--config",
				temp_file_path.to_str().unwrap(),
				"--self-secret",
				"0101010101010101010101010101010101010101010101010101010101010101",
			])),
			Ok(Arguments {
				self_secret: Secret::from([1u8; 32]),
				db_path: "db".into(),
				net_host: "nethost.com".into(),
				net_port: 8083,
				sub_host: "localhost".into(),
				sub_port: 4242,
				sub_signer: "//Bob".into(),
				sub_signer_password: None,
				key_server_set_source: KeyServerSetSource::OnChain,
				disable_auto_migration: true,
				admin: Some([3u8; 20].into()),
				enable_onchain_service: false,
				enable_http_service: true,
				http_service_interface: "localhost".into(),
				http_service_port: 8082,
				http_service_cors: "none".into(),
			}),
		);
	}

	#[test]
	fn arguments_read_full_from_file() {
		let yaml = clap::load_yaml!("cli.yml");
		let clap_app = clap::App::from_yaml(yaml);
		let temp_dir = tempdir::TempDir::new("arguments_read_from_file").unwrap();
		let temp_file_path = temp_dir.path().join("config.toml");
		std::fs::File::create(temp_file_path.clone()).unwrap().write_all(r#"
self-secret = "0101010101010101010101010101010101010101010101010101010101010101"
db-path = "mydb"
net-host = "nethost.com"
net-port = 42
sub-host = "subhost.com"
sub-port = 4242
sub-signer = "//Bob"
sub-signer-password = "password"
key-servers = "0101010101010101010101010101010101010101@7.7.7.7:33,0202020202020202020202020202020202020202@8.8.8.8:44"
admin = "0303030303030303030303030303030303030303"
on-chain-service = true
http-service = true
http-service-interface = "9.9.9.9"
http-service-port = 55
http-service-cors = "all"
		"#.as_bytes()).unwrap();

		assert_eq!(
			parse_arguments(&clap_app.get_matches_from(vec![
				"parity-secretstore-substrate",
				"--config",
				temp_file_path.to_str().unwrap(),
			])),
			Ok(Arguments {
				self_secret: Secret::from([1u8; 32]),
				db_path: "mydb".into(),
				net_host: "nethost.com".into(),
				net_port: 42,
				sub_host: "subhost.com".into(),
				sub_port: 4242,
				sub_signer: "//Bob".into(),
				sub_signer_password: Some("password".into()),
				key_server_set_source: KeyServerSetSource::Hardcoded(vec![
					([1u8; 20].into(), ("7.7.7.7".into(), 33)),
					([2u8; 20].into(), ("8.8.8.8".into(), 44))
				].into_iter().collect()),
				disable_auto_migration: false,
				admin: Some([3u8; 20].into()),
				enable_onchain_service: true,
				enable_http_service: true,
				http_service_interface: "9.9.9.9".into(),
				http_service_port: 55,
				http_service_cors: "all".into(),
			}),
		);
	}

	#[test]
	fn arguments_from_cli_overrides_arguments_from_file() {
		let yaml = clap::load_yaml!("cli.yml");
		let clap_app = clap::App::from_yaml(yaml);
		let temp_dir = tempdir::TempDir::new("arguments_read_from_file").unwrap();
		let temp_file_path = temp_dir.path().join("config.toml");
		std::fs::File::create(temp_file_path.clone()).unwrap().write_all(r#"
self-secret = "0202020202020202020202020202020202020202020202020202020202020202"
on-chain-service = false
http-service = false
		"#.as_bytes()).unwrap();

		assert_eq!(
			parse_arguments(&clap_app.get_matches_from(vec![
				"parity-secretstore-substrate",
				"--config",
				temp_file_path.to_str().unwrap(),
				"--self-secret=0101010101010101010101010101010101010101010101010101010101010101",
				"--on-chain-service",
				"--http-service",
			])),
			Ok(Arguments {
				self_secret: Secret::from([1u8; 32]),
				db_path: "db".into(),
				net_host: "0.0.0.0".into(),
				net_port: 8083,
				sub_host: "localhost".into(),
				sub_port: 9944,
				sub_signer: "//Alice".into(),
				sub_signer_password: None,
				key_server_set_source: KeyServerSetSource::OnChain,
				disable_auto_migration: false,
				admin: None,
				enable_onchain_service: true,
				enable_http_service: true,
				http_service_interface: "localhost".into(),
				http_service_port: 8082,
				http_service_cors: "none".into(),
			}),
		);
	}
}
