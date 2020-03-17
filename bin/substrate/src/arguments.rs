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
use serde::Deserialize;
use parity_crypto::publickey::Secret;

/// Program arguments. Read either from CLI arguments, or from configuration file
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
	args: Option<Vec<&'a str>>,
) -> Result<Arguments, String> {
	let yaml = clap::load_yaml!("cli.yml");
	let clap_app = clap::App::from_yaml(yaml);
	let matches = match args {
		Some(args) => clap_app.get_matches_from(args),
		None => clap_app.get_matches(),
	};

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
			.map(|self_secret| Secret::from_str(self_secret).map_err(|err| format!("{}", err)))
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
			.map(|net_port| u16::from_str(net_port).map_err(|err| format!("{}", err)))
			.or_else(|| toml_arguments.net_port.clone().map(Ok))
			.unwrap_or_else(|| Ok(8083))?,
		sub_host: matches.value_of("sub-host")
			.map(str::to_owned)
			.or_else(|| toml_arguments.sub_host.clone())
			.unwrap_or_else(|| "localhost".into()),
		sub_port: matches.value_of("sub-port")
			.map(|sub_port| u16::from_str(sub_port).map_err(|err| format!("{}", err)))
			.or_else(|| toml_arguments.sub_port.clone().map(Ok))
			.unwrap_or_else(|| Ok(9933))?,
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
		assert_eq!(
			parse_arguments(Some(vec![
				"parity-secretstore-substrate",
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
			}),
		);
	}

	#[test]
	fn arguments_read_full_from_cli() {
		assert_eq!(
			parse_arguments(Some(vec![
				"parity-secretstore-substrate",
				"--self-secret=0101010101010101010101010101010101010101010101010101010101010101",
				"--db-path=mydb",
				"--net-host=nethost.com",
				"--net-port=42",
				"--sub-host=subhost.com",
				"--sub-port=4242",
				"--sub-signer=//Bob",
				"--sub-signer-password=password",
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
			}),
		);
	}

	#[test]
	fn arguments_read_some_from_file() {
		let temp_dir = tempdir::TempDir::new("arguments_read_from_file").unwrap();
		let temp_file_path = temp_dir.path().join("config.toml");
		std::fs::File::create(temp_file_path.clone()).unwrap().write_all(r#"
net-host = "nethost.com"
sub-port = 4242
sub-signer = "//Bob"
		"#.as_bytes()).unwrap();

		assert_eq!(
			parse_arguments(Some(vec![
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
			}),
		);
	}

	#[test]
	fn arguments_read_full_from_file() {
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
		"#.as_bytes()).unwrap();

		assert_eq!(
			parse_arguments(Some(vec![
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
			}),
		);
	}

	#[test]
	fn arguments_from_cli_overrides_arguments_from_file() {
		let temp_dir = tempdir::TempDir::new("arguments_read_from_file").unwrap();
		let temp_file_path = temp_dir.path().join("config.toml");
		std::fs::File::create(temp_file_path.clone()).unwrap().write_all(r#"
self-secret = "0202020202020202020202020202020202020202020202020202020202020202"
		"#.as_bytes()).unwrap();

		assert_eq!(
			parse_arguments(Some(vec![
				"parity-secretstore-substrate",
				"--config",
				temp_file_path.to_str().unwrap(),
				"--self-secret=0101010101010101010101010101010101010101010101010101010101010101",
			])),
			Ok(Arguments {
				self_secret: Secret::from([1u8; 32]),
				db_path: "db".into(),
				net_host: "0.0.0.0".into(),
				net_port: 8083,
				sub_host: "localhost".into(),
				sub_port: 9933,
				sub_signer: "//Alice".into(),
				sub_signer_password: None,
			}),
		);
	}
}
