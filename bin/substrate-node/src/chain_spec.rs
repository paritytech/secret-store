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

use sp_core::{Pair, Public, sr25519};
use secretstore_runtime::{
	AccountId, AuraConfig, BalancesConfig, GenesisConfig, GrandpaConfig,
	SecretStoreConfig, SudoConfig, SystemConfig, WASM_BINARY, Signature
};
use sp_consensus_aura::sr25519::{AuthorityId as AuraId};
use sp_finality_grandpa::{AuthorityId as GrandpaId};
use sc_service;
use sp_runtime::traits::{Verify, IdentifyAccount};

/// Specialized `ChainSpec`. This is a specialization of the general Substrate ChainSpec type.
pub type ChainSpec = sc_service::GenericChainSpec<GenesisConfig>;

/// The chain specification option. This is expected to come in from the CLI and
/// is little more than one of a number of alternatives which can easily be converted
/// from a string (`--chain=...`) into a `ChainSpec`.
#[derive(Clone, Debug)]
pub enum Alternative {
	/// Whatever the current runtime is, with just Alice as an auth.
	Development,
}

/// Helper function to generate a crypto pair from seed
pub fn get_from_seed<TPublic: Public>(seed: &str) -> <TPublic::Pair as Pair>::Public {
	TPublic::Pair::from_string(&format!("//{}", seed), None)
		.expect("static values are valid; qed")
		.public()
}

type AccountPublic = <Signature as Verify>::Signer;

/// Helper function to generate an account ID from seed
pub fn get_account_id_from_seed<TPublic: Public>(seed: &str) -> AccountId where
	AccountPublic: From<<TPublic::Pair as Pair>::Public>
{
	AccountPublic::from(get_from_seed::<TPublic>(seed)).into_account()
}

/// Helper function to generate an authority key for Aura
pub fn get_authority_keys_from_seed(s: &str) -> (AuraId, GrandpaId) {
	(
		get_from_seed::<AuraId>(s),
		get_from_seed::<GrandpaId>(s),
	)
}

impl Alternative {
	/// Get an actual chain config from one of the alternatives.
	pub(crate) fn load(self) -> Result<ChainSpec, String> {
		Ok(match self {
			Alternative::Development => ChainSpec::from_genesis(
				"Development",
				"dev",
				|| testnet_genesis(
					vec![
						get_authority_keys_from_seed("Alice"),
					],
					get_account_id_from_seed::<sr25519::Public>("Alice"),
					vec![
						get_account_id_from_seed::<sr25519::Public>("Alice"),
						get_account_id_from_seed::<sr25519::Public>("Bob"),
						get_account_id_from_seed::<sr25519::Public>("Charlie"),
						get_account_id_from_seed::<sr25519::Public>("Dave"),
						get_account_id_from_seed::<sr25519::Public>("Alice//stash"),
						get_account_id_from_seed::<sr25519::Public>("Bob//stash"),
						get_account_id_from_seed::<sr25519::Public>("Charlie//stash"),
						get_account_id_from_seed::<sr25519::Public>("Dave//stash"),
					],
					true,
				),
				vec![],
				None,
				None,
				None,
				None
			),
		})
	}

	pub(crate) fn from(s: &str) -> Option<Self> {
		match s {
			"" | "dev" => Some(Alternative::Development),
			_ => None,
		}
	}
}

fn testnet_genesis(
	initial_authorities: Vec<(AuraId, GrandpaId)>,
	root_key: AccountId,
	endowed_accounts: Vec<AccountId>,
	_enable_println: bool,
) -> GenesisConfig {
	GenesisConfig {
		frame_system: Some(SystemConfig {
			code: WASM_BINARY.to_vec(),
			changes_trie_config: Default::default(),
		}),
		pallet_balances: Some(BalancesConfig {
			balances: endowed_accounts.iter().cloned().map(|k|(k, 1 << 60)).collect(),
		}),
		pallet_aura: Some(AuraConfig {
			authorities: initial_authorities.iter().map(|x| (x.0.clone())).collect(),
		}),
		pallet_grandpa: Some(GrandpaConfig {
			authorities: initial_authorities.iter().map(|x| (x.1.clone(), 1)).collect(),
		}),
		pallet_sudo: Some(SudoConfig {
			key: root_key,
		}),
		secretstore_runtime_module: Some(SecretStoreConfig {
			owner: get_account_id_from_seed::<sr25519::Public>("Alice"),
			is_initialization_completed: true,
			key_servers: vec![
				(
					"1a642f0e3c3af545e7acbd38b07251b3990914f1".parse().unwrap(),
					"127.0.0.1:10000".to_owned().into_bytes(),
				),
				(
					"5050a4f4b3f9338c3472dcc01a87c76a144b3c9c".parse().unwrap(),
					"127.0.0.1:10001".to_owned().into_bytes(),
				),
				(
					"3325a78425f17a7e487eb5666b2bfd93abb06c70".parse().unwrap(),
					"127.0.0.1:10002".to_owned().into_bytes(),
				),
			],
			claims: vec![
				(
					get_account_id_from_seed::<sr25519::Public>("Alice"),
					"1a642f0e3c3af545e7acbd38b07251b3990914f1".parse().unwrap(),
				),
				(
					get_account_id_from_seed::<sr25519::Public>("Bob"),
					"5050a4f4b3f9338c3472dcc01a87c76a144b3c9c".parse().unwrap(),
				),
				(
					get_account_id_from_seed::<sr25519::Public>("Charlie"),
					"3325a78425f17a7e487eb5666b2bfd93abb06c70".parse().unwrap(),
				),
				(
					get_account_id_from_seed::<sr25519::Public>("Dave"),
					"c48b812bb43401392c037381aca934f4069c0517".parse().unwrap(),
				),
			],
			server_key_generation_fee: 0,
			server_key_retrieval_fee: 0,
			document_key_store_fee: 0,
			document_key_shadow_retrieval_fee: 0,
		})
	}
}

pub fn load_spec(id: &str) -> Result<Box<dyn sc_service::ChainSpec>, String> {
	Ok(match Alternative::from(id) {
		Some(spec) => Box::new(spec.load()?),
		None => Box::new(ChainSpec::from_json_file(std::path::PathBuf::from(id))?),
	})
}
