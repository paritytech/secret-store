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

// TODO: key_Server.cluster().has_active_sessions() before starting SSchange session
// TODO: encrypt actual data using generated key and then decrypt using retrieved key

use std::{
	collections::BTreeSet,
	sync::Arc,
};
use log::trace;
use parity_crypto::publickey::{Address, Generator, KeyPair, Random, public_to_address, sign, verify_public};
use primitives::{
	acl_storage::InMemoryPermissiveAclStorage,
	executor::{tokio_runtime, TokioHandle},
	key_server::{AdminSessionsServer, DocumentKeyServer, MessageSigner, ServerKeyGenerator},
	key_server_key_pair::InMemoryKeyServerKeyPair,
	key_server_set::InMemoryKeyServerSet,
	key_storage::InMemoryKeyStorage,
	requester::Requester,
};
use crate::{
	ClusterConfiguration, KeyServerImpl,
	key_server_cluster::{
		math,
		jobs::servers_set_change_access_job::ordered_nodes_hash,
	},
};

/// Total number of key servers.
const TOTAL_KEY_SERVERS: usize = 6;
/// Number of key servers in initial set.
const INITIAL_KEY_SEVERS: usize = 5;

/// Admin secret key.
const ADMIN_SECRET: [u8; 32] = [100u8; 32];
/// Requester1 secret key.
const REQUESTER1_SECRET: [u8; 32] = [101u8; 32];

/// Key#1 threshold.
const KEY1_THRESHOLD: usize = 2;
/// Key#1 id.
const KEY1_ID: [u8; 32] = [1u8; 32];
/// Key#2 threshold.
const KEY2_THRESHOLD: usize = 3;
/// Key#2 id.
const KEY2_ID: [u8; 32] = [2u8; 32];

#[test]
fn integration_test_with_manual_servers_set_change_session() {
	let _ = ::env_logger::try_init();

	// create runtimes (we will use separate runtimes, because that is how
	// it'll work in real world)
	let mut client_runtime = tokio_runtime().unwrap();
	let key_servers_runtimes = (0..TOTAL_KEY_SERVERS)
		.map(|_| tokio_runtime().unwrap())
		.collect::<Vec<_>>();

	// generate key pair for every key server
	let key_servers_key_pairs = (0..TOTAL_KEY_SERVERS)
		.map(|index| KeyPair::from_secret_slice(&[1 + index as u8; 32]).unwrap())
		.collect::<Vec<_>>();

	// prepare key pairs that we're going to use
	let admin_key_pair = KeyPair::from_secret_slice(&ADMIN_SECRET).unwrap();
	let requester1_key_pair = KeyPair::from_secret_slice(&REQUESTER1_SECRET).unwrap();

	// create initial network (some key servers are isolated)
	trace!(target: "secretstore", "STARTING KEY SERVERS...");
	let key_server_sets = (0..TOTAL_KEY_SERVERS)
		.map(|index| Arc::new(InMemoryKeyServerSet::new(
			index >= INITIAL_KEY_SEVERS,
			key_servers_key_pairs
				.iter()
				.take(INITIAL_KEY_SEVERS)
				.enumerate()
				.map(|(index, kp)| (
					kp.address(),
					format!("127.0.0.1:{}", 10_000u16 + index as u16).parse().unwrap(),
				))
				.collect()
		)))
		.collect::<Vec<_>>();
	let key_servers = (0..TOTAL_KEY_SERVERS)
		.map(|index| start_key_server(
			key_servers_runtimes[index].executor(),
			Some(public_to_address(admin_key_pair.public())),
			index,
			key_server_sets[index].clone(),
			&key_servers_key_pairs,
		))
		.collect::<Vec<_>>();

	// wait until key servers are connected to each other
	trace!(target: "secretstore", "CONNECTING...");
	key_servers.iter().for_each(|ks| ks.cluster().connect());
	loop {
		if key_servers.iter().take(INITIAL_KEY_SEVERS).all(|ks| ks.cluster().is_fully_connected()) {
			break;
		}

		std::thread::sleep(std::time::Duration::from_millis(100));
	}

	// generate sk#1
	trace!(target: "secretstore", "GENERATING SK#1...");
	let requester1_signature = sign(requester1_key_pair.secret(), &KEY1_ID.into()).unwrap();
	let sk_generation_result = client_runtime.block_on_std(
		key_servers[0]
			.generate_key(
				None,
				KEY1_ID.into(),
				Requester::Signature(requester1_signature.clone()),
				KEY1_THRESHOLD,
			)
	);
	let server_key1 = sk_generation_result.result.unwrap().key;

	// retrieve sk#1
	trace!(target: "secretstore", "RETRIEVING SK#1...");
	let sk_retrieval_result = client_runtime.block_on_std(
		key_servers[0]
			.restore_key_public(
				None,
				KEY1_ID.into(),
				Some(Requester::Signature(requester1_signature)),
			)
	);
	assert_eq!(
		sk_retrieval_result.result.unwrap().key,
		server_key1,
	);

	// generate dk#2
	trace!(target: "secretstore", "GENERATING DK#2...");
	let requester1_signature = sign(requester1_key_pair.secret(), &KEY2_ID.into()).unwrap();
	let dk_generation_result = client_runtime.block_on_std(
		key_servers[0]
			.generate_document_key(
				None,
				KEY2_ID.into(),
				Requester::Signature(requester1_signature.clone()),
				KEY2_THRESHOLD,
			)
	);
	assert_eq!(
		dk_generation_result.result.map(drop),
		Ok(()),
	);

	// store dk#1
	trace!(target: "secretstore", "STORING DK#1...");
	let document_key_plain1 = Random.generate().public().clone();
	let encrypted_document_key1 = math::encrypt_secret(&document_key_plain1, &server_key1).unwrap();
	let requester1_signature = sign(requester1_key_pair.secret(), &KEY1_ID.into()).unwrap();
	let dk_store_result = client_runtime.block_on_std(
		key_servers[0]
			.store_document_key(
				None,
				KEY1_ID.into(),
				Requester::Signature(requester1_signature.clone()),
				encrypted_document_key1.common_point,
				encrypted_document_key1.encrypted_point,
			)
	);
	assert_eq!(
		dk_store_result.result.map(drop),
		Ok(()),
	);

	// retrieve dk#2
	trace!(target: "secretstore", "RETRIEVING DK#2...");
	let requester1_signature = sign(requester1_key_pair.secret(), &KEY2_ID.into()).unwrap();
	let dk_retrieval_result = client_runtime.block_on_std(
		key_servers[0]
			.restore_document_key(
				None,
				KEY2_ID.into(),
				Requester::Signature(requester1_signature.clone()),
			)
	);
	assert_eq!(
		dk_retrieval_result.result.map(drop),
		Ok(()),
	);

	// retrieve dk#1 shadow
	trace!(target: "secretstore", "RETRIEVING DK#1 SHADOW...");
	let requester1_signature = sign(requester1_key_pair.secret(), &KEY1_ID.into()).unwrap();
	let dk_shadow_retrieval_result = client_runtime.block_on_std(
		key_servers[0]
			.restore_document_key_shadow(
				None,
				KEY1_ID.into(),
				Requester::Signature(requester1_signature.clone()),
			)
	);
	assert_eq!(
		dk_shadow_retrieval_result.result.map(drop),
		Ok(()),
	);

	// Schnorr-sign using sk#1
	trace!(target: "secretstore", "SCHNORR-SIGNING USING SK#1...");
	let message_to_sign = *Random.generate().secret().clone();
	let schnorr_signing_result = client_runtime.block_on_std(
		key_servers[0]
			.sign_message_schnorr(
				None,
				KEY1_ID.into(),
				Requester::Signature(requester1_signature.clone()),
				message_to_sign,
			)
	);
	let schnorr_signature = schnorr_signing_result.result.unwrap();
	assert!(math::verify_schnorr_signature(
		&server_key1,
		&(schnorr_signature.signature_c.into(), schnorr_signature.signature_s.into()),
		&message_to_sign,
	).unwrap());

	// ECDSA-sign using sk#1
	trace!(target: "secretstore", "ECDSA-SIGNING USING SK#1...");
	let ecdsa_signing_result = client_runtime.block_on_std(
		key_servers[0]
			.sign_message_ecdsa(
				None,
				KEY1_ID.into(),
				Requester::Signature(requester1_signature.clone()),
				message_to_sign,
			)
	);
	let ecdsa_signature = ecdsa_signing_result.result.unwrap();
	assert!(verify_public(
		&server_key1,
		&ecdsa_signature.signature,
		&message_to_sign,
	).unwrap());

	// add remaining key servers
	trace!(target: "secretstore", "ADDING MORE KEY SERVERS...");
	for key_server_set in key_server_sets {
		for i in INITIAL_KEY_SEVERS..TOTAL_KEY_SERVERS {
			key_server_set.add_key_server(
				public_to_address(key_servers_key_pairs[i].public()),
				format!("127.0.0.1:{}", 10_000u16 + i as u16).parse().unwrap(),
			);
		}
		key_server_set.set_isolated(false);
	}

	// and wait until all key servers are connected
	trace!(target: "secretstore", "CONNECTING...");
	key_servers.iter().for_each(|ks| ks.cluster().connect());
	loop {
		if key_servers.iter().all(|ks| ks.cluster().is_fully_connected()) {
			break;
		}

		std::thread::sleep(std::time::Duration::from_millis(100));
	}
	
	// run change servers set change session
	// (mind that old_set is equal to new_set here, since we can't distinguish between
	// old connections and connections-with-additional-nodes with disabled auto-migration)
	trace!(target: "secretstore", "RUNNING SERVERS SET CHANGE SESSION...");
	let old_set = key_servers_key_pairs
		.iter()
		.map(|kp| public_to_address(kp.public()))
		.collect::<BTreeSet<_>>();
	let new_set = key_servers_key_pairs
		.iter()
		.map(|kp| public_to_address(kp.public()))
		.collect::<BTreeSet<_>>();
println!("=== SERVERS: {:?}", key_servers_key_pairs.iter().map(|kp| public_to_address(kp.public())).collect::<Vec<_>>());
	let old_set_admin_signature = sign(admin_key_pair.secret(), &ordered_nodes_hash(&old_set)).unwrap();
	let new_set_admin_signature = sign(admin_key_pair.secret(), &ordered_nodes_hash(&new_set)).unwrap();
	let change_servers_set_result = client_runtime.block_on_std(
		key_servers[0]
			.change_servers_set(
				None,
				old_set_admin_signature,
				new_set_admin_signature,
				new_set,
			)
	);
	assert_eq!(
		change_servers_set_result.result.map(drop),
		Ok(()),
	);

	// ensure that shares of sk#1 and sk#2 are on ks#4

	// remove ks#1

	// run change servers set change session

	// ensure that shares of sk#1 and sk#2 are on ks#4
}

/// Start single key server over TCP network.
fn start_key_server(
	executor: TokioHandle,
	admin_address: Option<Address>,
	key_server_index: usize,
	key_server_set: Arc<InMemoryKeyServerSet>,
	key_servers_key_pairs: &[KeyPair],
) -> Arc<KeyServerImpl> {
	let key_server_key_pair = Arc::new(InMemoryKeyServerKeyPair::new(
		key_servers_key_pairs[key_server_index].clone(),
	));
	let acl_storage = Arc::new(InMemoryPermissiveAclStorage::default());
	let key_storage = Arc::new(InMemoryKeyStorage::default());

	crate::Builder::new()
		.with_self_key_pair(key_server_key_pair)
		.with_acl_storage(acl_storage)
		.with_key_storage(key_storage)
		.with_config(ClusterConfiguration {
			admin_address,
			auto_migrate_enabled: false,
		})
		.build_for_tcp(
			executor,
			crate::network::tcp::NodeAddress {
				address: "127.0.0.1".into(),
				port: 10_000u16 + key_server_index as u16,
			},
			key_server_set,
		)
		.unwrap()
}
