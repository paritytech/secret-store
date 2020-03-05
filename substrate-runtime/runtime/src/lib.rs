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

#![cfg_attr(not(feature = "std"), no_std)]

use sp_std::prelude::*;

mod blockchain_storage;
mod entity_id_storage;
mod document_key_shadow_retrieval;
mod document_key_store;
mod key_server_set;
mod key_server_set_storage;
mod mock;
mod server_key_generation;
mod server_key_retrieval;
mod service;

use frame_support::{StorageMap, traits::Currency, decl_module, decl_event, decl_storage, ensure};
use frame_system::{self as system, ensure_signed};
use ss_runtime_primitives::{
	EntityId,
	KeyServerId,
	ServerKeyId,
	KeyServersMask,
	key_server_set::{KeyServerSetSnapshot, KeyServerNetworkAddress, MigrationId as MigrationIdT},
};
use document_key_shadow_retrieval::{
	DocumentKeyShadowRetrievalRequest,
	DocumentKeyShadowRetrievalPersonalData,
	DocumentKeyShadowRetrievalService,
};
use document_key_store::{DocumentKeyStoreRequest, DocumentKeyStoreService};
use server_key_generation::{ServerKeyGenerationRequest, ServerKeyGenerationService};
use server_key_retrieval::{ServerKeyRetrievalRequest, ServerKeyRetrievalService};
use key_server_set_storage::KeyServer;

pub type BalanceOf<T> = <<T as Trait>::Currency as Currency<<T as frame_system::Trait>::AccountId>>::Balance;

/// The module configuration trait
pub trait Trait: frame_system::Trait {
	/// They overarching event type.
	type Event: From<Event> + Into<<Self as frame_system::Trait>::Event>;

	/// The currency type used for paying services.
	type Currency: Currency<Self::AccountId>;
}

decl_module! {
	pub struct Module<T: Trait> for enum Call where origin: T::Origin {
		fn deposit_event() = default;

		/// Claim given id.
		pub fn claim_id(origin, id: EntityId) {
			ensure!(
				!<ClaimedBy<T>>::exists(&id),
				"Id is already claimed",
			);

			let origin = ensure_signed(origin)?;
			ensure!(
				!<ClaimedId<T>>::exists(&origin),
				"Account has already claimed an id",
			);

			<ClaimedBy<T>>::insert(id, origin.clone());
			<ClaimedId<T>>::insert(origin, id);
		}

/*		/// Change key server set owner.
		pub fn change_owner(origin, new_owner: T::AccountId) {
			KeyServerSetWithMigration::<T>::change_owner(origin, new_owner)?;
		}*/

		/// Complete initialization.
		pub fn complete_initialization(origin) {
			key_server_set::<T>().complete_initialization(origin)?;
		}

		/// Add key server to the set.
		pub fn add_key_server(origin, id: KeyServerId, network_address: KeyServerNetworkAddress) {
			key_server_set::<T>().add_key_server(origin, id, network_address)?;
		}

		/// Update key server in the set.
		pub fn update_key_server(origin, id: KeyServerId, network_address: KeyServerNetworkAddress) {
			key_server_set::<T>().update_key_server(origin, id, network_address)?;
		}

		/// Remove key server from the set.
		pub fn remove_key_server(origin, id: KeyServerId) {
			key_server_set::<T>().remove_key_server(origin, id)?;
		}

		/// Start migration.
		pub fn start_migration(origin, migration_id: MigrationIdT) {
			key_server_set::<T>().start_migration(origin, migration_id)?;
		}

		/// Confirm migration.
		pub fn confirm_migration(origin, migration_id: MigrationIdT) {
			key_server_set::<T>().confirm_migration(origin, migration_id)?;
		}

		/// Generate server key.
		pub fn generate_server_key(origin, id: ServerKeyId, threshold: u8) {
			ServerKeyGenerationService::<T>::generate(origin, id, threshold)?;
		}

		/// Called when generation is reported by key server.
		pub fn server_key_generated(origin, id: ServerKeyId, server_key_public: sp_core::H512) {
			ServerKeyGenerationService::<T>::on_generated(origin, id, server_key_public)?;
		}

		/// Called when generation error is reported by key server.
		pub fn server_key_generation_error(origin, id: ServerKeyId) {
			ServerKeyGenerationService::<T>::on_generation_error(origin, id)?;
		}

		/// Retrieve server key.
		pub fn retrieve_server_key(origin, id: ServerKeyId) {
			ServerKeyRetrievalService::<T>::retrieve(origin, id)?;
		}

		/// Called when generation is reported by key server.
		pub fn server_key_retrieved(origin, id: ServerKeyId, server_key_public: sp_core::H512, threshold: u8) {
			ServerKeyRetrievalService::<T>::on_retrieved(origin, id, server_key_public, threshold)?;
		}

		/// Called when generation error is reported by key server.
		pub fn server_key_retrieval_error(origin, id: ServerKeyId) {
			ServerKeyRetrievalService::<T>::on_retrieval_error(origin, id)?;
		}

		/// Store document key.
		pub fn store_document_key(origin, id: ServerKeyId, common_point: sp_core::H512, encrypted_point: sp_core::H512) {
			DocumentKeyStoreService::<T>::store(origin, id, common_point, encrypted_point)?;
		}

		/// Called when store is reported by key server.
		pub fn document_key_stored(origin, id: ServerKeyId) {
			DocumentKeyStoreService::<T>::on_stored(origin, id)?;
		}

		/// Called when store error is reported by key server.
		pub fn document_key_store_error(origin, id: ServerKeyId) {
			DocumentKeyStoreService::<T>::on_store_error(origin, id)?;
		}

		/// Retrieve document key shadow.
		pub fn retrieve_document_key_shadow(origin, id: ServerKeyId, requester_public: sp_core::H512) {
			DocumentKeyShadowRetrievalService::<T>::retrieve(origin, id, requester_public)?;
		}

		/// Called when document key common part is reported by key server.
		pub fn document_key_common_retrieved(
			origin,
			id: ServerKeyId,
			requester: EntityId,
			common_point: sp_core::H512,
			threshold: u8,
		) {
			DocumentKeyShadowRetrievalService::<T>::on_common_retrieved(
				origin,
				id,
				requester,
				common_point,
				threshold,
			)?;
		}
		/// Called when document key personal part is reported by key server.
		pub fn document_key_personal_retrieved(
			origin,
			id: ServerKeyId,
			requester: EntityId,
			participants: KeyServersMask,
			decrypted_secret: sp_core::H512,
			shadow: Vec<u8>,
		) {
			DocumentKeyShadowRetrievalService::<T>::on_personal_retrieved(
				origin,
				id,
				requester,
				participants,
				decrypted_secret,
				shadow,
			)?;
		}

		/// Called when document key shadow retrieval error is reported by key server.
		pub fn document_key_shadow_retrieval_error(origin, id: ServerKeyId, requester: EntityId) {
			DocumentKeyShadowRetrievalService::<T>::on_retrieval_error(origin, id, requester)?;
		}


/*
		/// Allow key operations for given requester.
		pub fn grant_key_access(origin, key: ServerKeyId, requester: Address) {
			let origin = ensure_signed(origin)?;
			ensure!(
				<KeyAccessRights<T>>::exists(&key, &origin),
				"Access to key is denied",
			);

			<KeyAccessRights<T>>::insert(&key, &requester, &());
		}

		/// Deny key operations for given requester.
		pub fn deny_key_access(origin, key: ServerKeyId, requester: Address) {
			let origin = ensure_signed(origin)?;
			ensure!(
				<KeyAccessRights<T>>::exists(&key, &origin),
				"Access to key is denied",
			);

			<KeyAccessRights<T>>::remove(&key, &requester, &());
		}

		/// Set requesters who are allowed to perform operations with given key.
		pub fn change_key_access(origin, key: ServerKeyId, requesters: Vec<Address>) {
			let origin = ensure_signed(origin)?;
			ensure!(
				<KeyAccessRights<T>>::exists(&key, &origin),
				"Access to key is denied",
			);

			<KeyAccessRights<T>>::remove_prefix(&key);
			requesters.for_each(|requester| <KeyAccessRights<T>>::insert(&key, &requester, &()));
		}
*/
	}
}

//<T> where <T as frame_system::Trait>::AccountId
decl_event!(
	pub enum Event {
		/// Key server set: key server added to the new set.
		KeyServerAdded(KeyServerId),
		/// Key server set: key server added to the new set.
		KeyServerRemoved(KeyServerId),
		/// Key server set: key server address has been updated.
		KeyServerUpdated(KeyServerId),
		/// Key server set: migration has started.
		MigrationStarted,
		/// Key server set: migration has completed.
		MigrationCompleted,

		/// 
		ServerKeyGenerationRequested(ServerKeyId, EntityId, u8),
		///
		ServerKeyGenerated(ServerKeyId, sp_core::H512),
		///
		ServerKeyGenerationError(ServerKeyId),

		/// 
		ServerKeyRetrievalRequested(ServerKeyId),
		///
		ServerKeyRetrieved(ServerKeyId, sp_core::H512),
		///
		ServerKeyRetrievalError(ServerKeyId),

		///
		DocumentKeyStoreRequested(ServerKeyId, EntityId, sp_core::H512, sp_core::H512),
		///
		DocumentKeyStored(ServerKeyId),
		///
		DocumentKeyStoreError(ServerKeyId),

		/// TODO: needs to be verified by the key server
		DocumentKeyShadowRetrievalRequested(ServerKeyId, EntityId),
		///
		DocumentKeyCommonRetrieved(ServerKeyId, EntityId, sp_core::H512, u8),
		///
		DocumentKeyPersonalRetrievalRequested(ServerKeyId, sp_core::H512),
		///
		DocumentKeyShadowRetrievalError(ServerKeyId, EntityId),
		///
		DocumentKeyPersonalRetrieved(ServerKeyId, EntityId, sp_core::H512, Vec<u8>),
	}
);

decl_storage! {
	trait Store for Module<T: Trait> as SecretStore {
		pub Owner get(owner) config(): T::AccountId;
		ClaimedId get(claimed_address): map T::AccountId => Option<EntityId>;
		ClaimedBy get(claimed_by): map EntityId => Option<T::AccountId>;

		IsInitialized: bool;
		CurrentSetChangeBlock: <T as frame_system::Trait>::BlockNumber;

		CurrentKeyServers: linked_map KeyServerId => Option<KeyServer>;
		MigrationKeyServers: linked_map KeyServerId => Option<KeyServer>;
		NewKeyServers: linked_map KeyServerId => Option<KeyServer>;
		MigrationId: Option<(MigrationIdT, KeyServerId)>;
		MigrationConfirmations: map KeyServerId => ();

		pub ServerKeyGenerationFee get(server_key_generation_fee) config(): BalanceOf<T>;
		ServerKeyGenerationRequestsKeys: Vec<ServerKeyId>;
		ServerKeyGenerationRequests: map ServerKeyId
			=> Option<ServerKeyGenerationRequest<<T as frame_system::Trait>::BlockNumber>>;
		ServerKeyGenerationResponses: double_map ServerKeyId, twox_128(sp_core::H512) => u8;

		pub ServerKeyRetrievalFee get(server_key_retrieval_fee) config(): BalanceOf<T>;
		ServerKeyRetrievalRequestsKeys: Vec<ServerKeyId>;
		ServerKeyRetrievalRequests: map ServerKeyId
			=> Option<ServerKeyRetrievalRequest<<T as frame_system::Trait>::BlockNumber>>;
		ServerKeyRetrievalResponses: double_map ServerKeyId, twox_128(sp_core::H512) => u8;
		ServerKeyRetrievalThresholdResponses: double_map ServerKeyId, twox_128(u8) => u8;

		pub DocumentKeyStoreFee get(document_key_store_fee) config(): BalanceOf<T>;
		DocumentKeyStoreRequestsKeys: Vec<ServerKeyId>;
		DocumentKeyStoreRequests: map ServerKeyId
			=> Option<DocumentKeyStoreRequest<<T as frame_system::Trait>::BlockNumber>>;
		DocumentKeyStoreResponses: double_map ServerKeyId, twox_128(()) => u8;

		pub DocumentKeyShadowRetrievalFee get(document_key_shadow_retrieval_fee) config(): BalanceOf<T>;
		DocumentKeyShadowRetrievalRequestsKeys: Vec<(ServerKeyId, EntityId)>;
		DocumentKeyShadowRetrievalRequests: map (ServerKeyId, EntityId)
			=> Option<DocumentKeyShadowRetrievalRequest<<T as frame_system::Trait>::BlockNumber>>;
		DocumentKeyShadowRetrievalCommonResponses:
			double_map (ServerKeyId, EntityId),
			twox_128((sp_core::H512, u8)) => u8;
		DocumentKeyShadowRetrievalPersonalResponses:
			double_map (ServerKeyId, EntityId),
			twox_128((KeyServersMask, sp_core::H512)) => DocumentKeyShadowRetrievalPersonalData;
	}
	add_extra_genesis {
		config(is_initialization_completed): bool;
		config(key_servers): Vec<(KeyServerId, KeyServerNetworkAddress)>;
		config(claims): Vec<(T::AccountId, EntityId)>;
		build(|config| {
			key_server_set::<T>()
				.fill(
					&config.key_servers,
					config.is_initialization_completed,
				).expect("invalid key servers set in configuration");

			let mut claimed_by_accounts = std::collections::BTreeSet::new();
			let mut claimed_entities = std::collections::BTreeSet::new();
			for (account_id, entity_id) in &config.claims {
				if !claimed_by_accounts.insert(account_id.clone()) {
					panic!("Account has already claimed EntityId");
				}
				if !claimed_entities.insert(*entity_id) {
					panic!("EntityId already claimed");
				}

				ClaimedId::<T>::insert(account_id.clone(), *entity_id);
				ClaimedBy::<T>::insert(*entity_id, account_id.clone());
			}
		})
	}
}

impl<T: Trait> Module<T> {
	/// Get snapshot of key servers set state.
	pub fn key_server_set_snapshot(key_server: KeyServerId) -> KeyServerSetSnapshot {
		key_server_set::<T>().snapshot(key_server)
	}

	/// Get current key servers with indices.
	pub fn key_server_set_with_indices() -> Vec<(KeyServerId, u8)> {
		key_server_set::<T>().current_set_with_indices()
	}

	///
	pub fn server_key_generation_tasks(begin: u32, end: u32) -> Vec<ss_runtime_primitives::service::ServiceTask> {
		ServerKeyGenerationRequestsKeys::get()
			.into_iter()
			.skip(begin as usize)
			.take(end.saturating_sub(begin) as usize)
			.map(|key_id| {
				let request = ServerKeyGenerationRequests::<T>::get(&key_id)
					.expect("every key from ServerKeyGenerationRequestsKeys has corresponding
						entry in ServerKeyGenerationRequests; qed");
				ss_runtime_primitives::service::ServiceTask::GenerateServerKey(
					key_id,
					request.author,
					request.threshold,
				)
			})
			.collect()
	}

	///
	pub fn is_server_key_generation_response_required(key_server: KeyServerId, key_id: ServerKeyId) -> bool {
		ServerKeyGenerationService::<T>::is_response_required(key_server, key_id)
	}

	///
	pub fn server_key_retrieval_tasks(begin: u32, end: u32) -> Vec<ss_runtime_primitives::service::ServiceTask> {
		ServerKeyRetrievalRequestsKeys::get()
			.into_iter()
			.skip(begin as usize)
			.take(end.saturating_sub(begin) as usize)
			.map(|key_id| {
				ss_runtime_primitives::service::ServiceTask::RetrieveServerKey(
					key_id,
				)
			})
			.collect()
	}

	///
	pub fn is_server_key_retrieval_response_required(key_server: KeyServerId, key_id: ServerKeyId) -> bool {
		ServerKeyRetrievalService::<T>::is_response_required(key_server, key_id)
	}

	///
	pub fn document_key_store_tasks(begin: u32, end: u32) -> Vec<ss_runtime_primitives::service::ServiceTask> {
		DocumentKeyStoreRequestsKeys::get()
			.into_iter()
			.skip(begin as usize)
			.take(end.saturating_sub(begin) as usize)
			.map(|key_id| {
				let request = DocumentKeyStoreRequests::<T>::get(&key_id)
					.expect("every key from DocumentKeyStoreRequestsKeys has corresponding
						entry in DocumentKeyStoreRequests; qed");
				ss_runtime_primitives::service::ServiceTask::StoreDocumentKey(
					key_id,
					request.author,
					request.common_point,
					request.encrypted_point,
				)
			})
			.collect()
	}

	///
	pub fn is_document_key_store_response_required(key_server: KeyServerId, key_id: ServerKeyId) -> bool {
		DocumentKeyStoreService::<T>::is_response_required(key_server, key_id)
	}

	///
	pub fn document_key_shadow_retrieval_tasks(begin: u32, end: u32) -> Vec<ss_runtime_primitives::service::ServiceTask> {
		DocumentKeyShadowRetrievalRequestsKeys::get()
			.into_iter()
			.skip(begin as usize)
			.take(end.saturating_sub(begin) as usize)
			.map(|(key_id, requester)| {
				let request = DocumentKeyShadowRetrievalRequests::<T>::get(&(key_id, requester))
					.expect("every key from DocumentKeyStoreRequestsKeys has corresponding
						entry in DocumentKeyStoreRequests; qed");
				match request.threshold.is_some() {
					true => ss_runtime_primitives::service::ServiceTask::RetrieveShadowDocumentKeyCommon(
						key_id,
						requester,
					),
					false => ss_runtime_primitives::service::ServiceTask::RetrieveShadowDocumentKeyPersonal(
						key_id,
						request.requester_public,
					),
				}
			})
			.collect()
	}

	///
	pub fn is_document_key_shadow_retrieval_response_required(key_server: KeyServerId, key_id: ServerKeyId, requester: EntityId) -> bool {
		DocumentKeyShadowRetrievalService::<T>::is_response_required(key_server, key_id, requester)
	}
}


pub(crate) type KeyServerSet<T> = key_server_set::KeyServerSetWithMigration<
	blockchain_storage::RuntimeStorage<T>,
	entity_id_storage::RuntimeStorage<T>,
	key_server_set_storage::RuntimeStorageWithMigration<T>,
>;

pub(crate) fn key_server_set<T: Trait>() -> KeyServerSet<T> {
	key_server_set::KeyServerSetWithMigration::with_storage(Default::default(), Default::default(), Default::default())
}

pub fn resolve_entity_id<T: Trait>(origin: &T::AccountId) -> Result<EntityId, &'static str> {
	let origin_id = ClaimedId::<T>::get(origin);
	match origin_id {
		Some(id) => Ok(id),
		None => Err("No associated id for this account"),
	}
}