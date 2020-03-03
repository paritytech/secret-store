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

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use ethereum_types::{Address, H160, H256};
use parity_crypto::publickey::{Public, Signature};
use crate::{
	KeyServerId, KeyServerPublic, ServerKeyId,
	error::Error,
	requester::Requester,
};

/// Expose AccumulatingKeyServer if requested.
pub use self::accumulating_key_server::*;

/// Session origin. Origin can be used by some services if they're working with
/// several endpoints (like ethereum service could listen to several contracts).
pub type Origin = H160;

/// Session result.
pub struct SessionResult<P, R> {
	/// Session origin.
	pub origin: Option<Origin>,
	/// Session parameters.
	pub params: P,
	/// Actual result.
	pub result: Result<R, Error>,
}

/// Essential server key generation params.
#[derive(Clone)]
pub struct ServerKeyGenerationParams {
	/// Key id.
	pub key_id: ServerKeyId,
}

/// Server key generation artifacts.
#[derive(Clone)]
pub struct ServerKeyGenerationArtifacts {
	/// Public portion of generated server key.
	pub key: Public,
}

/// Result of server key generation session.
pub type ServerKeyGenerationResult = SessionResult<ServerKeyGenerationParams, ServerKeyGenerationArtifacts>;

/// Essential server key retrieval params.
#[derive(Clone)]
pub struct ServerKeyRetrievalParams {
	/// Key id.
	pub key_id: ServerKeyId,
}

/// Server key retrieval artifacts.
#[derive(Clone)]
pub struct ServerKeyRetrievalArtifacts {
	/// Server key author.
	pub author: Address,
	/// Public portion of retrieved server key.
	pub key: Public,
	/// Threshold that has been used to generate server key.
	pub threshold: usize,
}

/// Result of server key retrieval session.
pub type ServerKeyRetrievalResult = SessionResult<ServerKeyRetrievalParams, ServerKeyRetrievalArtifacts>;

/// Server key (SK) generator.
pub trait ServerKeyGenerator {
	/// SK generation future.
	type GenerateKeyFuture: Future<Output = ServerKeyGenerationResult> + Send;
	/// SK restore future.
	type RestoreKeyFuture: Future<Output = ServerKeyRetrievalResult> + Send;

	/// Generate new SK.
	/// `key_id` is the caller-provided identifier of generated SK.
	/// `author` is the author of key entry.
	/// `threshold + 1` is the minimal number of nodes, required to restore private key.
	/// Result is a public portion of SK.
	fn generate_key(
		&self,
		origin: Option<Origin>,
		key_id: ServerKeyId,
		author: Requester,
		threshold: usize,
	) -> Self::GenerateKeyFuture;
	/// Retrieve public portion of previously generated SK.
	/// `key_id` is identifier of previously generated SK.
	/// `author` is the same author, that has created the server key.
	/// If `author` is `None`, then author-check is omitted.
	fn restore_key_public(
		&self,
		origin: Option<Origin>,
		key_id: ServerKeyId,
		author: Option<Requester>,
	) -> Self::RestoreKeyFuture;
}

/// Essential document key store params.
#[derive(Clone)]
pub struct DocumentKeyStoreParams {
	/// Key id.
	pub key_id: ServerKeyId,
}

/// Document key store artifacts.
#[derive(Clone)]
pub struct DocumentKeyStoreArtifacts;

/// Result of document key store session.
pub type DocumentKeyStoreResult = SessionResult<DocumentKeyStoreParams, DocumentKeyStoreArtifacts>;

/// Essential document key generation params.
#[derive(Clone)]
pub struct DocumentKeyGenerationParams {
	/// Key id.
	pub key_id: ServerKeyId,
}

/// Dcument key generation artifacts.
#[derive(Clone)]
pub struct DocumentKeyGenerationArtifacts {
	/// Generated document key. UNENCRYPTED.
	pub document_key: Public,
}

/// Result of document key generation session.
pub type DocumentKeyGenerationResult = SessionResult<DocumentKeyGenerationParams, DocumentKeyGenerationArtifacts>;

/// Essential document key retrieval params.
#[derive(Clone)]
pub struct DocumentKeyRetrievalParams {
	/// Key id.
	pub key_id: ServerKeyId,
	/// Key requester.
	pub requester: Requester,
}

/// Document key retrieval artifacts.
#[derive(Clone)]
pub struct DocumentKeyRetrievalArtifacts {
	/// Restored document key. UNENCRYPTED.
	pub document_key: Public,
}

/// Result of document key retrieval session.
pub type DocumentKeyRetrievalResult = SessionResult<DocumentKeyRetrievalParams, DocumentKeyRetrievalArtifacts>;

/// Essential document key common retrieval params.
#[derive(Clone)]
pub struct DocumentKeyCommonRetrievalParams {
	/// Key id.
	pub key_id: ServerKeyId,
	/// Key requester.
	pub requester: Requester,
}

/// Document key common retrieval artifacts.
///
/// This data isn't enough to recover document key and could only be used for
/// establishing consensus over `common_point` and `threshold`.
#[derive(Clone)]
pub struct DocumentKeyCommonRetrievalArtifacts {
	/// The common point of portion of encrypted document keys. Common point is
	/// shared among all key servers that aware of the given document key.
	pub common_point: Public,
	/// Threshold that has been used to generate associated server key.
	pub threshold: usize,
}

/// Result of document key common retrieval session.
pub type DocumentKeyCommonRetrievalResult = SessionResult<
	DocumentKeyCommonRetrievalParams,
	DocumentKeyCommonRetrievalArtifacts,
>;

/// Essential document key shadow retrieval params.
#[derive(Clone)]
pub struct DocumentKeyShadowRetrievalParams {
	/// Key id.
	pub key_id: ServerKeyId,
	/// Key requester.
	pub requester: Requester,
}

/// Document key shadow retrieval artifacts.
///
/// The data is enough to decrypt document key by the owner of corresponding
/// requester key.
#[derive(Clone)]
pub struct DocumentKeyShadowRetrievalArtifacts {
	/// The common point of portion of encrypted document keys. Common point is
	/// shared among all key servers that aware of the given document key.
	pub common_point: Public,
	/// Threshold that has been used to generate associated server key.
	pub threshold: usize,
	/// Partially decrypted document key.
	pub encrypted_document_key: Public,
	/// Key servers that has participated in decryption session along with their
	/// shadow coefficients. Shadow coefficients are encrypted with requester public
	/// key. After decryption, they can be used to finally decrypt document key.
	pub participants_coefficients: BTreeMap<KeyServerId, Vec<u8>>,
}

/// Result of document key shadow retrieval session.
pub type DocumentKeyShadowRetrievalResult = SessionResult<
	DocumentKeyShadowRetrievalParams,
	DocumentKeyShadowRetrievalArtifacts,
>;

/// Document key (DK) server.
pub trait DocumentKeyServer: ServerKeyGenerator {
	/// DK store future.
	type StoreDocumentKeyFuture: Future<Output = DocumentKeyStoreResult> + Send;
	/// DK generation future.
	type GenerateDocumentKeyFuture: Future<Output = DocumentKeyGenerationResult> + Send;
	/// DK restore future.
	type RestoreDocumentKeyFuture: Future<Output = DocumentKeyRetrievalResult> + Send;
	/// DK common part restore future.
	type RestoreDocumentKeyCommonFuture: Future<Output = DocumentKeyCommonRetrievalResult> + Send;
	/// DK shadow restore future.
	type RestoreDocumentKeyShadowFuture: Future<Output = DocumentKeyShadowRetrievalResult> + Send;

	/// Store externally generated DK.
	/// `key_id` is identifier of previously generated SK.
	/// `author` is the same author, that has created the server key.
	/// `common_point` is a result of `k * T` expression, where `T` is generation point
	/// and `k` is random scalar in EC field.
	/// `encrypted_document_key` is a result of `M + k * y` expression, where `M` is unencrypted document key (point on EC),
	///   `k` is the same scalar used in `common_point` calculation and `y` is previously generated public part of SK.
	fn store_document_key(
		&self,
		origin: Option<Origin>,
		key_id: ServerKeyId,
		author: Requester,
		common_point: Public,
		encrypted_document_key: Public,
	) -> Self::StoreDocumentKeyFuture;
	/// Generate and store both SK and DK. This is a shortcut for consequent calls of `generate_key` and `store_document_key`.
	/// The only difference is that DK is generated by DocumentKeyServer (which might be considered unsafe).
	/// `key_id` is the caller-provided identifier of generated SK.
	/// `author` is the author of server && document key entry.
	/// `threshold + 1` is the minimal number of nodes, required to restore private key.
	/// Result is a DK, encrypted with caller public key.
	fn generate_document_key(
		&self,
		origin: Option<Origin>,
		key_id: ServerKeyId,
		author: Requester,
		threshold: usize,
	) -> Self::GenerateDocumentKeyFuture;
	/// Restore previously stored DK.
	/// DK is decrypted on the key server (which might be considered unsafe), and then encrypted with caller public key.
	/// `key_id` is identifier of previously generated SK.
	/// `requester` is the one who requests access to document key. Caller must be on ACL for this function to succeed.
	/// Result is a DK, encrypted with caller public key.
	fn restore_document_key(
		&self,
		origin: Option<Origin>,
		key_id: ServerKeyId,
		requester: Requester,
	) -> Self::RestoreDocumentKeyFuture;
	/// Restore portion of DK that is the same among all key servers.
	fn restore_document_key_common(
		&self,
		origin: Option<Origin>,
		key_id: ServerKeyId,
		requester: Requester,
	) -> Self::RestoreDocumentKeyCommonFuture;
	/// Restore previously stored DK.
	/// To decrypt DK on client:
	/// 1) use requestor secret key to decrypt secret coefficients from result.decrypt_shadows
	/// 2) calculate decrypt_shadows_sum = sum of all secrets from (1)
	/// 3) calculate decrypt_shadow_point: decrypt_shadows_sum * result.common_point
	/// 4) calculate decrypted_secret: result.decrypted_secret + decrypt_shadow_point
	/// Result is a DK shadow.
	fn restore_document_key_shadow(
		&self,
		origin: Option<Origin>,
		key_id: ServerKeyId,
		requester: Requester,
	) -> Self::RestoreDocumentKeyShadowFuture;
}

/// Essential Schnorr signing params.
#[derive(Clone)]
pub struct SchnorrSigningParams {
	/// Key id.
	pub key_id: ServerKeyId,
	/// Key requester.
	pub requester: Requester,
}

/// Schnorr signing artifacts.
#[derive(Clone)]
pub struct SchnorrSigningArtifacts {
	/// C portion of Schnorr signature. UNENCRYPTED.
	pub signature_c: H256,
	/// S portion of Schnorr signature. UNENCRYPTED.
	pub signature_s: H256,
}

/// Result of Schnorr signing session.
pub type SchnorrSigningResult = SessionResult<SchnorrSigningParams, SchnorrSigningArtifacts>;

/// Essential ECDSA signing params.
#[derive(Clone)]
pub struct EcdsaSigningParams {
	/// Key id.
	pub key_id: ServerKeyId,
	/// Key requester.
	pub requester: Requester,
}

/// ECDSA signing artifacts.
#[derive(Clone)]
pub struct EcdsaSigningArtifacts {
	/// ECDSA signature. UNENCRYPTED.
	pub signature: Signature,
}

/// Result of ECDSA signing session.
pub type EcdsaSigningResult = SessionResult<EcdsaSigningParams, EcdsaSigningArtifacts>;

/// Message signer.
pub trait MessageSigner: ServerKeyGenerator {
	/// Schnorr signing future.
	type SignMessageSchnorrFuture: Future<Output = SchnorrSigningResult> + Send;
	/// ECDSA signing future.
	type SignMessageEcdsaFuture: Future<Output = EcdsaSigningResult> + Send;

	/// Generate Schnorr signature for message with previously generated SK.
	/// `key_id` is the caller-provided identifier of generated SK.
	/// `requester` is the one who requests access to server key private.
	/// `message` is the message to be signed.
	/// Result is a signed message, encrypted with caller public key.
	fn sign_message_schnorr(
		&self,
		origin: Option<Origin>,
		key_id: ServerKeyId,
		requester: Requester,
		message: H256,
	) -> Self::SignMessageSchnorrFuture;
	/// Generate ECDSA signature for message with previously generated SK.
	/// WARNING: only possible when SK was generated using t <= 2 * N.
	/// `key_id` is the caller-provided identifier of generated SK.
	/// `signature` is `key_id`, signed with caller public key.
	/// `message` is the hash of message to be signed.
	/// Result is a signed message, encrypted with caller public key.
	fn sign_message_ecdsa(
		&self,
		origin: Option<Origin>,
		key_id: ServerKeyId,
		requester: Requester,
		message: H256,
	) -> Self::SignMessageEcdsaFuture;
}

/// Administrative sessions server.
pub trait AdminSessionsServer {
	/// Change servers set future.
	type ChangeServersSetFuture: Future<Output = SessionResult<(), ()>> + Send;

	/// Change servers set so that nodes in new_servers_set became owners of shares for all keys.
	/// And old nodes (i.e. cluster nodes except new_servers_set) have clear databases.
	/// WARNING: newly generated keys will be distributed among all cluster nodes. So this session
	/// must be followed with cluster nodes change (either via contract, or config files).
	fn change_servers_set(
		&self,
		origin: Option<Origin>,
		old_set_signature: Signature,
		new_set_signature: Signature,
		new_servers_set: BTreeSet<KeyServerPublic>,
	) -> Self::ChangeServersSetFuture;
}

/// Key server.
pub trait KeyServer: AdminSessionsServer + DocumentKeyServer + MessageSigner + Send + Sync + 'static {
}

impl<P, R> SessionResult<P, R> {
	/// Result::map().
	pub fn map<U>(self, f: impl Fn(R) -> U) -> Result<U, Error> {
		self.result.map(f)
	}

	/// Result::map_err().
	pub fn map_err<E>(self, f: impl Fn(Error) -> E) -> Result<R, E> {
		self.result.map_err(f)
	}
}

impl<P, R> Into<Result<R, Error>> for SessionResult<P, R> {
	fn into(self: SessionResult<P, R>) -> Result<R, Error> {
		self.result
	}
}

#[cfg(not(feature = "test-helpers"))]
mod accumulating_key_server {
}

#[cfg(feature = "test-helpers")]
mod accumulating_key_server {
	use futures::future::{ready, Ready};
	use parking_lot::Mutex;
	use crate::service::ServiceTask;
	use super::*;

	/// Stores every incoming request in internal queue, then fails.
	#[derive(Default)]
	pub struct AccumulatingKeyServer {
		accumulated_tasks: Mutex<Vec<ServiceTask>>,
	}

	impl AccumulatingKeyServer {
		/// Returns all accumulated tasks.
		pub fn accumulated_tasks(&self) -> Vec<ServiceTask> {
			self.accumulated_tasks.lock().clone()
		}
	}

	impl ServerKeyGenerator for AccumulatingKeyServer {
		type GenerateKeyFuture = Ready<ServerKeyGenerationResult>;
		type RestoreKeyFuture = Ready<ServerKeyRetrievalResult>;

		fn generate_key(
			&self,
			origin: Option<Origin>,
			key_id: ServerKeyId,
			author: Requester,
			threshold: usize,
		) -> Self::GenerateKeyFuture {
			self.accumulated_tasks.lock().push(ServiceTask::GenerateServerKey(
				key_id,
				author,
				threshold,
			));
			ready(SessionResult {
				origin,
				params: ServerKeyGenerationParams {
					key_id,
				},
				result: Err(Error::Internal("Test-Error".into())),
			})
		}

		fn restore_key_public(
			&self,
			origin: Option<Origin>,
			key_id: ServerKeyId,
			author: Option<Requester>,
		) -> Self::RestoreKeyFuture {
			self.accumulated_tasks.lock().push(ServiceTask::RetrieveServerKey(
				key_id,
				author,
			));
			ready(SessionResult {
				origin,
				params: ServerKeyRetrievalParams {
					key_id,
				},
				result: Err(Error::Internal("Test-Error".into())),
			})
		}
	}

	impl DocumentKeyServer for AccumulatingKeyServer {
		type StoreDocumentKeyFuture = Ready<DocumentKeyStoreResult>;
		type GenerateDocumentKeyFuture = Ready<DocumentKeyGenerationResult>;
		type RestoreDocumentKeyFuture = Ready<DocumentKeyRetrievalResult>;
		type RestoreDocumentKeyCommonFuture = Ready<DocumentKeyCommonRetrievalResult>;
		type RestoreDocumentKeyShadowFuture = Ready<DocumentKeyShadowRetrievalResult>;

		fn store_document_key(
			&self,
			origin: Option<Origin>,
			key_id: ServerKeyId,
			author: Requester,
			common_point: Public,
			encrypted_document_key: Public,
		) -> Self::StoreDocumentKeyFuture {
			self.accumulated_tasks.lock().push(ServiceTask::StoreDocumentKey(
				key_id,
				author,
				common_point,
				encrypted_document_key,
			));
			ready(SessionResult {
				origin,
				params: DocumentKeyStoreParams {
					key_id,
				},
				result: Err(Error::Internal("Test-Error".into())),
			})
		}

		fn generate_document_key(
			&self,
			origin: Option<Origin>,
			key_id: ServerKeyId,
			author: Requester,
			threshold: usize,
		) -> Self::GenerateDocumentKeyFuture {
			self.accumulated_tasks.lock().push(ServiceTask::GenerateDocumentKey(
				key_id,
				author,
				threshold,
			));
			ready(SessionResult {
				origin,
				params: DocumentKeyGenerationParams {
					key_id,
				},
				result: Err(Error::Internal("Test-Error".into())),
			})
		}

		fn restore_document_key(
			&self,
			origin: Option<Origin>,
			key_id: ServerKeyId,
			requester: Requester,
		) -> Self::RestoreDocumentKeyFuture {
			self.accumulated_tasks.lock().push(ServiceTask::RetrieveDocumentKey(
				key_id,
				requester.clone(),
			));
			ready(SessionResult {
				origin,
				params: DocumentKeyRetrievalParams {
					key_id, requester,
				},
				result: Err(Error::Internal("Test-Error".into())),
			})
		}

		fn restore_document_key_common(
			&self,
			origin: Option<Origin>,
			key_id: ServerKeyId,
			requester: Requester,
		) -> Self::RestoreDocumentKeyCommonFuture {
			self.accumulated_tasks.lock().push(ServiceTask::RetrieveShadowDocumentKey(
				key_id,
				requester.clone(),
			));
			ready(SessionResult {
				origin,
				params: DocumentKeyCommonRetrievalParams {
					key_id, requester,
				},
				result: Err(Error::Internal("Test-Error".into())),
			})
		}

		fn restore_document_key_shadow(
			&self,
			origin: Option<Origin>,
			key_id: ServerKeyId,
			requester: Requester,
		) -> Self::RestoreDocumentKeyShadowFuture {
			self.accumulated_tasks.lock().push(ServiceTask::RetrieveShadowDocumentKey(
				key_id,
				requester.clone(),
			));
			ready(SessionResult {
				origin,
				params: DocumentKeyShadowRetrievalParams {
					key_id, requester,
				},
				result: Err(Error::Internal("Test-Error".into())),
			})
		}
	}

	impl MessageSigner for AccumulatingKeyServer {
		type SignMessageSchnorrFuture = Ready<SchnorrSigningResult>;
		type SignMessageEcdsaFuture = Ready<EcdsaSigningResult>;

		fn sign_message_schnorr(
			&self,
			origin: Option<Origin>,
			key_id: ServerKeyId,
			requester: Requester,
			message: H256,
		) -> Self::SignMessageSchnorrFuture {
			self.accumulated_tasks.lock().push(ServiceTask::SchnorrSignMessage(
				key_id,
				requester.clone(),
				message,
			));
			ready(SessionResult {
				origin,
				params: SchnorrSigningParams {
					key_id, requester,
				},
				result: Err(Error::Internal("Test-Error".into())),
			})
		}

		fn sign_message_ecdsa(
			&self,
			origin: Option<Origin>,
			key_id: ServerKeyId,
			requester: Requester,
			message: H256,
		) -> Self::SignMessageEcdsaFuture {
			self.accumulated_tasks.lock().push(ServiceTask::EcdsaSignMessage(
				key_id,
				requester.clone(),
				message,
			));
			ready(SessionResult {
				origin,
				params: EcdsaSigningParams {
					key_id, requester,
				},
				result: Err(Error::Internal("Test-Error".into())),
			})
		}
	}

	impl AdminSessionsServer for AccumulatingKeyServer {
		type ChangeServersSetFuture = Ready<SessionResult<(), ()>>;

		fn change_servers_set(
			&self,
			origin: Option<Origin>,
			old_set_signature: Signature,
			new_set_signature: Signature,
			new_servers_set: BTreeSet<KeyServerPublic>,
		) -> Self::ChangeServersSetFuture {
			self.accumulated_tasks.lock().push(ServiceTask::ChangeServersSet(
				old_set_signature,
				new_set_signature,
				new_servers_set,
			));
			ready(SessionResult {
				origin,
				params: (),
				result: Err(Error::Internal("Test-Error".into())),
			})
		}
	}

	impl KeyServer for AccumulatingKeyServer {
	}
}
