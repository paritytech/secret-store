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

use std::collections::{BTreeSet, HashSet};
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};
use futures::{future::{ready, Either}, FutureExt, Stream, StreamExt};
use log::{error, warn};
use parking_lot::RwLock;
use ethereum_types::{U256, BigEndianHash};

use primitives::{
	KeyServerId, ServerKeyId,
	error::Error,
	executor::Executor,
	key_server::{
		Origin, KeyServer, ServerKeyGenerationArtifacts, ServerKeyRetrievalArtifacts,
		DocumentKeyCommonRetrievalArtifacts, DocumentKeyShadowRetrievalArtifacts,
		ServerKeyGenerationResult, DocumentKeyShadowRetrievalResult,
	},
	key_storage::KeyStorage,
	requester::Requester,
	service::{ServiceTasksListenerRegistrar, ServiceTask},
};

/// Blockchain service tasks.
///
/// It is ServiceTask extended with `Origin` (which currently only makes sense
/// for blockchain services) and some blockchain-specific tasks.
#[derive(Debug)]
#[cfg_attr(test, derive(Clone))]
pub enum BlockchainServiceTask {
	/// Regular service task.
	Regular(Origin, ServiceTask),
	/// Retrieve common part of document key.
	RetrieveShadowDocumentKeyCommon(Origin, ServerKeyId, Requester),
	/// Retrieve personal part of document key.
	RetrieveShadowDocumentKeyPersonal(Origin, ServerKeyId, Requester),
}

/// Block API.
pub trait Block: Send + Sync {
	/// New blocks iterator.
	type NewBlocksIterator: IntoIterator<Item = BlockchainServiceTask>;
	/// Pending tasks iterator.
	type PendingBlocksIterator: IntoIterator<Item = BlockchainServiceTask>;

	/// Get all new service tasks from this block.
	fn new_tasks(&self) -> Self::NewBlocksIterator;
	/// Get all pending service tasks at this block.
	fn pending_tasks(&self) -> Self::PendingBlocksIterator;
	/// Returns current key server set at this block.
	fn current_key_servers_set(&self) -> BTreeSet<KeyServerId>;
}

/// Transaction pool API.
pub trait TransactionPool: Send + Sync + 'static {
	/// Publish generated server key.
	fn publish_generated_server_key(
		&self,
		origin: Origin,
		key_id: ServerKeyId,
		artifacts: ServerKeyGenerationArtifacts,
	);
	/// Publish server key generation error.
	fn publish_server_key_generation_error(&self, origin: Origin, key_id: ServerKeyId);
	/// Publish retrieved server key.
	fn publish_retrieved_server_key(
		&self,
		origin: Origin,
		key_id: ServerKeyId,
		artifacts: ServerKeyRetrievalArtifacts,
	);
	/// Publish server key retrieval error.
	fn publish_server_key_retrieval_error(&self, origin: Origin, key_id: ServerKeyId);
	/// Publish store document key result (success).
	fn publish_stored_document_key(&self, origin: Origin, key_id: ServerKeyId);
	/// Publish document key store error.
	fn publish_document_key_store_error(&self, origin: Origin, key_id: ServerKeyId);
	/// Publish retrieved common part of document key.
	fn publish_retrieved_document_key_common(
		&self,
		origin: Origin,
		key_id: ServerKeyId,
		requester: Requester,
		artifacts: DocumentKeyCommonRetrievalArtifacts,
	);
	/// Publish common part of document key retrieval error.
	fn publish_document_key_common_retrieval_error(
		&self,
		origin: Origin,
		key_id: ServerKeyId,
		requester: Requester,
	);
	/// Publish retrieved personal part of document key.
	fn publish_retrieved_document_key_personal(
		&self,
		origin: Origin,
		key_id: ServerKeyId,
		requester: Requester,
		artifacts: DocumentKeyShadowRetrievalArtifacts,
	);
	///
	fn publish_document_key_personal_retrieval_error(
		&self,
		origin: Origin,
		key_id: ServerKeyId,
		requester: Requester,
	);
}

/// Service configuration.
#[derive(Clone)]
pub struct Configuration {
	/// Id of this key server.
	pub self_id: KeyServerId,
	/// Maximal number of active sessions started by this service.
	/// None means that there's no limit.
	pub max_active_sessions: Option<usize>,
	/// Pending tasks restart interval.
	/// None means that pending tasks are never restarted.
	pub pending_restart_interval: Option<Duration>,
}

/// Service environment.
struct Environment<E, TP, KSrv, KStr> {
	/// This key server id.
	pub self_id: KeyServerId,
	/// Futures executor reference.
	pub executor: Arc<E>,
	/// Transaction pool reference.
	pub transaction_pool: Arc<TP>,
	/// Key server reference.
	pub key_server: Arc<KSrv>,
	/// Key storage reference.
	pub key_storage: Arc<KStr>,
}

/// Shared service data.
struct ServiceData {
	/// Last pending tasks restart time.
	pub last_restart_time: Instant,
	/// Active server key generation sessions started by this service.
	pub server_key_generation_sessions: HashSet<ServerKeyId>,
	/// Recently completed (with or without error) server key generation sessions,
	/// started by this service.
	pub recent_server_key_generation_sessions: HashSet<ServerKeyId>,
	/// Active server key retrieval sessions started by this service.
	pub server_key_retrieval_sessions: HashSet<ServerKeyId>,
	/// Recently completed (with or without error) server key retrieval sessions,
	/// started by this service.
	pub recent_server_key_retrieval_sessions: HashSet<ServerKeyId>,
	/// Active document key store sessions started by this service.
	pub document_key_store_sessions: HashSet<ServerKeyId>,
	/// Recently completed (with or without error) document key store sessions,
	/// started by this service.
	pub recent_document_key_store_sessions: HashSet<ServerKeyId>,
	/// Active common document key part retrieval sessions started by this service.
	pub document_key_common_retrieval_sessions: HashSet<(ServerKeyId, Requester)>,
	/// Recently completed (with or without error) common document key part retrieval sessions,
	/// started by this service.
	pub recent_document_key_common_retrieval_sessions: HashSet<(ServerKeyId, Requester)>,
	/// Active personal document key part retrieval sessions started by this service.
	pub document_key_personal_retrieval_sessions: HashSet<(ServerKeyId, Requester)>,
	/// Recently completed (with or without error) personal document key part retrieval sessions,
	/// started by this service.
	pub recent_document_key_personal_retrieval_sessions: HashSet<(ServerKeyId, Requester)>,
}

/// Service tasks listener.
struct ServiceTasksListener<E, TP, KSrv, KStr> {
	/// Shared service data reference.
	pub environment: Arc<Environment<E, TP, KSrv, KStr>>,
}

/// Start listening requests from given blocks stream.
///
/// Blockchain service checks every block from the stream for new tasks and
/// publishes responses using transaction pool. In addition, at given interval
/// service checks for pending tasks (that have been missed or failed for some
/// internal reason) and restarts them.
pub async fn start_service<B, E, TP, KSrv, KStr>(
	key_server: Arc<KSrv>,
	key_storage: Arc<KStr>,
	listener_registrar: Arc<dyn ServiceTasksListenerRegistrar>,
	executor: Arc<E>,
	transaction_pool: Arc<TP>,
	config: Configuration,
	new_blocks_stream: impl Stream<Item = B>,
) -> Result<(), Error> where
	B: Block,
	E: Executor,
	TP: TransactionPool,
	KSrv: KeyServer,
	KStr: KeyStorage,
{
	start_service_with_service_data(
		Arc::new(RwLock::new(empty_service_data())),
		key_server,
		key_storage,
		listener_registrar,
		executor,
		transaction_pool,
		config,
		new_blocks_stream,
	).await
}

async fn start_service_with_service_data<B, E, TP, KSrv, KStr>(
	service_data: Arc<RwLock<ServiceData>>,
	key_server: Arc<KSrv>,
	key_storage: Arc<KStr>,
	listener_registrar: Arc<dyn ServiceTasksListenerRegistrar>,
	executor: Arc<E>,
	transaction_pool: Arc<TP>,
	config: Configuration,
	new_blocks_stream: impl Stream<Item = B>,
) -> Result<(), Error> where
	B: Block,
	E: Executor,
	TP: TransactionPool,
	KSrv: KeyServer,
	KStr: KeyStorage,
{
	let environment = Arc::new(Environment {
		self_id: config.self_id,
		executor,
		transaction_pool,
		key_server,
		key_storage,
	});

	listener_registrar.register_listener(Arc::new(ServiceTasksListener {
		environment: environment.clone(),
	}));

	new_blocks_stream
		.for_each(|block| {
			// we do not want to overload Secret Store, so let's limit number of possible active sessions
			let future_service_data = service_data.clone();
			let mut service_data = service_data.write();
			let num_active_sessions = service_data.active_sessions();
			let mut max_additional_sessions = config
				.max_active_sessions
				.unwrap_or(std::usize::MAX)
				.checked_sub(num_active_sessions)
				.unwrap_or(0);

			// we need to know current key servers set to distribute tasks among nodes
			let current_set = block.current_key_servers_set();

			// if we are not a part of key server set, ignore all tasks
			if !current_set.contains(&environment.self_id) {
				return ready(());
			}

			// first, process new tasks
			max_additional_sessions -= process_tasks(
				&environment,
				&future_service_data,
				&current_set,
				block.new_tasks().into_iter().take(max_additional_sessions),
				&mut service_data,
			);

			// if enough time has passed since last tasks restart, let's start them now
			if let Some(pending_restart_interval) = config.pending_restart_interval {
				let last_restart_time = service_data.last_restart_time;
				let duration_since_last_restart = Instant::now() - last_restart_time;
				if duration_since_last_restart > pending_restart_interval {
					process_tasks(
						&environment,
						&future_service_data,
						&current_set,
						block.pending_tasks().into_iter().take(max_additional_sessions),
						&mut service_data,
					);

					service_data.last_restart_time = Instant::now();
					service_data.recent_server_key_generation_sessions.clear();
					service_data.recent_server_key_retrieval_sessions.clear();
					service_data.recent_document_key_store_sessions.clear();
					service_data.recent_document_key_common_retrieval_sessions.clear();
					service_data.recent_document_key_personal_retrieval_sessions.clear();
				}
			}

			ready(())
		})
		.await;

	Ok(())
}

/// Process multiple service tasks.
fn process_tasks<E, TP, KSrv, KStr>(
	future_environment: &Arc<Environment<E, TP, KSrv, KStr>>,
	future_service_data: &Arc<RwLock<ServiceData>>,
	current_set: &BTreeSet<KeyServerId>,
	new_tasks: impl Iterator<Item = BlockchainServiceTask>,
	service_data: &mut ServiceData,
) -> usize where
	E: Executor,
	TP: TransactionPool,
	KSrv: KeyServer,
	KStr: KeyStorage,
{
	let mut added_tasks = 0;
	for new_task in new_tasks {
		let filtered_task = process_task(
			future_environment,
			future_service_data,
			current_set,
			new_task,
			service_data,
		);

		if let Some(filtered_task) = filtered_task {
			future_environment.executor.spawn(filtered_task.boxed());
		}

		added_tasks += 1;
	}

	added_tasks
}

/// Process single service task.
fn process_task<E, TP, KSrv, KStr>(
	future_environment: &Arc<Environment<E, TP, KSrv, KStr>>,
	future_service_data: &Arc<RwLock<ServiceData>>,
	current_set: &BTreeSet<KeyServerId>,
	task: BlockchainServiceTask,
	service_data: &mut ServiceData,
) -> Option<impl Future<Output = ()>> where
	E: Executor,
	TP: TransactionPool,
	KSrv: KeyServer,
	KStr: KeyStorage,
{
	match task {
		BlockchainServiceTask::Regular(origin, ServiceTask::GenerateServerKey(key_id, requester, threshold)) => {
			if !filter_task(
				&current_set,
				Some(&future_environment.self_id),
				&key_id,
				Some(&mut service_data.server_key_generation_sessions),
				&mut service_data.recent_server_key_generation_sessions,
			) {
				return None;
			}

			let future_environment = future_environment.clone();
			let future_service_data = future_service_data.clone();
			Some(Either::Left(
				future_environment
					.key_server
					.generate_key(Some(origin), key_id, requester, threshold)
					.map(move |_| {
						future_service_data.write().server_key_generation_sessions.remove(&key_id);
					})
			))
		},
		BlockchainServiceTask::Regular(origin, ServiceTask::RetrieveServerKey(key_id, _requester)) => {
			// in blockchain services we ignore requesters for RetrieveServerKey requests
			// (i.e. public portion of server key is available to anyone)
			if !filter_task(
				&current_set,
				None,
				&key_id,
				None,
				&mut service_data.recent_server_key_retrieval_sessions,
			) {
				return None;
			}

			let future_environment = future_environment.clone();
			Some(Either::Right(Either::Left(
				ready({
					let key_share = future_environment.key_storage.get(&key_id);
					match key_share {
						Ok(Some(key_share)) => {
							future_environment.transaction_pool.publish_retrieved_server_key(
								origin,
								key_id,
								ServerKeyRetrievalArtifacts {
									author: key_share.author,
									key: key_share.public,
									threshold: key_share.threshold,
								},
							)
						},
						Ok(None) => {
							future_environment.transaction_pool.publish_server_key_retrieval_error(
								origin,
								key_id,
							)
						}
						Err(error) if error.is_non_fatal() => {
							log_nonfatal_secret_store_error(&format!("RetrieveServerKey({})", key_id), error);
						},
						Err(error) => {
							log_fatal_secret_store_error(&format!("RetrieveServerKey({})", key_id), error);
							future_environment.transaction_pool.publish_server_key_retrieval_error(
								origin,
								key_id,
							);
						},
					}
				})
			)))
		},
		BlockchainServiceTask::Regular(
			origin,
			ServiceTask::StoreDocumentKey(key_id, author, common_point, encrypted_point),
		) => {
			if !filter_task(
				&current_set,
				None,
				&key_id,
				None,
				&mut service_data.recent_document_key_store_sessions,
			) {
				return None;
			}


			let future_environment = future_environment.clone();
			Some(Either::Right(Either::Right(Either::Left(
				ready({
					let store_result = future_environment.key_storage.get(&key_id)
						.and_then(|key_share| key_share.ok_or(Error::ServerKeyIsNotFound))
						.and_then(|key_share| {
							// check that common_point and encrypted_point are still not set yet
							if key_share.common_point.is_some() || key_share.encrypted_point.is_some() {
								return Err(Error::DocumentKeyAlreadyStored);
							}

							Ok(key_share)
						})
						.and_then(|mut key_share| {
							// author must be the same
							if key_share.author != author.address(&key_id)? {
								return Err(Error::AccessDenied);
							}

							// save encryption data
							key_share.common_point = Some(common_point);
							key_share.encrypted_point = Some(encrypted_point);
							future_environment.key_storage.update(key_id, key_share)
						});

					match store_result {
						Ok(_) => future_environment.transaction_pool.publish_stored_document_key(
							origin,
							key_id,
						),
						Err(error) if error.is_non_fatal() => {
							log_nonfatal_secret_store_error(&format!("StoreDocumentKey({})", key_id), error);
						},
						Err(error) => {
							log_fatal_secret_store_error(&format!("StoreDocumentKey({})", key_id), error);
							future_environment.transaction_pool.publish_document_key_store_error(
								origin,
								key_id,
							);
						},
					}
				})
			))))
		},
		BlockchainServiceTask::RetrieveShadowDocumentKeyCommon(origin, key_id, requester) => {
			if !filter_document_task(
				&current_set,
				None,
				&key_id,
				&requester,
				Some(&mut service_data.document_key_common_retrieval_sessions),
				&mut service_data.recent_document_key_common_retrieval_sessions,
			) {
				return None;
			}

			let future_environment = future_environment.clone();
			let future_service_data = future_service_data.clone();
			Some(Either::Right(Either::Right(Either::Right(Either::Left(
				future_environment
					.key_server
					.restore_document_key_common(Some(origin), key_id, requester.clone())
					.map(move |result| {
						future_service_data.write().document_key_common_retrieval_sessions.remove(
							&(key_id, requester.clone()),
						);

						match result.result {
							Ok(artifacts) => future_environment
								.transaction_pool
								.publish_retrieved_document_key_common(
									origin,
									result.params.key_id,
									result.params.requester,
									artifacts,
								),
							Err(error) if error.is_non_fatal() => {
								log_nonfatal_secret_store_error(
									&format!(
										"RestoreDocumentKeyCommon({}, {})",
										result.params.key_id,
										result.params.requester,
									),
									error,
								);
							},
							Err(error) => {
								log_fatal_secret_store_error(
									&format!(
										"RestoreDocumentKeyCommon({}, {})",
										result.params.key_id,
										result.params.requester,
									),
									error,
								);
								future_environment.transaction_pool.publish_document_key_common_retrieval_error(
									origin,
									result.params.key_id,
									result.params.requester,
								);
							}
						}
					})
			)))))
		},
		BlockchainServiceTask::RetrieveShadowDocumentKeyPersonal(origin, key_id, requester) => {
			if !filter_document_task(
				&current_set,
				Some(&future_environment.self_id),
				&key_id,
				&requester,
				Some(&mut service_data.document_key_personal_retrieval_sessions),
				&mut service_data.recent_document_key_personal_retrieval_sessions,
			) {
				return None;
			}

			let future_environment = future_environment.clone();
			let future_service_data = future_service_data.clone();
			Some(Either::Right(Either::Right(Either::Right(Either::Right(
				future_environment
					.key_server
					.restore_document_key_shadow(Some(origin), key_id, requester.clone())
					.map(move |_| {
						future_service_data.write().document_key_personal_retrieval_sessions.remove(
							&(key_id, requester.clone()),
						);
					})
			)))))
		},
		BlockchainServiceTask::Regular(_, ServiceTask::GenerateDocumentKey(_, _, _)) => {
			unimplemented!("GenerateDocumentKey requests are not implemented on blockchain services");
		},
		BlockchainServiceTask::Regular(_, ServiceTask::RetrieveDocumentKey(_, _)) => {
			unimplemented!("RetrieveDocumentKey requests are not implemented on blockchain services");
		},
		BlockchainServiceTask::Regular(_, ServiceTask::RetrieveShadowDocumentKey(_, _)) => {
			unimplemented!("RetrieveShadowDocumentKey requests are not implemented on blockchain services");
		},
		BlockchainServiceTask::Regular(_, ServiceTask::SchnorrSignMessage(_, _, _)) => {
			unimplemented!("SchnorrSignMessage requests are not implemented on blockchain services");
		},
		BlockchainServiceTask::Regular(_, ServiceTask::EcdsaSignMessage(_, _, _)) => {
			unimplemented!("EcdsaSignMessage requests are not implemented on blockchain services");
		},
		BlockchainServiceTask::Regular(_, ServiceTask::ChangeServersSet(_, _, _)) => {
			unimplemented!("ChangeServersSet requests are not implemented on blockchain services");
		},
	}
}

/// Log nonfatal session error.
fn log_nonfatal_secret_store_error(request_type: &str, error: Error) {
	warn!(
		target: "secretstore",
		"{} request has nonfatally failed with: {}",
		request_type,
		error,
	);
}

/// Log fatal session error.
fn log_fatal_secret_store_error(request_type: &str, error: Error) {
	error!(
		target: "secretstore",
		"{} request has failed with: {}",
		request_type,
		error,
	);
}

/// Returns true when session, related to `server_key_id` could be started now.
fn filter_task(
	current_set: &BTreeSet<KeyServerId>,
	self_id: Option<&KeyServerId>,
	server_key_id: &ServerKeyId,
	active_sessions: Option<&mut HashSet<ServerKeyId>>,
	recent_sessions: &mut HashSet<ServerKeyId>,
) -> bool {
	// check if task mus be procesed by another node
	if let Some(self_id) = self_id {
		if !is_processed_by_this_key_server(current_set, self_id, server_key_id) {
			return false;
		}
	}
	// check if task has been completed recently
	if !recent_sessions.insert(*server_key_id) {
		return false;
	}
	// check if task is currently processed
	if let Some(active_sessions) = active_sessions {
		if !active_sessions.insert(*server_key_id) {
			return false;
		}
	}

	true
}

/// Returns true when session, related to both `server_key_id` and `requester` could be started now.
fn filter_document_task(
	current_set: &BTreeSet<KeyServerId>,
	self_id: Option<&KeyServerId>,
	server_key_id: &ServerKeyId,
	requester: &Requester,
	active_sessions: Option<&mut HashSet<(ServerKeyId, Requester)>>,
	recent_sessions: &mut HashSet<(ServerKeyId, Requester)>,
) -> bool {
	// check if task mus be procesed by another node
	if let Some(self_id) = self_id {
		if !is_processed_by_this_key_server(current_set, self_id, server_key_id) {
			return false;
		}
	}
	// check if task has been completed recently
	if !recent_sessions.insert((*server_key_id, requester.clone())) {
		return false;
	}
	// check if task is currently processed
	if let Some(active_sessions) = active_sessions {
		if !active_sessions.insert((*server_key_id, requester.clone())) {
			return false;
		}
	}

	true
}

/// Returns true when session, related to `server_key_id` must be started by this node.
fn is_processed_by_this_key_server(
	current_set: &BTreeSet<KeyServerId>,
	self_id: &KeyServerId,
	server_key_id: &ServerKeyId,
) -> bool {
	let total_servers_count = current_set.len();
	match total_servers_count {
		0 => return false,
		1 => return true,
		_ => (),
	}

	let this_server_index = match current_set.iter().enumerate().find(|&(_, s)| s == self_id) {
		Some((index, _)) => index,
		None => return false,
	};

	let server_key_id_value: U256 = server_key_id.into_uint();
	let range_interval = U256::max_value() / total_servers_count;
	let range_begin = (range_interval + 1) * this_server_index as u32;
	let range_end = range_begin.saturating_add(range_interval);

	server_key_id_value >= range_begin && server_key_id_value <= range_end
}

impl ServiceData {
	/// Return number of active sessions started by this service.
	fn active_sessions(&self) -> usize {
		self.server_key_generation_sessions.len()
			+ self.server_key_retrieval_sessions.len()
			+ self.document_key_store_sessions.len()
			+ self.document_key_common_retrieval_sessions.len()
			+ self.document_key_personal_retrieval_sessions.len()
	}
}

// TODO: we are not checking that session Origin omes from our service
// => if several services are active, we may submit transaction of
// another service. So origin must be service_id + current origin

impl<E, TP, KSrv, KStr>
	primitives::service::ServiceTasksListener
for
	ServiceTasksListener<E, TP, KSrv, KStr>
where
	E: Executor,
	TP: TransactionPool,
	KSrv: KeyServer,
	KStr: KeyStorage,
{
	fn server_key_generated(&self, result: ServerKeyGenerationResult) {
		if let Some(origin) = result.origin {
			match result.result {
				Ok(artifacts) => self.environment.transaction_pool.publish_generated_server_key(
					origin,
					result.params.key_id,
					artifacts,
				),
				Err(error) if error.is_non_fatal() => log_nonfatal_secret_store_error(
					&format!("GenerateServerKey({})", result.params.key_id),
					error,
				),
				Err(error) => {
					log_fatal_secret_store_error(&format!("GenerateServerKey({})", result.params.key_id), error);
					self.environment.transaction_pool.publish_server_key_generation_error(
						origin,
						result.params.key_id,
					);
				},
			}
		}
	}

	fn document_key_shadow_retrieved(&self, result: DocumentKeyShadowRetrievalResult) {
		if let Some(origin) = result.origin {
			match result.result {
				Ok(key_personal) => self.environment
					.transaction_pool
					.publish_retrieved_document_key_personal(
						origin,
						result.params.key_id,
						result.params.requester,
						key_personal,
					),
				Err(error) if error.is_non_fatal() => {
					log_nonfatal_secret_store_error(
						&format!(
							"RestoreDocumentKeyPersonal({}, {})",
							result.params.key_id,
							result.params.requester,
						),
						error,
					);
				},
				Err(error) => {
					log_fatal_secret_store_error(
						&format!(
							"RestoreDocumentKeyPersonal({}, {})",
							result.params.key_id,
							result.params.requester,
						),
						error,
					);
					self.environment
						.transaction_pool
						.publish_document_key_personal_retrieval_error(
							origin,
							result.params.key_id,
							result.params.requester,
						);
				}
			}
		}
	}
}


fn empty_service_data() -> ServiceData {
	ServiceData {
		last_restart_time: Instant::now(),
		server_key_generation_sessions: HashSet::new(),
		recent_server_key_generation_sessions: HashSet::new(),
		server_key_retrieval_sessions: HashSet::new(),
		recent_server_key_retrieval_sessions: HashSet::new(),
		document_key_store_sessions: HashSet::new(),
		recent_document_key_store_sessions: HashSet::new(),
		document_key_common_retrieval_sessions: HashSet::new(),
		recent_document_key_common_retrieval_sessions: HashSet::new(),
		document_key_personal_retrieval_sessions: HashSet::new(),
		recent_document_key_personal_retrieval_sessions: HashSet::new(),
	}
}

#[cfg(test)]
mod tests {
	use primitives::{
		executor::tokio_runtime,
		key_server::AccumulatingKeyServer,
		key_storage::InMemoryKeyStorage,
		service::ServiceTasksListener,
	};
	use super::*;

	const REQUESTER1_ID: [u8; 20] = [1u8; 20];
	const REQUESTER2_ID: [u8; 20] = [2u8; 20];

	const KEY1_ID: [u8; 32] = [1u8; 32];
	const KEY2_ID: [u8; 32] = [2u8; 32];
	const KEY3_ID: [u8; 32] = [3u8; 32];

	fn new_task() -> ServiceTask {
		ServiceTask::GenerateServerKey(
			KEY1_ID.into(),
			Requester::Address(REQUESTER1_ID.into()),
			8,
		)
	}

	fn pending_task() -> ServiceTask {
		ServiceTask::GenerateServerKey(
			KEY2_ID.into(),
			Requester::Address(REQUESTER1_ID.into()),
			8,
		)
	}

	fn server_key_retrieval_task() -> ServiceTask {
		ServiceTask::RetrieveServerKey(
			KEY1_ID.into(),
			None,
		)
	}

	fn document_key_store_task() -> ServiceTask {
		ServiceTask::StoreDocumentKey(
			KEY1_ID.into(),
			Requester::Address(REQUESTER1_ID.into()),
			[10u8; 64].into(),
			[11u8; 64].into(),
		)
	}

	fn document_key_shadow_retrieval_task() -> ServiceTask {
		ServiceTask::RetrieveShadowDocumentKey(
			KEY1_ID.into(),
			Requester::Address(REQUESTER1_ID.into()),
		)
	}

	#[derive(Default)]
	struct TestListenerRegistrar(RwLock<usize>);

	impl ServiceTasksListenerRegistrar for TestListenerRegistrar {
		fn register_listener(&self, _listener: Arc<dyn ServiceTasksListener>) {
			*self.0.write() += 1;
		}
	}

	struct TestBlock {
		key_servers_set: BTreeSet<KeyServerId>,
		new_tasks: Vec<BlockchainServiceTask>,
		pending_tasks: Vec<BlockchainServiceTask>,
	}

	impl Block for TestBlock {
		type NewBlocksIterator = Vec<BlockchainServiceTask>;
		type PendingBlocksIterator = Vec<BlockchainServiceTask>;

		fn new_tasks(&self) -> Self::NewBlocksIterator {
			self.new_tasks.clone()
		}

		fn pending_tasks(&self) -> Self::PendingBlocksIterator {
			self.pending_tasks.clone()
		}

		fn current_key_servers_set(&self) -> BTreeSet<KeyServerId> {
			self.key_servers_set.clone()
		}
	}

	#[derive(Default)]
	struct TestTransactionPool {
		retrieved_server_keys: RwLock<Vec<ServerKeyId>>,
		failed_retrieved_server_keys: RwLock<Vec<ServerKeyId>>,
		stored_document_keys: RwLock<Vec<ServerKeyId>>,
		failed_stored_document_keys: RwLock<Vec<ServerKeyId>>,
	}

	impl TransactionPool for TestTransactionPool {
		fn publish_generated_server_key(
			&self,
			_origin: Origin,
			_key_id: ServerKeyId,
			_artifacts: ServerKeyGenerationArtifacts,
		) { }

		fn publish_server_key_generation_error(&self, _origin: Origin, _key_id: ServerKeyId) { }

		fn publish_retrieved_server_key(
			&self,
			_origin: Origin,
			key_id: ServerKeyId,
			_artifacts: ServerKeyRetrievalArtifacts,
		) {
			self.retrieved_server_keys.write().push(key_id);
		}

		fn publish_server_key_retrieval_error(&self, _origin: Origin, key_id: ServerKeyId) {
			self.failed_retrieved_server_keys.write().push(key_id)
		}

		fn publish_stored_document_key(&self, _origin: Origin, key_id: ServerKeyId) {
			self.stored_document_keys.write().push(key_id);
		}

		fn publish_document_key_store_error(&self, _origin: Origin, key_id: ServerKeyId) {
			self.failed_stored_document_keys.write().push(key_id)
		}

		fn publish_retrieved_document_key_common(
			&self,
			_origin: Origin,
			_key_id: ServerKeyId,
			_requester: Requester,
			_artifacts: DocumentKeyCommonRetrievalArtifacts,
		) { }

		fn publish_document_key_common_retrieval_error(
			&self,
			_origin: Origin,
			_key_id: ServerKeyId,
			_requester: Requester,
		) { }

		fn publish_retrieved_document_key_personal(
			&self,
			_origin: Origin,
			_key_id: ServerKeyId,
			_requester: Requester,
			_artifacts: DocumentKeyShadowRetrievalArtifacts,
		) { }

		fn publish_document_key_personal_retrieval_error(
			&self,
			_origin: Origin,
			_key_id: ServerKeyId,
			_requester: Requester,
		) { }
	}

	const KEY_SERVER1_ID: [u8; 20] = REQUESTER1_ID;
	const KEY_SERVER2_ID: [u8; 20] = [2u8; 20];
	const KEY_SERVER100_ID: [u8; 20] = [2u8; 20];

	fn default_key_storage() -> Arc<InMemoryKeyStorage> {
		let key_storage = Arc::new(InMemoryKeyStorage::default());
		key_storage.insert(
			KEY1_ID.into(),
			primitives::key_storage::KeyShare {
				author: REQUESTER1_ID.into(),
				..Default::default()
			},
		).unwrap();
		key_storage
	}

	fn run_tasks_at_key_server_with_data(
		key_server_id: KeyServerId,
		service_data: Arc<RwLock<ServiceData>>,
		key_storage: Arc<InMemoryKeyStorage>,
		new_tasks: Vec<BlockchainServiceTask>,
		pending_tasks: Vec<BlockchainServiceTask>,
	) -> (Arc<AccumulatingKeyServer>, Arc<TestTransactionPool>) {
		let key_server = Arc::new(AccumulatingKeyServer::default());
		let listener_registrar = Arc::new(TestListenerRegistrar::default());
		let transaction_pool = Arc::new(TestTransactionPool::default());
		let blocks_stream = futures::stream::iter(vec![TestBlock {
			key_servers_set: vec![
				KEY_SERVER1_ID.into(),
				KEY_SERVER2_ID.into(),
			].into_iter().collect(),
			new_tasks,
			pending_tasks,
		}]);
		futures::executor::block_on(start_service_with_service_data(
			service_data,
			key_server.clone(),
			key_storage,
			listener_registrar.clone(),
			Arc::new(tokio_runtime().unwrap().executor()),
			transaction_pool.clone(),
			Configuration {
				self_id: key_server_id,
				max_active_sessions: Some(3),
				pending_restart_interval: Some(Duration::from_secs(60 * 1_000)),
			},
			blocks_stream,
		)).unwrap();

		// listener is registered once for every service
		assert_eq!(*listener_registrar.0.read(), 1);

		(
			key_server,
			transaction_pool
		)
	}

	fn run_at_key_server_with_data(
		key_server_id: KeyServerId,
		service_data: Arc<RwLock<ServiceData>>,
	) -> (Arc<AccumulatingKeyServer>, Arc<TestTransactionPool>) {
		run_tasks_at_key_server_with_data(
			key_server_id,
			service_data,
			default_key_storage(),
			vec![BlockchainServiceTask::Regular(Default::default(), new_task())],
			vec![BlockchainServiceTask::Regular(Default::default(), pending_task())],
		)
	}

	fn run_at_key_server(key_server_id: KeyServerId) -> (Arc<AccumulatingKeyServer>, Arc<TestTransactionPool>) {
		run_at_key_server_with_data(key_server_id, Arc::new(RwLock::new(empty_service_data())))
	}

	fn run_at_key_server_server_key_retrieval(
		key_server_id: KeyServerId,
		service_data: Arc<RwLock<ServiceData>>,
	) -> (Arc<AccumulatingKeyServer>, Arc<TestTransactionPool>) {
		run_tasks_at_key_server_with_data(
			key_server_id,
			service_data,
			default_key_storage(),
			vec![BlockchainServiceTask::Regular(Default::default(), server_key_retrieval_task())],
			vec![],
		)
	}

	fn run_at_key_server_document_key_store(
		key_server_id: KeyServerId,
		service_data: Arc<RwLock<ServiceData>>,
	) -> (Arc<AccumulatingKeyServer>, Arc<TestTransactionPool>) {
		run_tasks_at_key_server_with_data(
			key_server_id,
			service_data,
			default_key_storage(),
			vec![BlockchainServiceTask::Regular(Default::default(), document_key_store_task())],
			vec![],
		)
	}

	fn run_at_key_server_document_key_common_retrieval(
		key_server_id: KeyServerId,
		service_data: Arc<RwLock<ServiceData>>,
	) -> (Arc<AccumulatingKeyServer>, Arc<TestTransactionPool>) {
		run_tasks_at_key_server_with_data(
			key_server_id,
			service_data,
			default_key_storage(),
			vec![BlockchainServiceTask::RetrieveShadowDocumentKeyCommon(
				Default::default(),
				KEY1_ID.into(),
				Requester::Address(REQUESTER1_ID.into()),
			)],
			vec![],
		)
	}

	fn run_at_key_server_document_key_personal_retrieval(
		key_server_id: KeyServerId,
		service_data: Arc<RwLock<ServiceData>>,
	) -> (Arc<AccumulatingKeyServer>, Arc<TestTransactionPool>) {
		run_tasks_at_key_server_with_data(
			key_server_id,
			service_data,
			default_key_storage(),
			vec![BlockchainServiceTask::RetrieveShadowDocumentKeyPersonal(
				Default::default(),
				KEY1_ID.into(),
				Requester::Address(REQUESTER1_ID.into()),
			)],
			vec![],
		)
	}

	#[test]
	fn new_tasks_are_ignored_by_isolated_key_server() {
		assert_eq!(
			run_at_key_server(KEY_SERVER100_ID.into()).0.accumulated_tasks(),
			vec![],
		);
	}

	#[test]
	fn new_tasks_are_started_by_key_server() {
		assert_eq!(
			run_at_key_server(KEY_SERVER1_ID.into()).0.accumulated_tasks(),
			vec![new_task()],
		);
	}

	#[test]
	fn service_ignores_new_tasks_when_there_are_too_many_active_tasks() {
		let mut service_data = empty_service_data();
		service_data.last_restart_time = Instant::now() - Duration::from_secs(1_000);
		service_data.server_key_generation_sessions.insert([100u8; 32].into());
		service_data.server_key_generation_sessions.insert([101u8; 32].into());
		service_data.server_key_generation_sessions.insert([102u8; 32].into());

		assert_eq!(
			run_at_key_server_with_data(KEY_SERVER1_ID.into(), Arc::new(RwLock::new(service_data)))
				.0.accumulated_tasks(),
			vec![],
		);
	}

	#[test]
	fn service_retries_pending_tasks_when_it_is_time() {
		let mut service_data = empty_service_data();
		service_data.recent_server_key_generation_sessions.insert(KEY3_ID.into());
		service_data.last_restart_time = Instant::now() - Duration::from_secs(100 * 1_000);

		let service_data = Arc::new(RwLock::new(service_data));
		assert_eq!(
			run_at_key_server_with_data(KEY_SERVER1_ID.into(), service_data.clone())
				.0.accumulated_tasks(),
			vec![new_task(), pending_task()],
		);
		assert!(service_data.read().recent_server_key_generation_sessions.is_empty());
	}

	#[test]
	fn service_ignores_pending_tasks_when_there_are_too_many_active_tasks() {
		let mut service_data = empty_service_data();
		service_data.last_restart_time = Instant::now() - Duration::from_secs(1_000);
		service_data.server_key_generation_sessions.insert([100u8; 32].into());
		service_data.server_key_generation_sessions.insert([101u8; 32].into());
		service_data.last_restart_time = Instant::now() - Duration::from_secs(100 * 1_000);

		assert_eq!(
			run_at_key_server_with_data(KEY_SERVER1_ID.into(), Arc::new(RwLock::new(empty_service_data())))
				.0.accumulated_tasks(),
			vec![new_task()],
		);
	}

	#[test]
	fn process_tasks_ignores_foreign_server_key_generation_task() {
		assert_eq!(
			run_at_key_server(KEY_SERVER2_ID.into()).0.accumulated_tasks(),
			vec![],
		);
	}

	#[test]
	fn process_tasks_ignores_recent_server_key_generation_task() {
		let mut service_data = empty_service_data();
		service_data.recent_server_key_generation_sessions.insert(KEY1_ID.into());
		assert_eq!(
			run_at_key_server_with_data(KEY_SERVER1_ID.into(), Arc::new(RwLock::new(service_data)))
				.0.accumulated_tasks(),
			vec![],
		);
	}

	#[test]
	fn process_tasks_ignores_active_server_key_generation_task() {
		let mut service_data = empty_service_data();
		service_data.server_key_generation_sessions.insert(KEY1_ID.into());
		assert_eq!(
			run_at_key_server_with_data(KEY_SERVER1_ID.into(), Arc::new(RwLock::new(service_data)))
				.0.accumulated_tasks(),
			vec![],
		);
	}

	#[test]
	fn process_tasks_spawns_filtered_server_key_generation_task() {
		assert_eq!(
			run_at_key_server(KEY_SERVER1_ID.into()).0.accumulated_tasks(),
			vec![new_task()],
		);
	}

	#[test]
	fn process_tasks_ignores_recent_server_key_retrieval_task() {
		let mut service_data = empty_service_data();
		service_data.recent_server_key_retrieval_sessions.insert(KEY1_ID.into());
		assert_eq!(
			run_at_key_server_server_key_retrieval(
				KEY_SERVER1_ID.into(),
				Arc::new(RwLock::new(service_data)),
			).1.retrieved_server_keys.read().clone(),
			vec![],
		);
	}

	#[test]
	fn process_tasks_spawns_filtered_server_key_retrieval_task() {
		assert_eq!(
			run_at_key_server_server_key_retrieval(
				KEY_SERVER1_ID.into(),
				Arc::new(RwLock::new(empty_service_data())),
			).1.retrieved_server_keys.read().clone(),
			vec![KEY1_ID.into()],
		);
	}

	#[test]
	fn process_tasks_fails_filtered_server_key_retrieval_task_when_key_is_not_found() {
		assert_eq!(
			run_tasks_at_key_server_with_data(
				KEY_SERVER1_ID.into(),
				Arc::new(RwLock::new(empty_service_data())),
				Arc::new(InMemoryKeyStorage::default()),
				vec![BlockchainServiceTask::Regular(Default::default(), server_key_retrieval_task())],
				vec![],
			).1.failed_retrieved_server_keys.read().clone(),
			vec![KEY1_ID.into()],
		);
	}

	#[test]
	fn process_tasks_ignores_recent_document_key_store_task() {
		let mut service_data = empty_service_data();
		service_data.recent_document_key_store_sessions.insert(KEY1_ID.into());
		assert_eq!(
			run_at_key_server_document_key_store(
				KEY_SERVER1_ID.into(),
				Arc::new(RwLock::new(service_data)),
			).1.stored_document_keys.read().clone(),
			vec![],
		);
	}

	#[test]
	fn process_tasks_spawns_filtered_document_key_store_task() {
		assert_eq!(
			run_at_key_server_document_key_store(
				KEY_SERVER1_ID.into(),
				Arc::new(RwLock::new(empty_service_data())),
			).1.stored_document_keys.read().clone(),
			vec![KEY1_ID.into()],
		);
	}

	#[test]
	fn process_tasks_fails_filtered_document_key_store_task_when_key_is_not_found() {
		assert_eq!(
			run_tasks_at_key_server_with_data(
				KEY_SERVER1_ID.into(),
				Arc::new(RwLock::new(empty_service_data())),
				Arc::new(InMemoryKeyStorage::default()),
				vec![BlockchainServiceTask::Regular(Default::default(), document_key_store_task())],
				vec![],
			).1.failed_stored_document_keys.read().clone(),
			vec![KEY1_ID.into()],
		);
	}

	#[test]
	fn process_tasks_fails_filtered_document_key_store_task_when_key_is_already_stored() {
		let key_storage = InMemoryKeyStorage::default();
		key_storage.insert(KEY1_ID.into(), primitives::key_storage::KeyShare {
			author: REQUESTER1_ID.into(),
			common_point: Some([42u8; 64].into()),
			..Default::default()
		}).unwrap();
		assert_eq!(
			run_tasks_at_key_server_with_data(
				KEY_SERVER1_ID.into(),
				Arc::new(RwLock::new(empty_service_data())),
				Arc::new(key_storage),
				vec![BlockchainServiceTask::Regular(Default::default(), document_key_store_task())],
				vec![],
			).1.failed_stored_document_keys.read().clone(),
			vec![KEY1_ID.into()],
		);
	}

	#[test]
	fn process_tasks_fails_filtered_document_key_store_task_when_key_author_is_different() {
		let key_storage = InMemoryKeyStorage::default();
		key_storage.insert(KEY1_ID.into(), primitives::key_storage::KeyShare {
			author: REQUESTER2_ID.into(),
			..Default::default()
		}).unwrap();
		assert_eq!(
			run_tasks_at_key_server_with_data(
				KEY_SERVER1_ID.into(),
				Arc::new(RwLock::new(empty_service_data())),
				Arc::new(key_storage),
				vec![BlockchainServiceTask::Regular(Default::default(), document_key_store_task())],
				vec![],
			).1.failed_stored_document_keys.read().clone(),
			vec![KEY1_ID.into()],
		);
	}

	#[test]
	fn process_tasks_ignores_active_document_key_common_retrieval_task() {
		let mut service_data = empty_service_data();
		service_data.document_key_common_retrieval_sessions.insert(
			(KEY1_ID.into(), Requester::Address(REQUESTER1_ID.into())),
		);
		assert_eq!(
			run_at_key_server_document_key_common_retrieval(
				KEY_SERVER1_ID.into(),
				Arc::new(RwLock::new(service_data)),
			).0.accumulated_tasks(),
			vec![],
		);
	}

	#[test]
	fn process_tasks_ignores_recent_document_key_common_retrieval_task() {
		let mut service_data = empty_service_data();
		service_data.recent_document_key_common_retrieval_sessions.insert(
			(KEY1_ID.into(), Requester::Address(REQUESTER1_ID.into())),
		);
		assert_eq!(
			run_at_key_server_document_key_common_retrieval(
				KEY_SERVER1_ID.into(),
				Arc::new(RwLock::new(service_data)),
			).0.accumulated_tasks(),
			vec![],
		);
	}

	#[test]
	fn process_tasks_spawns_filtered_document_key_common_retrieval_task() {
		assert_eq!(
			run_at_key_server_document_key_common_retrieval(
				KEY_SERVER1_ID.into(),
				Arc::new(RwLock::new(empty_service_data())),
			).0.accumulated_tasks(),
			vec![document_key_shadow_retrieval_task()],
		);
	}

	#[test]
	fn process_tasks_ignores_foreign_document_key_personal_retrieval_task() {
		assert_eq!(
			run_at_key_server_document_key_personal_retrieval(
				KEY_SERVER2_ID.into(),
				Arc::new(RwLock::new(empty_service_data())),
			).0.accumulated_tasks(),
			vec![],
		);
	}

	#[test]
	fn process_tasks_ignores_recent_document_key_personal_retrieval_task() {
		let mut service_data = empty_service_data();
		service_data.recent_document_key_personal_retrieval_sessions.insert(
			(KEY1_ID.into(), Requester::Address(REQUESTER1_ID.into())),
		);
		assert_eq!(
			run_at_key_server_document_key_personal_retrieval(
				KEY_SERVER1_ID.into(),
				Arc::new(RwLock::new(service_data)),
			).0.accumulated_tasks(),
			vec![],
		);
	}

	#[test]
	fn process_tasks_ignores_active_document_key_personal_retrieval_task() {
		let mut service_data = empty_service_data();
		service_data.document_key_personal_retrieval_sessions.insert(
			(KEY1_ID.into(), Requester::Address(REQUESTER1_ID.into())),
		);
		assert_eq!(
			run_at_key_server_document_key_personal_retrieval(
				KEY_SERVER1_ID.into(),
				Arc::new(RwLock::new(service_data)),
			).0.accumulated_tasks(),
			vec![],
		);
	}

	#[test]
	fn process_tasks_spawns_filtered_document_key_personal_retrieval_task() {
		assert_eq!(
			run_at_key_server_document_key_personal_retrieval(
				KEY_SERVER1_ID.into(),
				Arc::new(RwLock::new(empty_service_data())),
			).0.accumulated_tasks(),
			vec![document_key_shadow_retrieval_task()],
		);
	}
}
