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

use std::{
	sync::Arc,
	time::Duration,
};
use futures::Stream;
use substrate_service::{Configuration, start_service};
use key_server::{KeyServerImpl, db_key_storage::PersistentKeyStorage};
use primitives::{
	error::Error,
	executor::TokioHandle,
	key_server_key_pair::KeyServerKeyPair,
};
use crate::{
	blockchain::SecretStoreBlockchain,
	transaction_pool::SecretStoreTransactionPool,
};

pub fn start(
	blockchain: Arc<SecretStoreBlockchain>,
	transaction_pool: Arc<SecretStoreTransactionPool>,
	executor: TokioHandle,
	key_server: Arc<KeyServerImpl>,
	key_storage: Arc<PersistentKeyStorage>,
	key_server_key_pair: Arc<dyn KeyServerKeyPair>,
	new_blocks_stream: impl Stream<Item = crate::runtime::BlockHash> + Send + 'static,
) -> Result<(), Error> {
	let listener_registrar = key_server.cluster().session_listener_registrar();
	start_service(
		key_server,
		key_storage,
		listener_registrar,
		blockchain,
		Arc::new(executor),
		transaction_pool,
		Configuration {
			self_id: key_server_key_pair.address(),
			max_active_sessions: Some(4),
			pending_restart_interval: Some(Duration::from_secs(10 * 60)),
		},
		new_blocks_stream,
	)
}
