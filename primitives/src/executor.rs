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

use futures::future::BoxFuture;
use crate::error::Error;

/// Futures executor.
pub trait Executor: Send + Sync + 'static {
	/// Spawn future and run to completion.
	fn spawn(&self, future: BoxFuture<'static, ()>);
}

/// Alias for tokio-compat runtime.
pub type TokioRuntime = tokio_compat::runtime::Runtime;

/// Alias for tokio-compat runtime handle.
pub type TokioHandle = tokio_compat::runtime::TaskExecutor;

/// Create new tokio runtime.
pub fn tokio_runtime() -> Result<TokioRuntime, Error> {
	TokioRuntime::new().map_err(|err| Error::Internal(format!("{}", err)))
}

impl Executor for TokioHandle {
	fn spawn(&self, future: BoxFuture<'static, ()>) {
		TokioHandle::spawn_std(self, future);
	}
}
