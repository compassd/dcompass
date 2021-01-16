// Copyright 2020 LEXUGE
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use async_trait::async_trait;
use dyn_clonable::*;
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};
use thiserror::Error;
use trust_dns_client::client::AsyncClient;
use trust_dns_proto::error::ProtoError;

#[cfg(feature = "crypto")]
mod crypto;
mod udp;

#[cfg(feature = "doh")]
pub use crypto::Https;
#[cfg(feature = "dot")]
pub use crypto::Tls;
pub use udp::Udp;

/// Error related to client pools
#[derive(Debug, Error)]
pub enum ClientPoolError {
    /// Any other unrecoverable errors.
    #[error("Client pool encountered an error: {0}")]
    Other(String),

    /// Error forwarded from `trust-dns-proto`.
    #[error(transparent)]
    ProtoError(#[from] ProtoError),
}

type Result<T> = std::result::Result<T, ClientPoolError>;

/// Client pool triat
#[async_trait]
#[clonable]
pub trait ClientPool: Sync + Send + Clone {
    /// Get a client from the client pool.
    async fn get_client(&self) -> Result<AsyncClient>;
    /// Return back the used client for reuse (if appropriate).
    async fn return_client(&self, c: AsyncClient);
}

const MAX_INSTANCE_NUM: usize = 128;

#[derive(Clone)]
pub(self) struct Pool<T> {
    inner: Arc<Mutex<VecDeque<T>>>,
}

impl<T> Pool<T> {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(VecDeque::new())),
        }
    }

    pub fn get(&self) -> Option<T> {
        {
            // This ensures during the lock, queue's state is unchanged. (We shall only lock once).
            let mut p = self.inner.lock().unwrap();
            if p.is_empty() {
                None
            } else {
                // queue is not empty
                Some(p.pop_front().unwrap())
            }
        }
    }

    pub fn put(&self, c: T) {
        let mut p = self.inner.lock().unwrap();
        p.push_back(c);
        p.truncate(MAX_INSTANCE_NUM);
    }
}
