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
use std::sync::{Arc, Mutex};
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

/// State of the client returned (used).
pub enum ClientState {
    /// Client failed to send message
    Failed,
    /// Client sent message successfully.
    Succeeded,
}

/// Client pool triat.
#[async_trait]
#[clonable]
pub trait ClientPool: Sync + Send + Clone {
    /// Get a client from the client pool. This may not indeed create one, instead, it probably only returns a cloned client.
    async fn get_client(&self) -> Result<AsyncClient>;
    /// Return back the used client for reuse or renewal (if appropriate).
    async fn return_client(&self, c: AsyncClient, state: ClientState) -> Result<()>;
}

/// A client wrapper. The difference between this and the `ClientPool` trait that it only cares about how to create a client.
#[async_trait]
pub trait ClientWrapper: Sync + Send + Clone {
    /// Create a client.
    async fn create(&self) -> Result<AsyncClient>;
    /// Client (connection) type. e.g. UDP, TCP.
    fn conn_type(&self) -> &'static str;
}

/// A client wrapper that makes the underlying `AsyncClient` a `client pool`.
#[derive(Clone)]
pub struct DefClientPool<T> {
    // A client instance used for creating clients
    client: T,
    inner: Arc<Mutex<Option<AsyncClient>>>,
}

impl<T: ClientWrapper> DefClientPool<T> {
    /// Create a new default client pool given the underlying client instance definition.
    pub fn new(client: T) -> Self {
        Self {
            client,
            inner: Arc::new(Mutex::new(None)),
        }
    }

    fn get(&self) -> Option<AsyncClient> {
        self.inner.lock().unwrap().clone()
    }

    fn set(&self, c: AsyncClient) {
        *self.inner.lock().unwrap() = Some(c);
    }
}

#[async_trait]
impl<T: ClientWrapper> ClientPool for DefClientPool<T> {
    async fn get_client(&self) -> Result<AsyncClient> {
        Ok(if let Some(c) = self.get() {
            c
        } else {
            log::info!(
                "No {} client in stock, creating a new one",
                self.client.conn_type()
            );
            let c = self.client.create().await?;
            self.set(c.clone());
            c
        })
    }

    async fn return_client(&self, _: AsyncClient, state: ClientState) -> Result<()> {
        match state {
            ClientState::Failed => {
                log::info!("Renewing the {} client", self.client.conn_type());
                self.set(self.client.create().await?);
            }
            // We don't need to return client cause all clients distrubuted are clones of the one held here.
            ClientState::Succeeded => {}
        }
        Ok(())
    }
}
