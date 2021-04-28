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

// Client => ClientPool => ClientWrapper (UDP, TCP, DoT, DoH)

use super::{QHandle, Result as QHandleResult};
use async_trait::async_trait;
use pinboard::Pinboard;
use thiserror::Error;
use tokio::time::{timeout, Duration};
use trust_dns_client::op::Message;
use trust_dns_proto::{error::ProtoError, DnsHandle};

#[cfg(feature = "crypto")]
mod crypto;
mod tcp;
mod udp;

#[cfg(feature = "doh")]
pub use crypto::Https;
#[cfg(feature = "dot")]
pub use crypto::Tls;
pub use tcp::Tcp;
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

pub type Result<T> = std::result::Result<T, ClientPoolError>;

/// State of the client returned (used).
pub enum ClientState {
    /// Client failed to send message
    Failed,
    /// Client sent message successfully.
    Succeeded,
}

/// A client wrapper. The difference between this and the `ClientPool` that it only cares about how to create a client.
#[async_trait]
pub trait ClientWrapper<T: DnsHandle>: Sync + Send + Clone {
    /// Create a DNSSEC client based on stream
    async fn create(&self) -> Result<T>;

    /// Client (connection) type. e.g. UDP, TCP.
    fn conn_type(&self) -> &'static str;
}

/// A client wrapper that makes the underlying `impl DnsHandle` a `client pool`.
pub struct ClientPool<T: ClientWrapper<U>, U: DnsHandle> {
    // A client instance used for creating clients
    client: T,
    inner: Pinboard<U>,
}

impl<T: ClientWrapper<U>, U: DnsHandle> ClientPool<T, U> {
    /// Create a new default client pool given the underlying client instance definition.
    pub fn new(client: T) -> Self {
        Self {
            client,
            inner: Pinboard::new_empty(),
        }
    }

    async fn get_client(&self) -> Result<U> {
        Ok(if let Some(c) = self.inner.read() {
            c
        } else {
            log::info!(
                "No {} client in stock, creating a new one",
                self.client.conn_type()
            );
            let c = self.client.create().await?;
            self.inner.set(c.clone());
            c
        })
    }

    async fn return_client(&self, _: U, state: ClientState) -> Result<()> {
        match state {
            ClientState::Failed => {
                log::info!(
                    "client query errored, renewing the {} client",
                    self.client.conn_type()
                );
                self.inner.set(self.client.create().await?);
            }
            // We don't need to return client cause all clients distrubuted are clones of the one held here.
            ClientState::Succeeded => {}
        }
        Ok(())
    }
}

// TODO: Probabaly we can put `Client` and `ClientPool` together?
// A Client that implements the `QHandle`.
pub struct Client<T: ClientWrapper<U>, U: DnsHandle> {
    pool: ClientPool<T, U>,
    timeout_dur: Duration,
}

impl<T: ClientWrapper<U>, U: DnsHandle> Client<T, U> {
    pub fn new(client: T, timeout_dur: Duration) -> Self {
        Self {
            pool: ClientPool::new(client),
            timeout_dur,
        }
    }
}

#[async_trait]
impl<T: ClientWrapper<U>, U: DnsHandle<Error = ProtoError>> QHandle for Client<T, U> {
    async fn query(&self, msg: Message) -> QHandleResult<Message> {
        let mut client = self.pool.get_client().await?;
        let r = Message::from(match timeout(self.timeout_dur, client.send(msg)).await {
            Ok(Ok(m)) => m,
            Ok(Err(e)) => {
                // Renew the client as it errored.
                self.pool.return_client(client, ClientState::Failed).await?;
                return Err(e.into());
            }
            Err(e) => {
                self.pool.return_client(client, ClientState::Failed).await?;
                return Err(e.into());
            }
        });

        // If the response can be obtained sucessfully, we then push back the client to the client cache
        self.pool
            .return_client(client, ClientState::Succeeded)
            .await?;
        Ok(r)
    }
}
