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

use std::{marker::PhantomData, time::Duration};

use super::{QHandle, Result as QHandleResult};
use async_trait::async_trait;
use bb8::{ManageConnection, Pool};
use thiserror::Error;
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

/// A client wrapper. The difference between this and the `ClientPool` that it only cares about how to create a client.
#[async_trait]
pub trait ClientWrapper<T: DnsHandle>: 'static + Sync + Send + Clone {
    /// Create a DNSSEC client based on stream
    async fn create(&self) -> Result<T>;

    /// Client (connection) type. e.g. UDP, TCP.
    fn conn_type(&self) -> &'static str;
}

/// A client pool that implements bb8 trait
pub struct ClientPool<T: ClientWrapper<U>, U: DnsHandle> {
    // A client wrapper instance used for creating clients
    wrapper: T,
    inner: PhantomData<U>,
}

impl<T: ClientWrapper<U>, U: DnsHandle> ClientPool<T, U> {
    /// Create a new default client pool given the underlying client instance definition.
    pub fn new(wrapper: T) -> Self {
        Self {
            wrapper,
            inner: PhantomData,
        }
    }
}

#[async_trait]
impl<T: ClientWrapper<U>, U: DnsHandle> ManageConnection for ClientPool<T, U> {
    type Connection = U;
    type Error = ClientPoolError;

    /// Attempts to create a new connection.
    async fn connect(&self) -> Result<Self::Connection> {
        self.wrapper.create().await
    }
    /// Determines if the connection is still connected to the database.
    // TODO: Test the connection
    async fn is_valid(&self, _conn: &mut bb8::PooledConnection<'_, Self>) -> Result<()> {
        Ok(())
    }
    /// Synchronously determine if the connection is no longer usable, if possible.
    fn has_broken(&self, _conn: &mut Self::Connection) -> bool {
        false
    }
}

// A Client that implements the `QHandle`.
pub struct Client<T: ClientWrapper<U>, U: DnsHandle> {
    pool: Pool<ClientPool<T, U>>,
}

impl<T: ClientWrapper<U>, U: DnsHandle> Client<T, U> {
    pub async fn new(client: T) -> QHandleResult<Self> {
        Ok(Self {
            pool: {
                let client_pool = ClientPool::new(client);
                bb8::Pool::builder()
                    .test_on_check_out(false)
                    .max_size(15)
                    .idle_timeout(Some(Duration::from_secs(2 * 60)))
                    .max_lifetime(Some(Duration::from_secs(10 * 60)))
                    .build(client_pool)
                    .await?
            },
        })
    }
}

#[async_trait]
impl<T: ClientWrapper<U>, U: DnsHandle<Error = ProtoError>> QHandle for Client<T, U> {
    async fn query(&self, msg: Message) -> QHandleResult<Message> {
        log::info!(
            "# of active conns: {}, # of idled conns: {}",
            self.pool.state().connections,
            self.pool.state().idle_connections
        );
        let mut client = self.pool.get().await?;
        Ok(Message::from(client.send(msg).await?))
    }
}
