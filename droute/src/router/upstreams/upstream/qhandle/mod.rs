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

mod client_pool;
mod zone;

#[cfg(feature = "doh")]
pub use self::client_pool::Https;
#[cfg(feature = "dot")]
pub use self::client_pool::Tls;
pub use self::{
    client_pool::{Client, Udp},
    zone::Zone,
};

use self::client_pool::ClientPoolError;
use async_trait::async_trait;
use thiserror::Error;
use tokio::time::error::Elapsed;
use trust_dns_client::{error::ClientError, op::Message};
use trust_dns_proto::error::ProtoError;
use trust_dns_server::authority::LookupError;

#[async_trait]
//#[clonable]
pub trait QHandle: Send + Sync {
    async fn query(&self, mut msg: Message) -> Result<Message>;
}

pub type Result<T> = std::result::Result<T, QHandleError>;

/// Error related to client pools
#[derive(Debug, Error)]
pub enum QHandleError {
    /// Error originated from client pools.
    #[error(transparent)]
    ClientPoolError(#[from] ClientPoolError),

    /// Error forwarded from `trust-dns-client`.
    #[error(transparent)]
    ClientError(#[from] ClientError),

    /// There is error in the process of zone creation
    #[error("An error occured in creating an DNS zone upstream: {0}")]
    ZoneCreationFailed(String),

    /// Error forwarded from `tokio::time::error`. This indicates a timeout probably.
    #[error(transparent)]
    TimeError(#[from] Elapsed),

    /// Error forwarded from `trust_dns_server::authority::LookupError`.
    #[error(transparent)]
    LookupError(#[from] LookupError),

    /// Error forwarded from `trust-dns-proto`.
    #[error(transparent)]
    ProtoError(#[from] ProtoError),
}
