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

#[cfg(any(feature = "doh-rustls", feature = "doh-native-tls"))]
pub mod https;
pub mod udp;

use async_trait::async_trait;
use bytes::Bytes;
use deadpool::managed::{self, BuildError, Manager, Pool, RecycleError};
use domain::base::Message;
#[cfg(any(feature = "doh-rustls", feature = "doh-native-tls"))]
use reqwest::{StatusCode, Url};
use std::time::Duration;
use thiserror::Error;
use tokio::time::{error::Elapsed, timeout};

const MAX_ERROR_TOLERANCE: u8 = 2;
const MAX_POOL_SIZE: usize = 64;

// The connection initiator, like Udp, Https. It is similar to ManageConnection.
// The primary reason for its existence is that we want to reduce the boilderplate on implementing ManageConnection
#[async_trait]
pub trait ConnInitiator: Send + Sync + 'static {
    type Connection: QHandle;

    async fn create(&self) -> std::io::Result<Self::Connection>;

    fn conn_type(&self) -> &'static str;
}

// A local ConnInitiator wrapper
pub struct ConnInitWrapper<T: ConnInitiator>(T);

#[async_trait]
impl<T: ConnInitiator> Manager for ConnInitWrapper<T> {
    type Type = (T::Connection, u8);

    type Error = std::io::Error;

    async fn create(&self) -> std::result::Result<Self::Type, Self::Error> {
        Ok((self.0.create().await?, 0))
    }

    async fn recycle(&self, obj: &mut Self::Type) -> managed::RecycleResult<Self::Error> {
        if obj.1 > MAX_ERROR_TOLERANCE {
            log::warn!("the number of error(s) encountered exceeded the threshold");
            Err(RecycleError::StaticMessage(
                "the number of error(s) encountered exceeded the threshold",
            ))
        } else {
            Ok(())
        }
    }
}

#[async_trait]
//#[clonable]
pub trait QHandle: Send + Sync {
    async fn query(&self, msg: &Message<Bytes>) -> Result<Message<Bytes>>;
}

pub type Result<T> = std::result::Result<T, QHandleError>;

/// Error related to client pools
#[derive(Debug, Error)]
pub enum QHandleError {
    /// Error forwarded from `tokio::time::error`. This indicates a timeout probably.
    #[error(transparent)]
    TimeError(#[from] Elapsed),

    /// IO Error
    #[error(transparent)]
    IoError(#[from] std::io::Error),

    /// Run error from deadpool
    #[error(transparent)]
    PoolRunError(#[from] managed::PoolError<std::io::Error>),

    #[error(transparent)]
    PoolBuildError(#[from] managed::BuildError<std::io::Error>),

    #[cfg(any(feature = "doh-rustls", feature = "doh-native-tls"))]
    #[error(transparent)]
    ReqwestError(#[from] reqwest::Error),

    #[cfg(any(feature = "doh-rustls", feature = "doh-native-tls"))]
    #[error("the URL '{0}' is invalid")]
    InvalidUri(String),

    #[cfg(any(feature = "doh-rustls", feature = "doh-native-tls"))]
    #[error("the URL '{0}' doesn't contain a valid domain")]
    InvalidDomain(Url),

    #[cfg(any(feature = "doh-rustls", feature = "doh-native-tls"))]
    #[error("unsuccessful HTTP code: {0}")]
    FailedHttp(StatusCode),

    #[error(transparent)]
    ShortBuf(#[from] domain::base::ShortBuf),
}

// For HTTPS connections, ConnPool enables parallelism
pub struct ConnPool<T: ConnInitiator> {
    pool: Pool<ConnInitWrapper<T>>,
    timeout: Duration,
}

impl<T: ConnInitiator> ConnPool<T> {
    pub fn new(
        initiator: T,
        timeout: Duration,
    ) -> std::result::Result<Self, BuildError<<ConnInitWrapper<T> as Manager>::Error>> {
        Ok(Self {
            pool: Pool::builder(ConnInitWrapper(initiator))
                .max_size(MAX_POOL_SIZE)
                .build()?,
            timeout,
        })
    }
}

#[async_trait]
impl<T: ConnInitiator> QHandle for ConnPool<T> {
    async fn query(&self, msg: &Message<Bytes>) -> Result<Message<Bytes>> {
        let mut conn = self.pool.get().await?;

        // Use flatten in the future
        match timeout(self.timeout, conn.0.query(msg)).await {
            // Within the timeout, query was successful
            Ok(Ok(m)) => {
                conn.1 = 0;
                Ok(m)
            }
            // Within the timeout, query was unsuccessful
            Ok(Err(e)) => {
                conn.1 += 1;
                Err(e)
            }
            // Timedout
            Err(e) => {
                conn.1 += 1;
                Err(QHandleError::TimeError(e))
            }
        }
    }
}
