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

#[cfg(feature = "doh")]
pub mod https;
pub mod udp;

use std::time::Duration;

use async_trait::async_trait;
use bb8::{ManageConnection, Pool, RunError};
use bytes::Bytes;
use domain::base::Message;
#[cfg(feature = "doh")]
use reqwest::{StatusCode, Url};
use thiserror::Error;
use tokio::time::{error::Elapsed, timeout};

const MAX_ERROR_TOLERANCE: u8 = 2;

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
impl<T: ConnInitiator> ManageConnection for ConnInitWrapper<T> {
    type Connection = (T::Connection, u8);

    type Error = std::io::Error;

    async fn connect(&self) -> std::result::Result<Self::Connection, Self::Error> {
        Ok((self.0.create().await?, 0))
    }

    async fn is_valid(
        &self,
        conn: &mut bb8::PooledConnection<'_, Self>,
    ) -> std::result::Result<(), Self::Error> {
        if conn.1 > MAX_ERROR_TOLERANCE {
            log::warn!("the number of error(s) encountered exceeded the threshold");
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "the number of error(s) encountered exceeded the threshold",
            ))
        } else {
            Ok(())
        }
    }

    fn has_broken(&self, conn: &mut Self::Connection) -> bool {
        conn.1 > MAX_ERROR_TOLERANCE
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

    /// Run error from bb8
    #[error(transparent)]
    RunError(#[from] RunError<std::io::Error>),

    #[cfg(feature = "doh")]
    #[error(transparent)]
    ReqwestError(#[from] reqwest::Error),

    #[cfg(feature = "doh")]
    #[error("the URL '{0}' is invalid")]
    InvalidUri(String),

    #[cfg(feature = "doh")]
    #[error("the URL '{0}' doesn't contain a valid domain")]
    InvalidDomain(Url),

    #[cfg(feature = "doh")]
    #[error("unsuccessful HTTP code: {0}")]
    FailedHttp(StatusCode),

    #[error(transparent)]
    ShortBuf(#[from] domain::base::ShortBuf),
}

pub struct ConnPool<T: ConnInitiator> {
    pool: Pool<ConnInitWrapper<T>>,
    timeout: Duration,
}

impl<T: ConnInitiator> ConnPool<T> {
    pub async fn new(initiator: T, timeout: Duration) -> std::io::Result<Self> {
        Ok(Self {
            pool: bb8::Pool::builder()
                .max_size(32)
                .idle_timeout(Some(Duration::from_secs(2 * 60)))
                .max_lifetime(Some(Duration::from_secs(10 * 60)))
                .build(ConnInitWrapper(initiator))
                .await?,
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
