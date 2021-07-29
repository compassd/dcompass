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

use async_trait::async_trait;
use bb8::RunError;
use bytes::Bytes;
use domain::base::Message;
#[cfg(feature = "doh")]
use reqwest::StatusCode;
use reqwest::Url;
use thiserror::Error;
use tokio::time::error::Elapsed;

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
