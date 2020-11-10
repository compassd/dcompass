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

//! This module provides universal error type used in the library. The error type uses `thiserror`.

use dmatcher::Label;
use thiserror::Error;
use trust_dns_client::error::ClientError;
use trust_dns_proto::error::ProtoError;

pub(crate) type Result<T> = std::result::Result<T, DrouteError>;

/// DrouteError enumerates all possible errors returned by this library.
#[derive(Error, Debug)]
pub enum DrouteError {
    /// Tag missing in upstream definition for either the destination of a rule or the `default_tag`
    #[error("No upstream with tag {0} found")]
    MissingTag(Label),

    /// Hybrid definition includes another hybrid upstream as a destination, whihc is currently prohibited. (May support in the future).
    #[error("Currently you cannot recursively use `hybrid` upstream method")]
    HybridRecursion,

    /// There is no destinations in hybrid's destination list.
    #[error("`hybrid` upstream method with tag {0} contains no upstreams to race")]
    EmptyHybrid(Label),

    /// Error forwarded from `trust-dns-client`.
    #[error(transparent)]
    ClientError(#[from] ClientError),

    /// Error forwarded from `std::io::Error`.
    #[error(transparent)]
    IOError(#[from] std::io::Error),

    /// Error forwarded from `trust-dns-proto`.
    #[error(transparent)]
    ProtoError(#[from] ProtoError),

    /// Error forwarded from `serde_json`. This indicates a parsing error
    #[error(transparent)]
    ParseError(#[from] serde_json::Error),

    /// Error forwarded from `tokio::time`. This indicates a timeout probably.
    #[error(transparent)]
    TimeError(#[from] tokio::time::Elapsed),
}
