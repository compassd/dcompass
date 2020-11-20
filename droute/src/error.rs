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

use std::fmt::{Debug, Display};
use thiserror::Error;
use trust_dns_client::error::ClientError;
use trust_dns_proto::error::ProtoError;

pub(crate) type Result<L, T> = std::result::Result<T, DrouteError<L>>;

/// DrouteError enumerates all possible errors returned by this library.
#[derive(Error, Debug)]
pub enum DrouteError<L: Display + Debug> {
    /// Tag missing in upstream definition for either the destination of a rule or the `default_tag`
    #[error("No upstream with tag {0} found")]
    MissingTag(L),

    /// There are multiple definitions of rules of the same destination or upstreams of the same tag name.
    #[error(
        "Multiple defintions found for tag/dst `{0}` either in `rules` or `upstreams` sections"
    )]
    MultipleDef(L),

    /// Hybrid definition forms a chain, which is prohibited
    #[error("You cannot recursively define `Hybrid` method. The `Hybrid` method that contains the destination to be recursively called: {0}")]
    HybridRecursion(L),

    /// There is no destinations in hybrid's destination list.
    #[error("`Hybrid` upstream method with tag {0} contains no upstreams to race")]
    EmptyHybrid(L),

    /// Error forwarded from `trust-dns-client`.
    #[error(transparent)]
    ClientError(#[from] ClientError),

    /// Error forwarded from `std::io::Error`.
    #[error("An I/O error encountered. Check files provided in configuration to ensure they exist and have the right permissions.")]
    IOError(#[from] std::io::Error),

    /// Error forwarded from `trust-dns-proto`.
    #[error(transparent)]
    ProtoError(#[from] ProtoError),

    /// Error forwarded from `tokio::time`. This indicates a timeout probably.
    #[error(transparent)]
    TimeError(#[from] tokio::time::Elapsed),
}
