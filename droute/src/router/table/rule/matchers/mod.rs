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

mod any;
/// Builders for built-in matchers and more.
pub mod builder;
mod domain;
#[cfg(feature = "geoip")]
mod geoip;
mod ipcidr;
mod qtype;

#[cfg(feature = "geoip")]
pub use self::geoip::GeoIp;
pub use self::{
    any::Any,
    domain::{Domain, ResourceType},
    ipcidr::IpCidr,
    qtype::QType,
};

use super::super::State;
#[cfg(feature = "geoip")]
use maxminddb::MaxMindDBError;
use std::fmt::Debug;
use thiserror::Error;

/// A shorthand for returning action error.
pub type Result<T> = std::result::Result<T, MatchError>;

#[derive(Error, Debug)]
/// All possible errors that may incur when using matchers.
pub enum MatchError {
    /// Error forwarded from `std::io::Error`.
    #[error("An I/O error encountered. Check files provided for matcher(s) to ensure they exist and have the right permissions.")]
    IoError(#[from] std::io::Error),

    /// Error related to GeoIP usages.
    #[cfg(feature = "geoip")]
    #[error("An error happened when using `geoip` matcher.")]
    GeoIpError(#[from] MaxMindDBError),

    /// Error related to IP CIDR.
    #[error("An error encountered in the IP CIDR matcher.")]
    IpCidrError(#[from] cidr_utils::cidr::IpCidrError),

    /// Malformatted file provided to a matcher.
    #[error("File provided for matcher(s) is malformatted.")]
    Malformatted,

    /// No path to GeoIP database specified while no builtin database is provided.
    #[cfg(feature = "geoip")]
    #[error("This build doesn't contain a built-in GeoIP database, please specify your own database or use other builds.")]
    NoBuiltInDb,

    /// Other error.
    #[error("An error encountered in matcher: {0}")]
    Other(String),
}

/// A matcher determines if something matches or not given the current state.
pub trait Matcher: Sync + Send {
    /// Determine if match.
    fn matches(&self, state: &State) -> bool;
}
