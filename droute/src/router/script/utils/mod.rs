// Copyright 2022 LEXUGE
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

// proc-macro on non-inline modules are unstable

mod blackhole;
mod domain;
mod geoip;
mod ipcidr;

pub use self::domain::Domain;
pub use blackhole::blackhole;
pub use geoip::GeoIp;
pub use ipcidr::IpCidr;

use ::domain::base::{name::FromStrError, octets::ParseError};
use maxminddb::MaxMindDBError;
use thiserror::Error;

/// A shorthand for returning utils error.
pub type Result<T> = std::result::Result<T, UtilsError>;

#[derive(Error, Debug)]
/// All possible errors that may incur when using utils.
pub enum UtilsError {
    /// Error forwarded from `std::io::Error`.
    #[error("An I/O error encountered. Check files provided for matcher(s) to ensure they exist and have the right permissions.")]
    IoError(#[from] std::io::Error),

    /// Error related to GeoIP usages.
    #[error("An error happened when using `geoip` matcher.")]
    GeoIpError(#[from] MaxMindDBError),

    /// Error related to IP CIDR.
    #[error("An error encountered in the IP CIDR matcher: {0}")]
    IpCidrError(#[from] cidr_utils::cidr::IpCidrError),

    /// No path to GeoIP database specified while no builtin database is provided.
    #[cfg(not(any(feature = "geoip-cn", feature = "geoip-maxmind")))]
    #[error("This build doesn't contain a built-in GeoIP database, please specify your own database or use other builds.")]
    NoBuiltInDb,

    /// Compression error
    #[error("Failed during decompression: {0}")]
    DecompError(#[from] niffler::Error),

    /// Failed to convert dname from string
    #[error(transparent)]
    FromStrError(#[from] FromStrError),

    /// Failed to parse the record
    #[error(transparent)]
    ParseError(#[from] ParseError),

    /// Short Buf
    #[error(transparent)]
    ShortBuf(#[from] ::domain::base::ShortBuf),
}
