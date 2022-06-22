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

use ::domain::base::{name::FromStrError, octets::ParseError};
use maxminddb::MaxMindDBError;
use rhai::{export_module, plugin::*};
use std::sync::Arc;
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

#[export_module]
pub mod rhai_mod {
    use crate::IntoEvalAltResultError;
    use rhai::{EvalAltResult, ImmutableString};
    use std::str::FromStr;

    pub mod blackhole {
        use super::super::blackhole::blackhole;
        use crate::IntoEvalAltResultError;
        use ::domain::base::Message;
        use bytes::Bytes;

        #[rhai_fn(return_raw, pure)]
        pub fn create_blackhole(
            query: &mut Message<Bytes>,
        ) -> std::result::Result<Message<Bytes>, Box<EvalAltResult>> {
            blackhole(query).into_evalrst_err()
        }
    }

    pub mod domain {
        use super::super::domain::Domain;
        use crate::IntoEvalAltResultError;
        use ::domain::base::Dname;

        pub fn new_domain_list() -> Domain {
            Domain::new()
        }

        #[rhai_fn(return_raw)]
        pub fn add_file(
            mut domain: Domain,
            path: ImmutableString,
        ) -> std::result::Result<Domain, Box<EvalAltResult>> {
            domain.add_file(path.as_str()).into_evalrst_err()?;
            Ok(domain)
        }

        #[rhai_fn(return_raw)]
        pub fn add_qname(
            mut domain: Domain,
            qname: ImmutableString,
        ) -> std::result::Result<Domain, Box<EvalAltResult>> {
            domain.add_qname(qname.as_str()).into_evalrst_err()?;
            Ok(domain)
        }

        pub fn seal(domain: Domain) -> Arc<Domain> {
            Arc::new(domain)
        }

        #[rhai_fn(pure, name = "contains", return_raw)]
        pub fn contains_str(
            domain: &mut Arc<Domain>,
            qname: ImmutableString,
        ) -> std::result::Result<bool, Box<EvalAltResult>> {
            Ok(domain.contains(Dname::from_str(&qname).into_evalrst_err()?))
        }

        #[rhai_fn(pure, name = "contains")]
        pub fn contains_dname(domain: &mut Arc<Domain>, qname: Dname<bytes::Bytes>) -> bool {
            domain.contains(qname)
        }
    }

    pub mod geoip {
        use super::super::geoip::GeoIp;
        use std::net::IpAddr;

        #[rhai_fn(return_raw)]
        pub fn new_builtin_geoip() -> std::result::Result<GeoIp, Box<EvalAltResult>> {
            GeoIp::create_default().into_evalrst_err()
        }

        #[rhai_fn(return_raw)]
        pub fn new_geoip_from_path(
            path: ImmutableString,
        ) -> std::result::Result<GeoIp, Box<EvalAltResult>> {
            GeoIp::from_path(path).into_evalrst_err()
        }

        pub fn seal(geoip: GeoIp) -> Arc<GeoIp> {
            Arc::new(geoip)
        }

        #[rhai_fn(pure, return_raw, name = "contains")]
        pub fn contains_ip_str(
            geoip: &mut Arc<GeoIp>,
            ip: ImmutableString,
            code: ImmutableString,
        ) -> std::result::Result<bool, Box<EvalAltResult>> {
            Ok(geoip.contains(ip.parse().into_evalrst_err()?, &code))
        }

        #[rhai_fn(pure, name = "contains")]
        pub fn contains_ip(geoip: &mut Arc<GeoIp>, ip: IpAddr, code: ImmutableString) -> bool {
            geoip.contains(ip, &code)
        }
    }

    pub mod ipcidr {
        use super::super::ipcidr::IpCidr;
        use std::net::IpAddr;

        pub fn new_ipcidr() -> IpCidr {
            IpCidr::new()
        }

        #[rhai_fn(return_raw)]
        pub fn add_file(
            mut ipcidr: IpCidr,
            path: ImmutableString,
        ) -> std::result::Result<IpCidr, Box<EvalAltResult>> {
            ipcidr.add_file(path.as_str()).into_evalrst_err()?;
            Ok(ipcidr)
        }

        pub fn seal(ipcidr: IpCidr) -> Arc<IpCidr> {
            Arc::new(ipcidr)
        }

        #[rhai_fn(pure, return_raw, name = "contains")]
        pub fn contains_ip_str(
            ipcidr: &mut Arc<IpCidr>,
            ip: ImmutableString,
        ) -> std::result::Result<bool, Box<EvalAltResult>> {
            Ok(ipcidr.contains(ip.parse().into_evalrst_err()?))
        }

        #[rhai_fn(pure, name = "contains")]
        pub fn contains_ip(ipcidr: &mut Arc<IpCidr>, ip: IpAddr) -> bool {
            ipcidr.contains(ip)
        }
    }
}
