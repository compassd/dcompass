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
use super::client_pool::Https;
#[cfg(feature = "dot")]
use super::client_pool::Tls;
use super::{
    client_pool::{DefClientPool, Udp},
    error::{Result, UpstreamError},
    upstream::{UpstreamKind, UpstreamKind::*},
};
use crate::Label;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, net::SocketAddr, time::Duration};
use trust_dns_proto::rr::Name;
use trust_dns_server::{
    authority::ZoneType,
    store::file::{FileAuthority, FileConfig},
};

/// A trait to help you to setup a customized upstream kind.
#[async_trait]
pub trait ParUpstreamKind {
    /// Convert itself to an upstream kind.
    async fn build(self) -> Result<UpstreamKind>;
}

#[serde(rename_all = "lowercase")]
#[derive(Serialize, Deserialize, Clone)]
/// Def(ault) Par(sed) Upstream
/// Information needed for an upstream. This implements deserialize to help you to parse data and construct `Upstream`
pub struct ParUpstream<K: ParUpstreamKind> {
    /// The destination (tag) associated with the upstream.
    pub tag: Label,
    /// Querying method.
    pub method: K,
}

// Default value for timeout
#[cfg(feature = "serde-cfg")]
fn default_timeout() -> u64 {
    5
}

// A struct that helps us to parse into the actual UpstreamKind
#[serde(rename_all = "lowercase")]
#[derive(Serialize, Deserialize, Clone)]
/// The methods of querying
pub enum DefParUpstreamKind {
    /// Race various different upstreams concurrently. You can use it recursively, meaning Hybrid over (Hybrid over (DoH + UDP) + UDP) is legal.
    Hybrid(HashSet<Label>),
    /// DNS over HTTPS (DoH).
    #[cfg(feature = "doh")]
    Https {
        /// The domain name of the server. e.g. `cloudflare-dns.com` for Cloudflare DNS.
        name: String,
        /// The address of the server. e.g. `1.1.1.1:443` for Cloudflare DNS.
        addr: SocketAddr,
        /// Set to `true` to not send SNI. This is useful to bypass firewalls and censorships.
        no_sni: bool,
        /// Timeout length
        #[serde(default = "default_timeout")]
        timeout: u64,
    },
    /// DNS over TLS (DoT).
    #[cfg(feature = "dot")]
    Tls {
        /// The domain name of the server. e.g. `cloudflare-dns.com` for Cloudflare DNS.
        name: String,
        /// The address of the server. e.g. `1.1.1.1:853` for Cloudflare DNS.
        addr: SocketAddr,
        /// Set to `true` to not send SNI. This is useful to bypass firewalls and censorships.
        no_sni: bool,
        /// Timeout length
        #[serde(default = "default_timeout")]
        timeout: u64,
    },
    /// UDP connection.
    Udp {
        /// Address of the remote server
        addr: SocketAddr,
        /// Timeout length
        #[serde(default = "default_timeout")]
        timeout: u64,
    },
    /// Local DNS zone server.
    Zone {
        /// The type of the DNS zone.
        zone_type: ZoneType,
        /// The zone `Name` being created, this should match that of the RecordType::SOA record.
        origin: String,
        /// Path to the zone file.
        path: String,
    },
}

#[async_trait]
impl ParUpstreamKind for DefParUpstreamKind {
    async fn build(self) -> Result<UpstreamKind> {
        Ok(match self {
            Self::Hybrid(v) => Hybrid(v),

            // UDP Upstream
            Self::Udp { addr, timeout } => Client {
                pool: Box::new(DefClientPool::new(Udp::new(addr))),
                timeout_dur: Duration::from_secs(timeout),
            },

            // DNS zone file
            Self::Zone {
                zone_type,
                origin,
                path,
            } => Zone(
                FileAuthority::try_from_config(
                    Name::from_utf8(origin)?,
                    zone_type,
                    false,
                    None,
                    &FileConfig {
                        zone_file_path: path,
                    },
                )
                .map_err(UpstreamError::ZoneCreationFailed)?,
            ),
            #[cfg(feature = "doh")]
            Self::Https {
                name,
                addr,
                no_sni,
                timeout,
            } => Client {
                pool: Box::new(DefClientPool::new(Https::new(name, addr, no_sni))),
                timeout_dur: Duration::from_secs(timeout),
            },
            #[cfg(feature = "dot")]
            Self::Tls {
                name,
                addr,
                no_sni,
                timeout,
            } => Client {
                pool: Box::new(DefClientPool::new(Tls::new(name, addr, no_sni))),
                timeout_dur: Duration::from_secs(timeout),
            },
        })
    }
}
