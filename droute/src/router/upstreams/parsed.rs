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

use super::{
    client_pool::*,
    error::Result,
    upstream::{UpstreamKind, UpstreamKind::*},
};
use crate::Label;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

#[serde(rename_all = "lowercase")]
#[derive(Serialize, Deserialize, Clone)]
/// Information needed for an upstream.
pub struct ParsedUpstream {
    /// The destination (tag) associated with the upstream.
    pub tag: Label,
    /// Querying method.
    pub method: ParsedUpstreamKind,
}

// Default value for timeout
#[cfg(feature = "serde-cfg")]
fn default_timeout() -> u64 {
    5
}

#[serde(rename_all = "lowercase")]
#[derive(Serialize, Deserialize, Clone)]
/// The methods of querying
pub enum ParsedUpstreamKind {
    /// Race various different upstreams concurrently. You can use it recursively, meaning Hybrid over (Hybrid over (DoH + UDP) + UDP) is legal.
    Hybrid(Vec<Label>),
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
}

impl ParsedUpstreamKind {
    // Shall not be accessible by external callers.
    pub(super) async fn convert(self) -> Result<UpstreamKind> {
        Ok(match self {
            Self::Hybrid(v) => Hybrid(v),
            Self::Udp { addr, timeout } => Client {
                pool: Box::new(Udp::new(&addr).await?),
                timeout,
            },
            #[cfg(feature = "doh")]
            Self::Https {
                name,
                addr,
                no_sni,
                timeout,
            } => Client {
                pool: Box::new(Https::new(name, addr, no_sni)),
                timeout,
            },
            #[cfg(feature = "dot")]
            Self::Tls {
                name,
                addr,
                no_sni,
                timeout,
            } => Client {
                pool: Box::new(Tls::new(name, addr, no_sni)),
                timeout,
            },
        })
    }
}
