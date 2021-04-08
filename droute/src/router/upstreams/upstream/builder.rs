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

use self::remote_def::ZoneTypeDef;
#[cfg(feature = "doh")]
use super::qhandle::Https;
#[cfg(feature = "dot")]
use super::qhandle::Tls;
use super::{
    qhandle::{Client, Result, Udp, Zone},
    Upstream,
};
use crate::Label;
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, net::SocketAddr, sync::Arc, time::Duration};
use trust_dns_client::client::{AsyncClient, AsyncDnssecClient};
#[cfg(feature = "dot")]
use trust_dns_proto::DnssecDnsHandle;
use trust_dns_server::authority::ZoneType;

fn default_dnssec() -> bool {
    false
}

// Default value for timeout
fn default_timeout() -> u64 {
    5
}

fn default_zone_type() -> ZoneType {
    ZoneType::Primary
}

mod remote_def {
    // Remote crate has deprecation for `Master` and `Slave`.
    #![allow(deprecated)]

    use serde::{Deserialize, Serialize};
    use trust_dns_server::authority::ZoneType;

    #[derive(Serialize, Deserialize)]
    #[serde(rename_all = "lowercase")]
    #[serde(remote = "ZoneType")]
    pub enum ZoneTypeDef {
        /// This authority for a zone
        Primary,
        /// This authority for a zone, i.e. the Primary
        Master,
        /// A secondary, i.e. replicated from the Primary
        Secondary,
        /// A secondary, i.e. replicated from the Primary
        Slave,
        /// A cached zone with recursive resolver abilities
        Hint,
        /// A cached zone where all requests are forwarded to another Resolver
        Forward,
    }
}

#[serde(rename_all = "lowercase")]
#[derive(Serialize, Deserialize, Clone)]
/// The builder for `Upstream`
pub enum UpstreamBuilder {
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
        /// Use DNSSEC or not
        #[serde(default = "default_dnssec")]
        dnssec: bool,
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
        /// Use DNSSEC or not
        #[serde(default = "default_dnssec")]
        dnssec: bool,
        /// Timeout length
        #[serde(default = "default_timeout")]
        timeout: u64,
    },
    /// UDP connection.
    Udp {
        /// Address of the remote server
        addr: SocketAddr,
        /// Use DNSSEC or not
        #[serde(default = "default_dnssec")]
        dnssec: bool,
        /// Timeout length
        #[serde(default = "default_timeout")]
        timeout: u64,
    },
    /// Local DNS zone server.
    Zone {
        /// The type of the DNS zone.
        #[serde(with = "ZoneTypeDef")]
        #[serde(default = "default_zone_type")]
        zone_type: ZoneType,
        /// The zone `Name` being created, this should match that of the RecordType::SOA record.
        origin: String,
        /// Path to the zone file.
        path: String,
    },
}

impl UpstreamBuilder {
    pub async fn build(self) -> Result<Upstream> {
        Ok(match self {
            Self::Hybrid(v) => Upstream::Hybrid(v),

            // UDP Upstream
            Self::Udp {
                addr,
                timeout,
                dnssec,
            } if !dnssec => Upstream::Others(Arc::new(Client::<Udp, AsyncClient>::new(
                Udp::new(addr),
                Duration::from_secs(timeout),
            ))),

            // UDP Upstream with DNSSEC
            Self::Udp {
                addr,
                timeout,
                dnssec,
            } if dnssec => Upstream::Others(Arc::new(Client::<Udp, AsyncDnssecClient>::new(
                Udp::new(addr),
                Duration::from_secs(timeout),
            ))),

            // DNS zone file
            Self::Zone {
                zone_type,
                origin,
                path,
            } => Upstream::Others(Arc::new(Zone::new(zone_type, origin, path)?)),

            #[cfg(feature = "doh")]
            Self::Https {
                name,
                addr,
                no_sni,
                timeout,
                dnssec,
            } if !dnssec => Upstream::Others(Arc::new(Client::<Https, AsyncClient>::new(
                Https::new(name, addr, no_sni),
                Duration::from_secs(timeout),
            ))),

            #[cfg(feature = "doh")]
            Self::Https {
                name,
                addr,
                no_sni,
                timeout,
                dnssec,
            } if dnssec => Upstream::Others(Arc::new(Client::<Https, AsyncDnssecClient>::new(
                Https::new(name, addr, no_sni),
                Duration::from_secs(timeout),
            ))),

            #[cfg(feature = "dot")]
            Self::Tls {
                name,
                addr,
                no_sni,
                timeout,
                dnssec,
            } if !dnssec => Upstream::Others(Arc::new(Client::<Tls, AsyncClient>::new(
                Tls::new(name, addr, no_sni),
                Duration::from_secs(timeout),
            ))),

            #[cfg(feature = "dot")]
            Self::Tls {
                name,
                addr,
                no_sni,
                timeout,
                dnssec,
            } if dnssec => {
                Upstream::Others(Arc::new(Client::<Tls, DnssecDnsHandle<AsyncClient>>::new(
                    Tls::new(name, addr, no_sni),
                    Duration::from_secs(timeout),
                )))
            }

            // We have already covered the two sides of the dnssec.
            Self::Udp {
                addr: _,
                timeout: _,
                dnssec: _,
            } => unreachable!(),

            #[cfg(feature = "doh")]
            Self::Https {
                name: _,
                addr: _,
                no_sni: _,
                timeout: _,
                dnssec: _,
            } => unreachable!(),

            #[cfg(feature = "dot")]
            Self::Tls {
                name: _,
                addr: _,
                no_sni: _,
                timeout: _,
                dnssec: _,
            } => unreachable!(),
        })
    }
}
