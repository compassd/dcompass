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
    qhandle::{Client, Result, Tcp, Udp, Zone},
    QHandleError, Upstream,
};
use crate::{AsyncTryInto, Label};
use async_trait::async_trait;
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

#[derive(Serialize, Deserialize, Clone)]
pub struct HybridBuilder(HashSet<Label>);

impl Default for HybridBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl HybridBuilder {
    pub fn new() -> Self {
        Self(HashSet::new())
    }

    pub fn add_tag(mut self, tag: impl Into<Label>) -> Self {
        self.0.insert(tag.into());
        self
    }
}

#[async_trait]
impl AsyncTryInto<Upstream> for HybridBuilder {
    type Error = QHandleError;

    async fn try_into(self) -> Result<Upstream> {
        Ok(Upstream::Hybrid(self.0))
    }
}

#[cfg(feature = "doh")]
#[serde(rename_all = "lowercase")]
#[derive(Serialize, Deserialize, Clone)]
pub struct HttpsBuilder {
    /// The domain name of the server. e.g. `cloudflare-dns.com` for Cloudflare DNS.
    pub name: String,
    /// The address of the server. e.g. `1.1.1.1:443` for Cloudflare DNS.
    pub addr: SocketAddr,
    /// Set to `true` to not send SNI. This is useful to bypass firewalls and censorships.
    pub no_sni: bool,
    /// Use DNSSEC or not
    #[serde(default = "default_dnssec")]
    pub dnssec: bool,
}

#[cfg(feature = "doh")]
#[async_trait]
impl AsyncTryInto<Upstream> for HttpsBuilder {
    type Error = QHandleError;

    async fn try_into(self) -> Result<Upstream> {
        if self.dnssec {
            Ok(Upstream::Others(Arc::new(
                Client::<Https, AsyncDnssecClient>::new(Https::new(
                    self.name,
                    self.addr,
                    self.no_sni,
                ))
                .await?,
            )))
        } else {
            Ok(Upstream::Others(Arc::new(
                Client::<Https, AsyncClient>::new(Https::new(self.name, self.addr, self.no_sni))
                    .await?,
            )))
        }
    }
}

#[cfg(feature = "dot")]
#[serde(rename_all = "lowercase")]
#[derive(Serialize, Deserialize, Clone)]
pub struct TlsBuilder {
    /// The domain name of the server. e.g. `cloudflare-dns.com` for Cloudflare DNS.
    pub name: String,
    /// The address of the server. e.g. `1.1.1.1:853` for Cloudflare DNS.
    pub addr: SocketAddr,
    /// Set to `true` to not send SNI. This is useful to bypass firewalls and censorships.
    pub no_sni: bool,
    /// Use DNSSEC or not
    #[serde(default = "default_dnssec")]
    pub dnssec: bool,
}

#[cfg(feature = "dot")]
#[async_trait]
impl AsyncTryInto<Upstream> for TlsBuilder {
    type Error = QHandleError;

    async fn try_into(self) -> Result<Upstream> {
        if self.dnssec {
            Ok(Upstream::Others(Arc::new(
                Client::<Tls, DnssecDnsHandle<AsyncClient>>::new(Tls::new(
                    self.name,
                    self.addr,
                    self.no_sni,
                ))
                .await?,
            )))
        } else {
            Ok(Upstream::Others(Arc::new(
                Client::<Tls, AsyncClient>::new(Tls::new(self.name, self.addr, self.no_sni))
                    .await?,
            )))
        }
    }
}

#[serde(rename_all = "lowercase")]
#[derive(Serialize, Deserialize, Clone)]
pub struct UdpBuilder {
    /// Address of the remote server
    pub addr: SocketAddr,
    /// Use DNSSEC or not
    #[serde(default = "default_dnssec")]
    pub dnssec: bool,
    /// Timeout length
    #[serde(default = "default_timeout")]
    pub timeout: u64,
}

#[async_trait]
impl AsyncTryInto<Upstream> for UdpBuilder {
    type Error = QHandleError;

    async fn try_into(self) -> Result<Upstream> {
        if self.dnssec {
            Ok(Upstream::Others(Arc::new(
                Client::<Udp, AsyncDnssecClient>::new(Udp::new(
                    self.addr,
                    Duration::from_secs(self.timeout),
                ))
                .await?,
            )))
        } else {
            Ok(Upstream::Others(Arc::new(
                Client::<Udp, AsyncClient>::new(Udp::new(
                    self.addr,
                    Duration::from_secs(self.timeout),
                ))
                .await?,
            )))
        }
    }
}

#[serde(rename_all = "lowercase")]
#[derive(Serialize, Deserialize, Clone)]
pub struct TcpBuilder {
    /// Address of the remote server
    pub addr: SocketAddr,
    /// Timeout length
    #[serde(default = "default_timeout")]
    pub timeout: u64,
}

#[async_trait]
impl AsyncTryInto<Upstream> for TcpBuilder {
    type Error = QHandleError;

    async fn try_into(self) -> Result<Upstream> {
        Ok(Upstream::Others(Arc::new(
            Client::<Tcp, AsyncClient>::new(Tcp::new(self.addr, Duration::from_secs(self.timeout)))
                .await?,
        )))
    }
}

#[serde(rename_all = "lowercase")]
#[derive(Serialize, Deserialize, Clone)]
pub struct ZoneBuilder {
    /// The type of the DNS zone.
    #[serde(with = "ZoneTypeDef")]
    #[serde(default = "default_zone_type")]
    pub zone_type: ZoneType,
    /// The zone `Name` being created, this should match that of the RecordType::SOA record.
    pub origin: String,
    /// Path to the zone file.
    pub path: String,
}

#[async_trait]
impl AsyncTryInto<Upstream> for ZoneBuilder {
    type Error = QHandleError;

    async fn try_into(self) -> Result<Upstream> {
        Ok(Upstream::Others(Arc::new(Zone::new(
            self.zone_type,
            self.origin,
            self.path,
        )?)))
    }
}

#[serde(rename_all = "lowercase")]
#[derive(Serialize, Deserialize, Clone)]
/// The builder for `Upstream`
pub enum UpstreamBuilder {
    /// Race various different upstreams concurrently. You can use it recursively, meaning Hybrid over (Hybrid over (DoH + UDP) + UDP) is legal.
    Hybrid(HybridBuilder),
    /// DNS over HTTPS (DoH).
    #[cfg(feature = "doh")]
    Https(HttpsBuilder),
    /// DNS over TLS (DoT).
    #[cfg(feature = "dot")]
    Tls(TlsBuilder),
    /// UDP connection.
    Udp(UdpBuilder),
    /// TCP connection.
    Tcp(TcpBuilder),
    /// Local DNS zone server.
    Zone(ZoneBuilder),
}

#[async_trait]
impl AsyncTryInto<Upstream> for UpstreamBuilder {
    /// Build the Upstream from an UpstreamBuilder
    async fn try_into(self) -> std::result::Result<Upstream, QHandleError> {
        Ok(match self {
            Self::Hybrid(v) => v.try_into().await?,

            // UDP Upstream
            Self::Udp(u) => u.try_into().await?,

            // TCP Upstream
            Self::Tcp(t) => t.try_into().await?,

            // DNS zone file
            Self::Zone(z) => z.try_into().await?,

            #[cfg(feature = "doh")]
            Self::Https(h) => h.try_into().await?,

            #[cfg(feature = "dot")]
            Self::Tls(t) => t.try_into().await?,
        })
    }

    type Error = QHandleError;
}
