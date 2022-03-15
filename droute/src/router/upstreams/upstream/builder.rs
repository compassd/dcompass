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

#[cfg(any(feature = "doh-rustls", feature = "doh-native-tls"))]
use super::qhandle::https::Https;
#[cfg(any(feature = "dot-native-tls", feature = "dot-rustls"))]
use super::qhandle::tls::Tls;
use super::{
    qhandle::{udp::Udp, ConnPool, Result},
    QHandleError, Upstream,
};
use crate::{AsyncTryInto, Label};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
#[cfg(any(feature = "doh-rustls", feature = "doh-native-tls"))]
use std::net::IpAddr;
use std::{net::SocketAddr, num::NonZeroU32, sync::Arc, time::Duration};

// Default value for timeout
const fn default_timeout() -> u64 {
    5
}

// RATIONALE BEHIND THIS DEFAULT VALUE
// Actually, if the tolerance level is 2, then the expected number of queries needed to get a valid response is about E(n) = 1.34*n + 1.66
// That means we have to have on average 344.265 queries by a single sender in order to get one valid response given all the connections in pool are broken and the pool size is 256.
//
// Let's say if we have m senders concurrently sending requests on an all-broken connection pool. Let's say for each sender the expected time to get the valid response is about E(n)/m. Then for m = 5, at the worst case -- timeout for 5 seconds each request -- we would need E(n) seconds to recover the system.
//
// According to our benchmark and real world scenario, UDP connections' turnabout time is between 4 - 60ms. That means a single connection can support 16 to 250 queries per second.
// This means: for each 1.3 second we wait on recovery, we can get about 200 more qps. Quite a good deal!
//
// Let's say finally we are willing to wait 60 seconds on recovery. We could then take a pool size of 43, which corresponds to a recovery time of 59.6425
const fn default_udp_max_pool_size() -> usize {
    43
}

// We do cache TLS connections, let's use the same default as UDP temporarily.
#[cfg(any(feature = "dot-native-tls", feature = "dot-rustls"))]
const fn default_tls_max_pool_size() -> usize {
    43
}

#[cfg(any(feature = "dot-native-tls", feature = "dot-rustls"))]
const fn default_tls_max_reuse() -> usize {
    200
}

#[cfg(any(feature = "dot-native-tls", feature = "dot-rustls"))]
const fn default_tls_reuse_timeout() -> u64 {
    60000
}

// We don't cache HTTPS connections. That means we wouldn't need any recovery! Indeed, we store clients.
// On average, HTTPS query roundtrip time is 750ms. That means a bigger connection pool is almost always better.
#[cfg(any(feature = "doh-rustls", feature = "doh-native-tls"))]
const fn default_https_max_pool_size() -> usize {
    1024
}

/// A builder for hybrid upstream
#[derive(Serialize, Deserialize, Clone)]
pub struct HybridBuilder(Vec<Label>);

impl Default for HybridBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl HybridBuilder {
    /// Create an empty hybrid builder
    pub fn new() -> Self {
        Self(Vec::new())
    }

    /// Add another upstream to the hybrid upstream about to build
    pub fn add_tag(mut self, tag: impl Into<Label>) -> Self {
        self.0.push(tag.into());
        self
    }
}

#[async_trait]
impl AsyncTryInto<Upstream> for HybridBuilder {
    type Error = QHandleError;

    async fn async_try_into(self) -> Result<Upstream> {
        Ok(Upstream::Hybrid(self.0))
    }
}

/// A builder for DNS over HTTPS upstream
#[cfg(any(feature = "doh-rustls", feature = "doh-native-tls"))]
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub struct HttpsBuilder {
    /// The URL of the DoH server. e.g. `https://cloudflare-dns.com/dns-query`
    pub uri: String,
    /// The address of the server. e.g. `1.1.1.1` for Cloudflare DNS.
    pub addr: IpAddr,
    /// The Proxy URL used to connect the upstream server. Supporting HTTP and SOCKS5 proxy formats.
    pub proxy: Option<String>,
    /// Timeout length
    #[serde(default = "default_timeout")]
    pub timeout: u64,
    /// Max connection pool size
    #[serde(default = "default_https_max_pool_size")]
    pub max_pool_size: usize,
    /// Maximum number of query per second and the query burst size allowed to upstream using Leaky Bucket algorithm
    #[serde(default)]
    pub ratelimit: Option<NonZeroU32>,
    /// SNI
    #[serde(default)]
    pub sni: bool,
}

#[cfg(any(feature = "doh-rustls", feature = "doh-native-tls"))]
#[async_trait]
impl AsyncTryInto<Upstream> for HttpsBuilder {
    type Error = QHandleError;

    async fn async_try_into(self) -> Result<Upstream> {
        Ok(Upstream::Others(Arc::new(ConnPool::new(
            Https::new(self.uri, self.addr, self.proxy, self.sni).await?,
            self.max_pool_size,
            Duration::from_secs(self.timeout),
            self.ratelimit.into(),
        )?)))
    }
}

/// A builder for DNS over TLS upstream
#[cfg(any(feature = "dot-native-tls", feature = "dot-rustls"))]
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub struct TlsBuilder {
    /// The domain of the DoH server. e.g. `cloudflare-dns.com`
    pub domain: String,
    /// The address of the server. e.g. `1.1.1.1:853` for Cloudflare DNS.
    pub addr: SocketAddr,
    /// Timeout length
    #[serde(default = "default_timeout")]
    pub timeout: u64,
    /// Max connection pool size
    #[serde(default = "default_tls_max_pool_size")]
    pub max_pool_size: usize,
    /// The time in millisecond to keep the underlying persistent TCP connection open for reuse
    #[serde(default = "default_tls_reuse_timeout")]
    pub reuse_timeout: u64,
    /// The maximum number of queries allowed to send over a single underlying TCP connection
    #[serde(default = "default_tls_max_reuse")]
    pub max_reuse: usize,
    /// Maximum number of query per second and the query burst size allowed to upstream using Leaky Bucket algorithm
    #[serde(default)]
    pub ratelimit: Option<NonZeroU32>,
    /// SNI
    #[serde(default)]
    pub sni: bool,
}

#[cfg(any(feature = "dot-native-tls", feature = "dot-rustls"))]
#[async_trait]
impl AsyncTryInto<Upstream> for TlsBuilder {
    type Error = QHandleError;

    async fn async_try_into(self) -> Result<Upstream> {
        Ok(Upstream::Others(Arc::new(ConnPool::new(
            Tls::new(
                self.domain,
                self.addr,
                self.sni,
                self.reuse_timeout,
                self.max_reuse,
            )?,
            self.max_pool_size,
            Duration::from_secs(self.timeout),
            self.ratelimit.into(),
        )?)))
    }
}

/// A builder for UDP upstream
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub struct UdpBuilder {
    /// Address of the remote server
    pub addr: SocketAddr,
    /// Max connection pool size
    #[serde(default = "default_udp_max_pool_size")]
    pub max_pool_size: usize,
    /// Maximum number of query per second and the query burst size allowed to upstream using Leaky Bucket algorithm
    #[serde(default)]
    pub ratelimit: Option<NonZeroU32>,
    /// Timeout length
    #[serde(default = "default_timeout")]
    pub timeout: u64,
}

#[async_trait]
impl AsyncTryInto<Upstream> for UdpBuilder {
    type Error = QHandleError;

    async fn async_try_into(self) -> Result<Upstream> {
        Ok(Upstream::Others(Arc::new(ConnPool::new(
            Udp::new(self.addr).await?,
            self.max_pool_size,
            Duration::from_secs(self.timeout),
            self.ratelimit.into(),
        )?)))
    }
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
/// The builder for `Upstream`
pub enum UpstreamBuilder {
    /// Race various different upstreams concurrently. You can use it recursively, meaning Hybrid over (Hybrid over (DoH + UDP) + UDP) is legal.
    Hybrid(HybridBuilder),
    /// UDP connection.
    Udp(UdpBuilder),
    #[cfg(any(feature = "doh-rustls", feature = "doh-native-tls"))]
    /// HTTPS connection.
    Https(HttpsBuilder),
    #[cfg(any(feature = "dot-native-tls", feature = "dot-rustls"))]
    /// HTTPS connection.
    Tls(TlsBuilder),
}

#[async_trait]
impl AsyncTryInto<Upstream> for UpstreamBuilder {
    /// Build the Upstream from an UpstreamBuilder
    async fn async_try_into(self) -> std::result::Result<Upstream, QHandleError> {
        Ok(match self {
            Self::Hybrid(v) => v.async_try_into().await?,

            // UDP Upstream
            Self::Udp(u) => u.async_try_into().await?,

            #[cfg(any(feature = "doh-rustls", feature = "doh-native-tls"))]
            Self::Https(h) => h.async_try_into().await?,

            #[cfg(any(feature = "dot-native-tls", feature = "dot-rustls"))]
            Self::Tls(t) => t.async_try_into().await?,
        })
    }

    type Error = QHandleError;
}
