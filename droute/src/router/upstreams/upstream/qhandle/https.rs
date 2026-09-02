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

use super::{ConnInitiator, QHandle, QHandleError, Result};
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use domain::base::Message;
use reqwest::{Client, Proxy, Url};
use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
    time::Duration,
};

/// Client instance for HTTPS connections
#[derive(Clone)]
pub struct Https {
    client: PostClient,
}

static APP_USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"),);

impl Https {
    /// Create a new HTTPS client creator instance. with the given remote server address.
    // We *CANNOT* reuse the client *WITH* connection pool because if the network changes, *connection* inside client pool of each client remains the same, and cloning them inevitably leads to no reconnection but using stale connections.
    // However, we are able to disable the connection pool and use the client.
    // We cannot store ClientBuilder because it is not Clone.
    pub async fn new(uri: String, addr: IpAddr, proxy: Option<String>, sni: bool) -> Result<Self> {
        let uri = Url::from_str(&uri).map_err(|_| QHandleError::InvalidUri(uri))?;
        // Check domain validness
        let _ = uri
            .domain()
            .ok_or_else(|| QHandleError::InvalidDomain(uri.clone()))?;

        // This has already been checked and it is safe to unwrap
        let domain = uri.domain().unwrap();
        let client = Client::builder()
            // The port in socket addr doesn't take effect here per documentation
            .resolve(domain, SocketAddr::new(addr, 0))
            .https_only(true)
            .user_agent(APP_USER_AGENT)
            .connect_timeout(Duration::from_secs(3))
            // Disable the inner connection pool
            .pool_max_idle_per_host(0)
            .tls_sni(sni);

        // Let reqwest initialize the TLS backend with the exact feature/version
        // that reqwest itself was compiled with.  Passing droute's own
        // preconfigured rustls/native-tls connector into reqwest can fail because
        // the connector type must match reqwest's internal TLS dependency.
        #[cfg(feature = "doh-rustls")]
        let client = client.use_rustls_tls();
        #[cfg(feature = "doh-native-tls")]
        let client = client.use_native_tls();

        // Add proxy
        let client = if let Some(proxy) = proxy {
            client.proxy(Proxy::all(proxy)?)
        } else {
            client
        };

        Ok(Self {
            client: PostClient(client.build()?, uri.clone()),
        })
    }
}

#[async_trait]
impl ConnInitiator for Https {
    type Connection = PostClient;

    async fn create(&self) -> std::io::Result<Self::Connection> {
        Ok(self.client.clone())
    }

    fn conn_type(&self) -> &'static str {
        "HTTPS"
    }
}

#[derive(Clone)]
pub struct PostClient(Client, Url);

#[async_trait]
impl QHandle for PostClient {
    async fn query(&self, msg: &Message<Bytes>) -> Result<Message<Bytes>> {
        // Per RFC, the message ID should be set to 0 to better facilitate HTTPS caching.
        let mut msg = Message::from_octets(BytesMut::from(msg.as_slice()))?;
        msg.header_mut().set_id(0);

        let body: reqwest::Body = msg.into_octets().freeze().into();
        let res = self
            .0
            .post(self.1.clone())
            .header("content-type", "application/dns-message")
            .body(body)
            .send()
            .await?;

        if res.status().is_success() {
            let res = res.bytes().await?;
            let answer = Message::from_octets(res)?;
            Ok(answer)
        } else {
            Err(QHandleError::FailedHttp(res.status()))
        }
    }

    async fn reusable(&self) -> deadpool::managed::RecycleResult<std::io::Error> {
        Ok(())
    }
}
