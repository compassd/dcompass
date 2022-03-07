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

#[cfg(feature = "doh-rustls")]
mod rustls_cfgs {
    use once_cell::sync::Lazy;
    use rustls::{ClientConfig, OwnedTrustAnchor, RootCertStore};

    pub static NO_SNI_CLIENT_CFG: Lazy<ClientConfig> = Lazy::new(|| create_client_config(&false));
    pub static CLIENT_CFG: Lazy<ClientConfig> = Lazy::new(|| create_client_config(&true));

    fn create_client_config(sni: &bool) -> ClientConfig {
        let mut root_store = RootCertStore::empty();
        root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
            OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        }));

        let mut client_config = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        client_config.enable_sni = *sni; // Disable SNI on need.

        client_config
    }
}

#[cfg(feature = "doh-native-tls")]
mod native_tls_cfgs {
    use native_tls::TlsConnector;
    use once_cell::sync::Lazy;

    pub static NO_SNI_CLIENT_CFG: Lazy<TlsConnector> =
        Lazy::new(|| TlsConnector::builder().use_sni(false).build().unwrap());
    pub static CLIENT_CFG: Lazy<TlsConnector> = Lazy::new(|| TlsConnector::new().unwrap());
}

#[cfg(feature = "doh-rustls")]
use rustls_cfgs::{CLIENT_CFG, NO_SNI_CLIENT_CFG};

#[cfg(feature = "doh-native-tls")]
use native_tls_cfgs::{CLIENT_CFG, NO_SNI_CLIENT_CFG};

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

/// Client instance for UDP connections
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
            .use_preconfigured_tls(if sni {
                CLIENT_CFG.clone()
            } else {
                NO_SNI_CLIENT_CFG.clone()
            })
            .https_only(true)
            .user_agent(APP_USER_AGENT)
            .connect_timeout(Duration::from_secs(3))
            // Disable the inner connection pool
            .pool_max_idle_per_host(0);

        // Add proxy
        let client = if let Some(proxy) = proxy {
            client.proxy(Proxy::all(proxy)?)
        } else {
            client
        };

        Ok(Self {
            client: PostClient(
                client.build().map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "TLS backend failed to initialize",
                    )
                })?,
                uri.clone(),
            ),
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
}
