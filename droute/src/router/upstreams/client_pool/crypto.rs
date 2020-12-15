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

// This file is under feature gate `crypto`.

use super::{ClientPool, Result};
use async_trait::async_trait;
use rustls::{ClientConfig, KeyLogFile, ProtocolVersion, RootCertStore};
use std::{
    collections::VecDeque,
    net::SocketAddr,
    sync::{Arc, Mutex},
};
#[cfg(feature = "doh")]
use tokio::net::TcpStream as TokioTcpStream;
use trust_dns_client::client::AsyncClient;
#[cfg(feature = "doh")]
use trust_dns_https::HttpsClientStreamBuilder;
#[cfg(feature = "doh")]
use trust_dns_proto::iocompat::AsyncIoTokioAsStd;
#[cfg(feature = "dot")]
use trust_dns_rustls::tls_client_stream::tls_client_connect;

const ALPN_H2: &[u8] = b"h2";

// Create client config for TLS and HTTPS clients
fn create_client_config(no_sni: &bool) -> Arc<ClientConfig> {
    let mut root_store = RootCertStore::empty();
    root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
    let versions = vec![ProtocolVersion::TLSv1_2];

    let mut client_config = ClientConfig::new();
    client_config.root_store = root_store;
    client_config.versions = versions;
    client_config.alpn_protocols.push(ALPN_H2.to_vec());
    client_config.key_log = Arc::new(KeyLogFile::new());
    client_config.enable_sni = !no_sni; // Disable SNI on need.

    Arc::new(client_config)
}

/// Client pool for DNS over HTTPS.
#[derive(Clone)]
#[cfg(feature = "doh")]
pub struct Https {
    name: String,
    addr: SocketAddr,
    no_sni: bool,
    pool: Arc<Mutex<VecDeque<AsyncClient>>>,
}

#[cfg(feature = "doh")]
impl Https {
    /// Create a new DNS over HTTPS client pool
    /// - `name`: the domain name of the server. e.g. `cloudflare-dns.com` for Cloudflare DNS.
    /// - `addr`: the address of the server. e.g. `1.1.1.1:443` for Cloudflare DNS.
    /// - `no_sni`: set to `true` to not send SNI. This is useful to bypass firewalls and censorships.
    pub fn new(name: String, addr: SocketAddr, no_sni: bool) -> Self {
        Self {
            name,
            addr,
            no_sni,
            pool: Arc::new(Mutex::new(VecDeque::new())),
        }
    }
}

#[cfg(feature = "doh")]
#[async_trait]
impl ClientPool for Https {
    async fn get_client(&self) -> Result<AsyncClient> {
        Ok({
            // This ensures during the lock, queue's state is unchanged. (We shall only lock once).
            let mut p = self.pool.lock().unwrap();
            if p.is_empty() {
                None
            } else {
                log::info!("HTTPS client cache hit");
                // queue is not empty
                Some(p.pop_front().unwrap())
            }
        }
        .unwrap_or({
            let stream =
                HttpsClientStreamBuilder::with_client_config(create_client_config(&self.no_sni))
                    .build::<AsyncIoTokioAsStd<TokioTcpStream>>(self.addr, self.name.clone());
            let (client, bg) = AsyncClient::connect(stream).await?;
            tokio::spawn(bg);
            client
        }))
    }

    async fn return_client(&self, c: AsyncClient) {
        let mut p = self.pool.lock().unwrap();
        p.push_back(c);
    }
}

/// Client pool for DNS over TLS.
#[derive(Clone)]
#[cfg(feature = "dot")]
pub struct Tls {
    name: String,
    addr: SocketAddr,
    no_sni: bool,
    pool: Arc<Mutex<VecDeque<AsyncClient>>>,
}

#[cfg(feature = "dot")]
impl Tls {
    /// Create a new DNS over TLS client pool
    /// - `name`: the domain name of the server. e.g. `cloudflare-dns.com` for Cloudflare DNS.
    /// - `addr`: the address of the server. e.g. `1.1.1.1:853` for Cloudflare DNS.
    /// - `no_sni`: set to `true` to not send SNI. This is useful to bypass firewalls and censorships.
    pub fn new(name: String, addr: SocketAddr, no_sni: bool) -> Self {
        Self {
            name,
            addr,
            no_sni,
            pool: Arc::new(Mutex::new(VecDeque::new())),
        }
    }
}

#[cfg(feature = "dot")]
#[async_trait]
impl ClientPool for Tls {
    async fn get_client(&self) -> Result<AsyncClient> {
        Ok({
            // This ensures during the lock, queue's state is unchanged. (We shall only lock once).
            let mut p = self.pool.lock().unwrap();
            if p.is_empty() {
                None
            } else {
                log::info!("HTTPS client cache hit");
                // queue is not empty
                Some(p.pop_front().unwrap())
            }
        }
        .unwrap_or({
            let (stream, sender) = tls_client_connect(
                self.addr,
                self.name.clone(),
                create_client_config(&self.no_sni),
            );
            let (client, bg) = AsyncClient::new(stream, Box::new(sender), None).await?;
            tokio::spawn(bg);
            client
        }))
    }

    async fn return_client(&self, c: AsyncClient) {
        let mut p = self.pool.lock().unwrap();
        p.push_back(c);
    }
}
