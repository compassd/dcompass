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

// Cache client to reuse client connections.

use super::{error::Result, Upstream, UpstreamKind};
#[cfg(feature = "crypto")]
use rustls::{ClientConfig, KeyLogFile, ProtocolVersion, RootCertStore};
#[cfg(feature = "tcp")]
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};
#[cfg(feature = "tcp")]
use tokio::net::TcpStream as TokioTcpStream;
use tokio::net::UdpSocket;
use trust_dns_client::{client::AsyncClient, udp::UdpClientStream};
#[cfg(feature = "doh")]
use trust_dns_https::HttpsClientStreamBuilder;
#[cfg(feature = "tcp")]
use trust_dns_proto::iocompat::AsyncIoTokioAsStd;
#[cfg(feature = "dot")]
use trust_dns_rustls::tls_client_stream::tls_client_connect;

#[cfg(feature = "crypto")]
const ALPN_H2: &[u8] = b"h2";

#[derive(Clone)]
pub enum ClientCache {
    // We should use sync Mutex implementation here, else the channel seems to fail if lock is presented across querying in `final_resolve` in Upstreams.
    #[cfg(feature = "doh")]
    Https(Arc<Mutex<VecDeque<AsyncClient>>>),
    #[cfg(feature = "doh")]
    Tls(Arc<Mutex<VecDeque<AsyncClient>>>),
    Udp(AsyncClient),
    // Create a type placeholder (currently used by hybrid), which doesn't implement any method other than `new`
    Placeholder,
}

impl ClientCache {
    pub async fn new(u: &Upstream) -> Result<Self> {
        Ok(match &u.method {
            // For UDP, we only use one client throughout the course.
            UpstreamKind::Udp(_) => Self::Udp(Self::create_client(u).await?),
            #[cfg(feature = "doh")]
            UpstreamKind::Https {
                name: _,
                addr: _,
                no_sni: _,
            } => Self::Https(Arc::new(Mutex::new(VecDeque::new()))),
            #[cfg(feature = "dot")]
            UpstreamKind::Tls {
                name: _,
                addr: _,
                no_sni: _,
            } => Self::Tls(Arc::new(Mutex::new(VecDeque::new()))),
            _ => Self::Placeholder,
        })
    }

    pub async fn get_client(&self, _u: &Upstream) -> Result<AsyncClient> {
        Ok(match self {
            #[cfg(feature = "crypto")]
            Self::Https(q) | Self::Tls(q) => {
                {
                    // This ensures during the lock, queue's state is unchanged. (We shall only lock once).
                    let mut q = q.lock().unwrap();
                    if q.is_empty() {
                        None
                    } else {
                        log::info!("HTTPS/TLS client cache hit");
                        // queue is not empty
                        Some(q.pop_front().unwrap())
                    }
                }
                .unwrap_or(Self::create_client(_u).await?)
            }
            // For UDP connections, it is pointless for us to cache as every `send` query would create a new socket. If we cache and pop it out, there would be endless client creation, resulting in rather low performance. (It takes me two days to realize)
            Self::Udp(c) => c.clone(),
            Self::Placeholder => unreachable!(),
        })
    }

    pub fn return_back(&self, _c: AsyncClient) {
        match self {
            #[cfg(feature = "crypto")]
            Self::Https(q) | Self::Tls(q) => {
                let mut q = q.lock().unwrap();
                q.push_back(_c);
            }
            Self::Udp(_) => {}
            Self::Placeholder => unreachable!(),
        }
    }

    // Create client config for TLS and HTTPS clients
    #[cfg(feature = "crypto")]
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

    async fn create_client(u: &Upstream) -> Result<AsyncClient> {
        Ok(match &u.method {
            UpstreamKind::Udp(s) => {
                let stream = UdpClientStream::<UdpSocket>::new(*s);
                let (client, bg) = AsyncClient::connect(stream).await?;
                tokio::spawn(bg);
                client
            }
            #[cfg(feature = "dot")]
            UpstreamKind::Tls { name, addr, no_sni } => {
                let (stream, sender) =
                    tls_client_connect(*addr, name.to_string(), Self::create_client_config(no_sni));
                let (client, bg) = AsyncClient::new(stream, Box::new(sender), None).await?;
                tokio::spawn(bg);
                client
            }
            #[cfg(feature = "doh")]
            UpstreamKind::Https { name, addr, no_sni } => {
                let stream = HttpsClientStreamBuilder::with_client_config(
                    Self::create_client_config(no_sni),
                )
                .build::<AsyncIoTokioAsStd<TokioTcpStream>>(*addr, name.to_string());
                let (client, bg) = AsyncClient::connect(stream).await?;
                tokio::spawn(bg);
                client
            }
            _ => unreachable!(),
        })
    }
}
