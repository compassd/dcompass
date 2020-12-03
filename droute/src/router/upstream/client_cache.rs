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

use super::{Upstream, UpstreamKind};
use crate::error::Result;
use log::*;
use rustls::{ClientConfig, KeyLogFile, ProtocolVersion, RootCertStore};
use std::{
    collections::VecDeque,
    fmt::{Debug, Display},
    hash::Hash,
    sync::{Arc, Mutex},
};
use tokio::net::{TcpStream as TokioTcpStream, UdpSocket};
use trust_dns_client::{client::AsyncClient, udp::UdpClientStream};
use trust_dns_https::HttpsClientStreamBuilder;
use trust_dns_proto::iocompat::AsyncIoTokioAsStd;
use trust_dns_rustls::tls_client_stream::tls_client_connect;

const ALPN_H2: &[u8] = b"h2";

#[derive(Clone)]
pub enum ClientCache {
    // We should use sync Mutex implementation here, else the channel seems to fail if lock is presented across querying in `final_resolve` in Upstreams.
    Https(Arc<Mutex<VecDeque<AsyncClient>>>),
    Tls(Arc<Mutex<VecDeque<AsyncClient>>>),
    Udp(AsyncClient),
    // Create a type placeholder (currently used by hybrid), which doesn't implement any method other than `new`
    Placeholder,
}

impl ClientCache {
    pub async fn new<L>(u: &Upstream<L>) -> Result<L, Self>
    where
        L: Display + Debug + Eq + Hash + Send + Clone + Sync,
    {
        Ok(match &u.method {
            // For UDP, we only use one client throughout the course.
            UpstreamKind::Udp(_) => Self::Udp(Self::create_client(u).await?),
            UpstreamKind::Https {
                name: _,
                addr: _,
                no_sni: _,
            } => Self::Https(Arc::new(Mutex::new(VecDeque::new()))),
            UpstreamKind::Tls {
                name: _,
                addr: _,
                no_sni: _,
            } => Self::Tls(Arc::new(Mutex::new(VecDeque::new()))),
            _ => Self::Placeholder,
        })
    }

    pub async fn get_client<L>(&self, u: &Upstream<L>) -> Result<L, AsyncClient>
    where
        L: Display + Debug + Eq + Hash + Send + Clone + Sync,
    {
        Ok(match self {
            Self::Https(q) | Self::Tls(q) => {
                // Using closed TCP socket seems to be an fatal issue on Windows, see https://github.com/LEXUGE/dcompass/issues/2.
                (if cfg!(windows) {
                    None
                } else {
                    // This ensures during the lock, queue's state is unchanged. (We shall only lock once).
                    let mut q = q.lock().unwrap();
                    if q.is_empty() {
                        None
                    } else {
                        info!("HTTPS/TLS client cache hit");
                        // queue is not empty
                        Some(q.pop_front().unwrap())
                    }
                })
                .unwrap_or(Self::create_client(u).await?)
            }
            // For UDP connections, it is pointless for us to cache as every `send` query would create a new socket. If we cache and pop it out, there would be endless client creation, resulting in rather low performance. (It takes me two days to realize)
            Self::Udp(c) => c.clone(),
            Self::Placeholder => unreachable!(),
        })
    }

    pub fn return_back(&self, c: AsyncClient) {
        match self {
            Self::Https(q) | Self::Tls(q) => {
                if !cfg!(windows) {
                    let mut q = q.lock().unwrap();
                    q.push_back(c);
                }
            }
            Self::Udp(_) => {}
            Self::Placeholder => unreachable!(),
        }
    }

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

    async fn create_client<L>(u: &Upstream<L>) -> Result<L, AsyncClient>
    where
        L: Display + Debug + Eq + Hash + Send + Clone + Sync,
    {
        Ok(match &u.method {
            UpstreamKind::Udp(s) => {
                let stream = UdpClientStream::<UdpSocket>::new(*s);
                let (client, bg) = AsyncClient::connect(stream).await?;
                tokio::spawn(bg);
                client
            }
            UpstreamKind::Tls { name, addr, no_sni } => {
                let (stream, sender) =
                    tls_client_connect(*addr, name.to_string(), Self::create_client_config(no_sni));
                let (client, bg) = AsyncClient::new(stream, Box::new(sender), None).await?;
                tokio::spawn(bg);
                client
            }
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
