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
use crate::error::DrouteError;
use crate::error::Result;
use log::*;
use std::collections::VecDeque;
use std::sync::Mutex;
use tokio::net::TcpStream as TokioTcpStream;
use tokio::net::UdpSocket;
use trust_dns_client::{client::AsyncClient, udp::UdpClientStream};
use trust_dns_https::HttpsClientStreamBuilder;
use trust_dns_proto::iocompat::AsyncIo02As03;

const ALPN_H2: &[u8] = b"h2";

pub enum ClientCache {
    // We should use sync Mutex implementation here, else the channel seems to fail if lock is presented across querying in `final_resolve` in Upstreams.
    Https(Mutex<VecDeque<AsyncClient>>),
    Udp(AsyncClient),
    // Create a type placeholder (currently used by hybrid), which doesn't implement any method other than `new`
    Placeholder,
}

impl ClientCache {
    pub async fn new(u: &Upstream) -> Result<Self> {
        Ok(match &u.method {
            // For UDP, we only use one client throughout the course.
            UpstreamKind::Udp(_) => Self::Udp(Self::create_client(u).await?),
            UpstreamKind::Https {
                name: _,
                addr: _,
                no_sni: _,
            } => Self::Https(Mutex::new(VecDeque::new())),
            _ => Self::Placeholder,
        })
    }

    pub async fn get_client(&self, u: &Upstream) -> Result<AsyncClient> {
        Ok(match self {
            Self::Https(q) => {
                if q.lock().unwrap().is_empty() {
                    Self::create_client(u).await?
                } else {
                    let mut q = q.lock().unwrap();
                    info!("HTTPS client cache hit");
                    // queue is not empty
                    q.pop_front().unwrap()
                }
            }
            // For UDP connections, it is pointless for us to cache as every `send` query would create a new socket. If we cache and pop it out, there would be endless client creation, resulting in rather low performance. (It takes me two days to realize)
            Self::Udp(c) => c.clone(),
            _ => unreachable!(),
        })
    }

    pub fn return_back(&self, c: AsyncClient) {
        match self {
            Self::Https(q) => {
                let mut q = q.lock().unwrap();
                q.push_back(c);
            }
            Self::Udp(_) => {}
            _ => unreachable!(),
        }
    }

    async fn create_client(u: &Upstream) -> Result<AsyncClient> {
        Ok(match &u.method {
            UpstreamKind::Udp(s) => {
                let stream = UdpClientStream::<UdpSocket>::new(*s);
                let (client, bg) = AsyncClient::connect(stream).await?;
                tokio::spawn(bg);
                client
            }
            UpstreamKind::Https { name, addr, no_sni } => {
                use rustls::{ClientConfig, KeyLogFile, ProtocolVersion, RootCertStore};
                use std::sync::Arc;

                let mut root_store = RootCertStore::empty();
                root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
                let versions = vec![ProtocolVersion::TLSv1_2];

                let mut client_config = ClientConfig::new();
                client_config.root_store = root_store;
                client_config.versions = versions;
                client_config.alpn_protocols.push(ALPN_H2.to_vec());
                client_config.key_log = Arc::new(KeyLogFile::new());
                client_config.enable_sni = !no_sni; // Disable SNI on need.

                let client_config = Arc::new(client_config);

                let stream = HttpsClientStreamBuilder::with_client_config(client_config)
                    .build::<AsyncIo02As03<TokioTcpStream>>(*addr, name.to_string());
                let (client, bg) = AsyncClient::connect(stream).await?;
                tokio::spawn(bg);
                client
            }
            // We don't create client for Hybrid
            _ => return Err(DrouteError::HybridRecursion),
        })
    }
}
