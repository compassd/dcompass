// Copyright 2022 LEXUGE
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

use super::{ConnInitiator, Result};
use async_trait::async_trait;
use rustls::{ClientConfig, OwnedTrustAnchor, RootCertStore};
use socket2::{Socket, TcpKeepalive};
use std::{net::SocketAddr, sync::Arc, time::Instant};
use tokio::{net::TcpStream, sync::Mutex};
pub use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

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

/// Client instance for TLS connections
#[derive(Clone)]
pub struct Tls {
    client: TlsConnector,
    addr: SocketAddr,
    domain: String,
    tcp_reuse_timeout: u64,
    max_reuse_tcp_queries: usize,
}

impl Tls {
    /// Create a new TLS connection creator instance. with the given remote server address.
    pub fn new(
        domain: String,
        addr: SocketAddr,
        sni: bool,
        tcp_reuse_timeout: u64,
        max_reuse_tcp_queries: usize,
    ) -> Result<Self> {
        Ok(Self {
            client: TlsConnector::from(Arc::new(create_client_config(&sni))),
            addr,
            domain,
            tcp_reuse_timeout,
            max_reuse_tcp_queries,
        })
    }
}

#[async_trait]
impl ConnInitiator for Tls {
    type Connection = (Mutex<(TlsStream<TcpStream>, Instant, usize)>, u64, usize);

    async fn create(&self) -> std::io::Result<Self::Connection> {
        let mut stream = TcpStream::connect(self.addr).await?;

        // Good default as reqwest also sets this.
        let keepalive = TcpKeepalive::new().with_time(std::time::Duration::from_secs(60));
        let socket: Socket = stream.into_std()?.into();
        socket.set_tcp_keepalive(&keepalive)?;
        stream = TcpStream::from_std(socket.into())?;

        let domain = rustls::ServerName::try_from(self.domain.as_str()).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid dnsname")
        })?;
        Ok((
            Mutex::new((
                self.client
                    .connect(domain, stream)
                    .await
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::WouldBlock, e))?,
                Instant::now(),
                0,
            )),
            self.tcp_reuse_timeout,
            self.max_reuse_tcp_queries,
        ))
    }

    fn conn_type(&self) -> &'static str {
        "TLS"
    }
}
