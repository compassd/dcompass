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
use native_tls::{Protocol, TlsConnector as NativeTlsConnector};
use socket2::{Socket, TcpKeepalive};
use std::net::SocketAddr;
use tokio::{net::TcpStream, sync::Mutex};
use tokio_native_tls::TlsConnector;
pub use tokio_native_tls::TlsStream;

/// Client instance for TLS connections
#[derive(Clone)]
pub struct Tls {
    client: TlsConnector,
    addr: SocketAddr,
    domain: String,
}

impl Tls {
    /// Create a new TLS connection creator instance. with the given remote server address.
    pub fn new(domain: String, addr: SocketAddr, sni: bool) -> Result<Self> {
        Ok(Self {
            client: NativeTlsConnector::builder()
                .use_sni(sni)
                .min_protocol_version(Some(Protocol::Tlsv12))
                .build()?
                .into(),
            addr,
            domain,
        })
    }
}

#[async_trait]
impl ConnInitiator for Tls {
    type Connection = Mutex<TlsStream<TcpStream>>;

    async fn create(&self) -> std::io::Result<Self::Connection> {
        let mut stream = TcpStream::connect(self.addr).await?;

        // Good default as reqwest also sets this
        let keepalive = TcpKeepalive::new().with_time(std::time::Duration::from_secs(60));
        let socket: Socket = stream.into_std()?.into();
        socket.set_tcp_keepalive(&keepalive)?;
        stream = TcpStream::from_std(socket.into())?;

        Ok(Mutex::new(
            self.client
                .connect(&self.domain, stream)
                .await
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::WouldBlock, e))?,
        ))
    }

    fn conn_type(&self) -> &'static str {
        "TLS"
    }
}
