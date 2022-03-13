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

use super::{ConnInitiator, QHandle, Result, DUMMY_QUERY};
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use deadpool::managed::{self, RecycleError};
use domain::base::Message;
use log::debug;
use rustls::{ClientConfig, OwnedTrustAnchor, RootCertStore};
use socket2::{Socket, TcpKeepalive};
use std::{net::SocketAddr, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::Mutex,
};
use tokio_rustls::{client::TlsStream, TlsConnector};

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
}

impl Tls {
    /// Create a new TLS connection creator instance. with the given remote server address.
    pub fn new(domain: String, addr: SocketAddr, sni: bool) -> Result<Self> {
        Ok(Self {
            client: TlsConnector::from(Arc::new(create_client_config(&sni))),
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

        let keepalive = TcpKeepalive::new().with_time(std::time::Duration::from_secs(3));
        let socket: Socket = stream.into_std()?.into();
        socket.set_tcp_keepalive(&keepalive)?;
        stream = TcpStream::from_std(socket.into())?;

        let domain = rustls::ServerName::try_from(self.domain.as_str()).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid dnsname")
        })?;
        Ok(Mutex::new(
            self.client
                .connect(domain, stream)
                .await
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::WouldBlock, e))?,
        ))
    }

    fn conn_type(&self) -> &'static str {
        "TLS"
    }
}

#[async_trait]
impl QHandle for Mutex<TlsStream<TcpStream>> {
    async fn query(&self, msg: &Message<Bytes>) -> Result<Message<Bytes>> {
        let mut stream = self.lock().await;

        // Randomnize the message
        let mut msg = Message::from_octets(BytesMut::from(msg.as_slice()))?;
        msg.header_mut().set_random_id();
        let msg = msg.for_slice();

        // Prefix our payload with length per RFC.
        let mut payload = BytesMut::new();
        let len = u16::try_from(msg.as_slice().len())
            .expect("request too long")
            .to_be_bytes();
        payload.extend_from_slice(&len);
        payload.extend_from_slice(msg.as_slice());
        let payload = payload.freeze();

        // Write all of our query
        stream.write_all(&payload).await?;
        stream.flush().await?;

        debug!("TlsStream wrote all of the prefixed query");

        loop {
            // Get the length of the response
            let mut len = [0; 2];
            stream.read_exact(&mut len).await?;
            let len = u16::from_be_bytes(len);

            debug!("TlsStream got response length: {} bytes", len);

            // Read the response
            let mut buf = BytesMut::with_capacity(len.into());
            buf.resize(len.into(), 0);
            stream.read_exact(&mut buf).await?;

            debug!("TlsStream received {:?}", buf);

            // We ignore garbage since there is a timer on this whole thing.
            let answer = match Message::from_octets(buf.freeze()) {
                Ok(answer) => answer,
                Err(_) => continue,
            };
            if !answer.is_answer(&msg) {
                continue;
            }
            return Ok(answer);
        }
    }

    async fn reusable(&self) -> managed::RecycleResult<std::io::Error> {
        // For TCP streams, it is possible to have it being writable but not readable.
        // Upon those situations, merely sending the query doesn't suffice our testing purpose.
        // Therefore, it's better to conduct a full test
        self.query(&DUMMY_QUERY.clone())
            .await
            .map(|_| {
                log::debug!("reusable test successfully completed");
            })
            .map_err(|_| RecycleError::StaticMessage("test query failed"))
    }
}
