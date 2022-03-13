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

use super::{ConnInitiator, QHandle, Result};
use crate::router::upstreams::QHandleError;
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use domain::base::Message;
use log::debug;
use native_tls::{Protocol, TlsConnector as NativeTlsConnector};
use std::net::SocketAddr;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::Mutex,
};
use tokio_native_tls::{TlsConnector, TlsStream};

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
        let stream = TcpStream::connect(self.addr).await?;
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

        // TODO: we are unable to manage connections well currently.
        stream.shutdown().await?;

        // We ignore garbage since there is a timer on this whole thing.
        let answer = Message::from_octets(buf.into())?;
        if !answer.is_answer(&msg) {
            Err(QHandleError::NotAnswer)
        } else {
            Ok(answer)
        }
    }

    async fn reusable(&self) -> bool {
        false
    }
}
