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

#[cfg_attr(feature = "dot-native-tls", path = "native_tls.rs")]
#[cfg_attr(feature = "dot-rustls", path = "rustls.rs")]
#[cfg(any(feature = "dot-rustls", feature = "dot-native-tls"))]
mod connector;

use super::{ConnInitiator, QHandle, Result, DUMMY_QUERY};
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
pub use connector::Tls;
use connector::TlsStream;
use deadpool::managed::{self, RecycleError};
use domain::base::Message;
use log::debug;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::Mutex,
};

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
            let len: usize = u16::from_be_bytes(len).into();

            debug!("TlsStream got response length: {} bytes", len);

            // Read the response
            let mut buf = BytesMut::with_capacity(len);
            buf.resize(len, 0);
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
        // Remote host can close a connection after a timeout set by it.
        // Remote can also close connection after responding to up to a certain number of requests sent by us.
        // It's better to conduct a full test.
        match self.query(&DUMMY_QUERY.clone()).await {
            Ok(_) => {
                log::debug!("reusable test successfully completed");
                Ok(())
            }
            Err(_) => {
                // Shutdown the underlying stream
                self.lock().await.shutdown().await?;
                Err(RecycleError::StaticMessage("test query failed"))
            }
        }
    }
}
