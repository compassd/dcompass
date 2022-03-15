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

use super::{ConnInitiator, QHandle, Result};
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
pub use connector::Tls;
use connector::TlsStream;
use deadpool::managed::{self, RecycleError};
use domain::base::Message;
use log::debug;
use std::time::Instant;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::Mutex,
};

// Instant: Time the connection established
// usize: Number of query sent
#[async_trait]
impl QHandle for (Mutex<(TlsStream<TcpStream>, Instant, usize)>, u64, usize) {
    async fn query(&self, msg: &Message<Bytes>) -> Result<Message<Bytes>> {
        let mut guard = self.0.lock().await;

        {
            // Sadly because of borrow checker issue we cannot increase our counter after we have sent all of our query.
            // We have sent our query once more
            guard.2 += 1;
        }

        let stream = &mut guard.0;

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
        // No matter when our last valid query was on, TCP connections all expire a certain amount of time after they were established.
        // This is because the server may have got a timeout timer set on our outgoing connections.
        // Moreover, most of the server has limit on the maximum number of query possible. We check it as well here
        let mut guard = self.0.lock().await;
        if guard.2 >= self.2 {
            guard.0.shutdown().await?;
            log::debug!("TlsStream has reached maximum number of queries that can be sent on the underlying persistent TCP connection.");
            return Err(RecycleError::StaticMessage("max reuse TCP queries reached"));
        }
        if guard.1.elapsed().as_millis() >= self.1.into() {
            guard.0.shutdown().await?;
            log::debug!("TlsStream has reached period dcompass will keep the underlying TCP persistent connections open.");
            return Err(RecycleError::StaticMessage("TCP reuse timeout reached"));
        }
        Ok(())
    }
}
