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

use crate::MAX_LEN;

use super::{ConnInitiator, QHandle, Result};
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use domain::base::Message;
use std::net::SocketAddr;
use tokio::net::UdpSocket;

/// Client instance for UDP connections
#[derive(Clone)]
pub struct Udp {
    addr: SocketAddr,
}

impl Udp {
    /// Create a new UDP client creator instance. with the given remote server address.
    pub async fn new(addr: SocketAddr) -> Result<Self> {
        Ok(Self { addr })
    }
}

#[async_trait]
impl ConnInitiator for Udp {
    type Connection = UdpSocket;

    async fn create(&self) -> std::io::Result<Self::Connection> {
        let socket = UdpSocket::bind(bind_addr(self.addr.is_ipv4())).await?;
        socket.connect(self.addr).await?;
        Ok(socket)
    }

    fn conn_type(&self) -> &'static str {
        "UDP"
    }
}

fn bind_addr(is_ipv4: bool) -> SocketAddr {
    if is_ipv4 {
        ([0u8; 4], 0).into()
    } else {
        ([0u16; 8], 0).into()
    }
}

#[async_trait]
impl QHandle for UdpSocket {
    async fn query(&self, msg: &Message<Bytes>) -> Result<Message<Bytes>> {
        // Randomnize the message
        let mut msg = Message::from_octets(BytesMut::from(msg.as_slice()))?;
        msg.header_mut().set_random_id();
        let msg = msg.for_slice();

        self.send(msg.as_slice()).await?;

        loop {
            let mut buf = BytesMut::with_capacity(MAX_LEN);
            buf.resize(MAX_LEN, 0);
            let len = self.recv(&mut buf).await?;
            buf.resize(len, 0);

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

    async fn reusable(&self) -> bool {
        true
    }
}
