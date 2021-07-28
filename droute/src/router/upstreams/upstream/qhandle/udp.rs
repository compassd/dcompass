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

use super::{QHandle, Result};
use async_trait::async_trait;
use bb8::{ManageConnection, Pool};
use bytes::Bytes;
use domain::base::Message;
use std::{net::SocketAddr, time::Duration};
use tokio::{net::UdpSocket, time::timeout};

struct ConnPool {
    pub addr: SocketAddr,
}

#[async_trait]
impl ManageConnection for ConnPool {
    type Connection = UdpSocket;

    type Error = std::io::Error;

    async fn connect(&self) -> std::result::Result<Self::Connection, Self::Error> {
        let socket = UdpSocket::bind(bind_addr(self.addr.is_ipv4())).await?;
        socket.connect(self.addr).await?;
        Ok(socket)
    }

    async fn is_valid(
        &self,
        _conn: &mut bb8::PooledConnection<'_, Self>,
    ) -> std::result::Result<(), Self::Error> {
        Ok(())
    }

    fn has_broken(&self, _conn: &mut Self::Connection) -> bool {
        false
    }
}

/// Client instance for UDP connections
#[derive(Clone)]
pub struct Udp {
    pool: Pool<ConnPool>,
    timeout: Duration,
}

impl Udp {
    /// Create a new UDP client creator instance. with the given remote server address.
    pub async fn new(addr: SocketAddr, timeout: Duration) -> Result<Self> {
        Ok(Self {
            pool: {
                bb8::Pool::builder()
                    .test_on_check_out(false)
                    .max_size(15)
                    .idle_timeout(Some(Duration::from_secs(2 * 60)))
                    .max_lifetime(Some(Duration::from_secs(10 * 60)))
                    .build(ConnPool { addr })
                    .await?
            },
            timeout,
        })
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
impl QHandle for Udp {
    async fn query(&self, msg: &Message<Bytes>) -> Result<Message<Bytes>> {
        let socket = self.pool.get().await?;
        socket.send(msg.as_slice()).await?;

        timeout(self.timeout, async {
            loop {
                let mut buf = [0; 1232];
                let len = socket.recv(&mut buf).await?;

                // We ignore garbage since there is a timer on this whole thing.
                let answer = match Message::from_octets(Bytes::copy_from_slice(&buf[..len])) {
                    Ok(answer) => answer,
                    Err(_) => continue,
                };
                if !answer.is_answer(&msg) {
                    continue;
                }
                return Ok(answer);
            }
        })
        .await?
    }
}
