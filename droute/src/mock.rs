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

//! This module is NOT intended to be used by regular users. It is used for mocking purpose only.
use bytes::Bytes;
use domain::base::Message;
use std::net::SocketAddr;
use tokio::net::UdpSocket;

/// Mock echo server
pub struct Server {
    socket: UdpSocket,
    buf: Vec<u8>,
    to_send: Option<SocketAddr>,
}

impl Server {
    /// Create a new mock server
    pub fn new(socket: UdpSocket, buf: Vec<u8>, to_send: Option<SocketAddr>) -> Self {
        Self {
            socket,
            buf,
            to_send,
        }
    }

    /// Run it
    pub async fn run(self, msg: Message<Bytes>) -> Result<(), std::io::Error> {
        let Server {
            socket,
            mut buf,
            mut to_send,
        } = self;

        loop {
            // First we check to see if there's a message we need to echo back.
            // If so then we try to send it back to the original source, waiting
            // until it's writable and we're able to do so.
            if let Some(peer) = to_send {
                socket.send_to(&msg.as_slice(), &peer).await?;
            }

            // If we're here then `to_send` is `None`, so we take a look for the
            // next message we're going to echo back.
            to_send = Some(socket.recv_from(&mut buf).await?.1);
        }
    }
}
