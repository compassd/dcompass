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

use super::super::client_pool::{ClientPool, Result};
use async_trait::async_trait;
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use trust_dns_client::{client::AsyncClient, udp::UdpClientStream};

/// Client pool for UDP connections
#[derive(Clone)]
pub struct Udp {
    client: AsyncClient,
}

impl Udp {
    /// Create a new UDP client pool with the given remote server address.
    pub async fn new(addr: &SocketAddr) -> Result<Self> {
        let stream = UdpClientStream::<UdpSocket>::new(*addr);
        let (client, bg) = AsyncClient::connect(stream).await?;
        tokio::spawn(bg);
        Ok(Self { client })
    }
}

#[async_trait]
impl ClientPool for Udp {
    async fn get_client(&self) -> Result<AsyncClient> {
        Ok(self.client.clone())
    }
    async fn return_client(&self, _: AsyncClient) {}
}
