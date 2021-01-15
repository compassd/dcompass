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

use super::{
    super::client_pool::{ClientPool, Result},
    Pool,
};
use async_trait::async_trait;
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use trust_dns_client::{client::AsyncClient, udp::UdpClientStream};

/// Client pool for UDP connections
#[derive(Clone)]
pub struct Udp {
    addr: SocketAddr,
    // We are using client pool for UDP connection here bacause trust-dns seems have irrecoverable underlying channel congestion once the channel is full. Therefore, we have to drop client in order to recover the service.
    pool: Pool<AsyncClient>,
}

impl Udp {
    /// Create a new UDP client pool with the given remote server address.
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            pool: Pool::new(),
        }
    }
}

#[async_trait]
impl ClientPool for Udp {
    async fn get_client(&self) -> Result<AsyncClient> {
        Ok(self.pool.get().unwrap_or({
            log::info!("UDP Client cache missed, creating a new one.");
            let stream = UdpClientStream::<UdpSocket>::new(self.addr);
            let (client, bg) = AsyncClient::connect(stream).await?;
            tokio::spawn(bg);
            client
        }))
    }

    async fn return_client(&self, c: AsyncClient) {
        self.pool.put(c);
    }
}
