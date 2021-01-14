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
use std::{
    collections::VecDeque,
    net::SocketAddr,
    sync::{Arc, Mutex},
};
use tokio::net::UdpSocket;
use trust_dns_client::{client::AsyncClient, udp::UdpClientStream};

/// Client pool for UDP connections
#[derive(Clone)]
pub struct Udp {
    addr: SocketAddr,
    // We are using client pool for UDP connection here bacause trust-dns seems have irrecoverable underlying channel congestion once the channel is full. Therefore, we have to drop client in order to recover the service.
    pool: Arc<Mutex<VecDeque<AsyncClient>>>,
}

impl Udp {
    /// Create a new UDP client pool with the given remote server address.
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            pool: Arc::new(Mutex::new(VecDeque::new())),
        }
    }
}

#[async_trait]
impl ClientPool for Udp {
    async fn get_client(&self) -> Result<AsyncClient> {
        Ok({
            // This ensures during the lock, queue's state is unchanged. (We shall only lock once).
            let mut p = self.pool.lock().unwrap();
            if p.is_empty() {
                None
            } else {
                log::info!("UDP client cache hit");
                // queue is not empty
                Some(p.pop_front().unwrap())
            }
        }
        .unwrap_or({
            let stream = UdpClientStream::<UdpSocket>::new(self.addr);
            let (client, bg) = AsyncClient::connect(stream).await?;
            tokio::spawn(bg);
            client
        }))
    }
    async fn return_client(&self, c: AsyncClient) {
        let mut p = self.pool.lock().unwrap();
        p.push_back(c);
    }
}
