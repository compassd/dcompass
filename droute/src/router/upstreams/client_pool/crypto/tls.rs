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
    super::{ClientPool, Result},
    create_client_config,
};
use async_trait::async_trait;
use std::{
    collections::VecDeque,
    net::SocketAddr,
    sync::{Arc, Mutex},
};
use trust_dns_client::client::AsyncClient;
use trust_dns_rustls::tls_client_stream::tls_client_connect;

/// Client pool for DNS over TLS.
#[derive(Clone)]
pub struct Tls {
    name: String,
    addr: SocketAddr,
    no_sni: bool,
    pool: Arc<Mutex<VecDeque<AsyncClient>>>,
}

impl Tls {
    /// Create a new DNS over TLS client pool
    /// - `name`: the domain name of the server. e.g. `cloudflare-dns.com` for Cloudflare DNS.
    /// - `addr`: the address of the server. e.g. `1.1.1.1:853` for Cloudflare DNS.
    /// - `no_sni`: set to `true` to not send SNI. This is useful to bypass firewalls and censorships.
    pub fn new(name: String, addr: SocketAddr, no_sni: bool) -> Self {
        Self {
            name,
            addr,
            no_sni,
            pool: Arc::new(Mutex::new(VecDeque::new())),
        }
    }
}

#[async_trait]
impl ClientPool for Tls {
    async fn get_client(&self) -> Result<AsyncClient> {
        Ok({
            // This ensures during the lock, queue's state is unchanged. (We shall only lock once).
            let mut p = self.pool.lock().unwrap();
            if p.is_empty() {
                None
            } else {
                log::info!("TLS client cache hit");
                // queue is not empty
                Some(p.pop_front().unwrap())
            }
        }
        .unwrap_or({
            let (stream, sender) = tls_client_connect(
                self.addr,
                self.name.clone(),
                create_client_config(&self.no_sni),
            );
            let (client, bg) = AsyncClient::new(stream, Box::new(sender), None).await?;
            tokio::spawn(bg);
            client
        }))
    }

    async fn return_client(&self, c: AsyncClient) {
        let mut p = self.pool.lock().unwrap();
        p.push_back(c);
    }
}
