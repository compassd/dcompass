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
    create_client_config, Pool,
};
use async_trait::async_trait;
use std::net::SocketAddr;
use trust_dns_client::client::AsyncClient;
use trust_dns_rustls::tls_client_stream::tls_client_connect;

/// Client pool for DNS over TLS.
#[derive(Clone)]
pub struct Tls {
    name: String,
    addr: SocketAddr,
    no_sni: bool,
    pool: Pool<AsyncClient>,
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
            pool: Pool::new(),
        }
    }
}

#[async_trait]
impl ClientPool for Tls {
    async fn get_client(&self) -> Result<AsyncClient> {
        Ok(self.pool.get().unwrap_or({
            log::info!("HTTPS Client cache missed, creating a new one.");
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
        self.pool.put(c);
    }

    async fn renew(&self) -> Result<()> {
        // We don't need to renew anything cause if it errored out it won't be returned. Next time we are gonna create a new client on fly.
        Ok(())
    }
}
