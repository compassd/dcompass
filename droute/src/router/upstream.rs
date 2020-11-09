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

mod client_cache;

use self::client_cache::ClientCache;
use crate::error::DrouteError;
use crate::error::Result;
use futures::future::select_ok;
use futures::future::FutureExt;
use hashbrown::HashMap;
use log::*;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tokio::time::timeout;
use tokio::time::Duration;
use trust_dns_client::{client::AsyncClient, op::Message};
use trust_dns_proto::xfer::dns_handle::DnsHandle;

#[derive(Serialize, Deserialize, Clone)]
pub enum UpstreamKind {
    Hybrid(Vec<usize>),
    Https {
        name: String,
        addr: SocketAddr,
        no_sni: bool,
    },
    // Drop TLS support until we figure out how to do without OpenSSL
    // Tls(String, SocketAddr),
    Udp(SocketAddr),
}

pub struct Upstreams {
    upstreams: HashMap<usize, Upstream>,
    clients: HashMap<usize, ClientCache>,
}

impl Upstreams {
    pub async fn new(upstreams: Vec<Upstream>) -> Result<Self> {
        let mut r = HashMap::new();
        let mut c = HashMap::new();
        for u in upstreams {
            r.insert(u.tag, u);
        }
        for (k, v) in r.iter() {
            c.insert(*k, ClientCache::new(v).await?);
        }
        Ok(Self {
            upstreams: r,
            clients: c,
        })
    }

    pub fn hybrid_check(&self) -> Result<bool> {
        for (tag, u) in self.upstreams.iter() {
            if let UpstreamKind::Hybrid(v) = &u.method {
                if v.is_empty() {
                    return Err(DrouteError::EmptyHybrid(*tag));
                }
                if let Some(t) = v.iter().find(|tag| self.exists(*tag).is_err()) {
                    return Err(DrouteError::MissingTag(*t));
                }
            }
        }
        Ok(true)
    }

    pub fn exists(&self, tag: &usize) -> Result<bool> {
        if self.upstreams.contains_key(tag) {
            Ok(true)
        } else {
            Err(DrouteError::MissingTag(*tag))
        }
    }

    async fn query(t: u64, mut client: AsyncClient, msg: Message) -> Result<Message> {
        let id = msg.id();
        let mut resp = Message::from(timeout(Duration::from_secs(t), client.send(msg)).await??);
        resp.set_id(id);
        Ok(resp)
    }

    async fn final_resolve(&self, tag: usize, msg: Message) -> Result<Message> {
        let u = self
            .upstreams
            .get(&tag)
            .ok_or_else(|| DrouteError::MissingTag(tag))?;
        // HashMap is created for every single upstream (including Hybrid) when `Upstreams` is created
        let cache = self.clients.get(&tag).unwrap();
        let client = cache.get_client(u).await?;
        let resp = Self::query(u.timeout, client.clone(), msg).await?;
        // If the response can be obtained sucessfully, we then push back the client to the queue
        info!("Pushing back client cache for tag {}", tag);
        cache.return_back(client);
        Ok(resp)
    }

    pub async fn resolve(&self, tag: usize, msg: Message) -> Result<Message> {
        let u = self
            .upstreams
            .get(&tag)
            .ok_or_else(|| DrouteError::MissingTag(tag))?;
        Ok(match &u.method {
            UpstreamKind::Hybrid(v) => {
                let v = v
                    .iter()
                    .map(|u| self.final_resolve(*u, msg.clone()).boxed());
                let (resp, _) = timeout(Duration::from_secs(u.timeout), select_ok(v)).await??;
                resp
            }
            _ => self.final_resolve(tag, msg).await?,
        })
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Upstream {
    pub tag: usize,
    pub method: UpstreamKind,
    pub cache_size: usize,
    pub timeout: u64,
}
