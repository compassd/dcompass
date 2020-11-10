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
mod resp_cache;

use self::client_cache::ClientCache;
use self::resp_cache::RespCache;
use crate::error::DrouteError;
use crate::error::Result;
use dmatcher::Label;
use futures::future::select_ok;
use futures::future::FutureExt;
use hashbrown::HashMap;
use log::*;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tokio::time::timeout;
use tokio::time::Duration;
use trust_dns_client::op::Message;
use trust_dns_proto::xfer::dns_handle::DnsHandle;

#[derive(Serialize, Deserialize, Clone)]
pub struct Upstream {
    pub tag: Label,
    pub method: UpstreamKind,
    pub timeout: u64,
}

#[derive(Serialize, Deserialize, Clone)]
pub enum UpstreamKind {
    Hybrid(Vec<Label>),
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
    upstreams: HashMap<Label, Upstream>,
    client_cache: HashMap<Label, ClientCache>,
    resp_cache: RespCache,
}

impl Upstreams {
    // TODO: Implement response cache
    pub async fn new(upstreams: Vec<Upstream>, size: usize) -> Result<Self> {
        let mut r: HashMap<Label, Upstream> = HashMap::new();
        let mut c = HashMap::new();
        for u in upstreams {
            r.insert(u.tag.clone(), u);
        }
        for (k, v) in r.iter() {
            c.insert(k.clone(), ClientCache::new(v).await?);
        }
        Ok(Self {
            upstreams: r,
            client_cache: c,
            resp_cache: RespCache::new(size),
        })
    }

    pub fn hybrid_check(&self) -> Result<bool> {
        for (tag, u) in self.upstreams.iter() {
            if let UpstreamKind::Hybrid(v) = &u.method {
                if v.is_empty() {
                    return Err(DrouteError::EmptyHybrid(tag.clone()));
                }
                if let Some(t) = v.iter().find(|tag| self.exists(&tag).is_err()) {
                    return Err(DrouteError::MissingTag(t.clone()));
                }
            }
        }
        Ok(true)
    }

    pub fn exists(&self, tag: &Label) -> Result<bool> {
        if self.upstreams.contains_key(tag) {
            Ok(true)
        } else {
            Err(DrouteError::MissingTag(tag.clone()))
        }
    }

    async fn final_resolve(&self, tag: Label, msg: Message) -> Result<Message> {
        let id = msg.id();
        // Check if cache exists
        let mut resp = if let Some(resp) = self.resp_cache.get(&msg) {
            resp
        } else {
            let u = self
                .upstreams
                .get(&tag)
                .ok_or_else(|| DrouteError::MissingTag(tag.clone()))?;
            // HashMap is created for every single upstream (including Hybrid) when `Upstreams` is created
            let client_cache = self.client_cache.get(&tag).unwrap();
            let mut client = client_cache.get_client(u).await?;

            let r =
                Message::from(timeout(Duration::from_secs(u.timeout), client.send(msg)).await??);

            // If the response can be obtained sucessfully, we then push back the client to the queue
            info!("Pushing back client cache for tag {}", tag);
            client_cache.return_back(client);
            self.resp_cache.put(r.clone());
            r
        };
        resp.set_id(id);
        Ok(resp)
    }

    pub async fn resolve(&self, tag: Label, msg: Message) -> Result<Message> {
        let u = self
            .upstreams
            .get(&tag)
            .ok_or_else(|| DrouteError::MissingTag(tag.clone()))?;
        Ok(match &u.method {
            UpstreamKind::Hybrid(v) => {
                let v = v
                    .iter()
                    .map(|t| self.final_resolve(t.clone(), msg.clone()).boxed());
                let (resp, _) = timeout(Duration::from_secs(u.timeout), select_ok(v)).await??;
                resp
            }
            _ => self.final_resolve(tag, msg).await?,
        })
    }
}
