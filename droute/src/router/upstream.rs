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
use self::resp_cache::{RecordStatus::*, RespCache};
use crate::error::{DrouteError, Result};
use futures::future::{select_ok, BoxFuture, FutureExt};
use hashbrown::{HashMap, HashSet};
use serde::{Deserialize, Serialize};
use std::borrow::Borrow;
use std::fmt::{Debug, Display};
use std::hash::Hash;
use std::net::SocketAddr;
use tokio::time::{timeout, Duration};
use trust_dns_client::op::Message;
use trust_dns_proto::xfer::dns_handle::DnsHandle;

#[derive(Serialize, Deserialize, Clone)]
pub struct Upstream<L> {
    pub tag: L,
    pub method: UpstreamKind<L>,
    #[serde(default = "default_timeout")]
    pub timeout: u64,
}

impl<L: 'static + Display + Debug + Eq + Hash + Send + Clone + Sync> Upstream<L> {
    // Send the query and handle caching schemes.
    async fn query(
        u: impl Borrow<Upstream<L>>,
        client_cache: impl Borrow<ClientCache>,
        resp_cache: impl Borrow<RespCache>,
        msg: Message,
    ) -> Result<L, Message> {
        let (u, client_cache, resp_cache) =
            (u.borrow(), client_cache.borrow(), resp_cache.borrow());

        let mut client = client_cache.get_client(u).await?;
        let r = Message::from(timeout(Duration::from_secs(u.timeout), client.send(msg)).await??);

        // If the response can be obtained sucessfully, we then push back the client to the client cache
        client_cache.return_back(client);
        resp_cache.put(r.clone());
        Ok(r)
    }

    pub async fn resolve(
        &self,
        resp_cache: &RespCache,
        client_cache: &ClientCache,
        msg: &Message,
    ) -> Result<L, Message> {
        let id = msg.id();

        // Check if cache exists
        let mut r = match resp_cache.get(&msg) {
            // Cache available within TTL constraints
            Some(Alive(r)) => r,
            Some(Expired(r)) => {
                // Cache records exists, but TTL exceeded.
                // We try to update the cache and return back the outdated value.
                tokio::spawn(Self::query(
                    self.clone(),
                    client_cache.clone(),
                    resp_cache.clone(),
                    msg.clone(),
                ));
                r
            }
            None => Self::query(self, client_cache, resp_cache, msg.clone()).await?,
        };
        r.set_id(id);
        Ok(r)
    }
}

// Default value for timeout
fn default_timeout() -> u64 {
    5
}

#[derive(Serialize, Deserialize, Clone)]
pub enum UpstreamKind<L> {
    Hybrid(Vec<L>),
    Https {
        name: String,
        addr: SocketAddr,
        no_sni: bool,
    },
    // Drop TLS support until we figure out how to do without OpenSSL
    // Tls(String, SocketAddr),
    Udp(SocketAddr),
}

pub(crate) struct Upstreams<L> {
    upstreams: HashMap<L, Upstream<L>>,
    client_cache: HashMap<L, ClientCache>,
    resp_cache: RespCache,
}

impl<L: 'static + Display + Debug + Eq + Hash + Send + Clone + Sync> Upstreams<L> {
    pub async fn new(upstreams: Vec<Upstream<L>>, size: usize) -> Result<L, Self> {
        let mut r: HashMap<L, Upstream<L>> = HashMap::new();
        let mut c = HashMap::new();
        for u in upstreams {
            r.insert(u.tag.clone(), u);
        }
        for (k, v) in r.iter() {
            c.insert(k.clone(), ClientCache::new(v).await?);
        }
        let u = Self {
            upstreams: r,
            client_cache: c,
            resp_cache: RespCache::new(size),
        };
        u.hybrid_check()?;
        Ok(u)
    }

    // Check any upstream types
    // tag: current upstream node's tag
    // l: visited tags
    fn hybrid_search(&self, l: &mut HashSet<L>, tag: L) -> Result<L, ()> {
        if l.contains(&tag) {
            return Err(DrouteError::HybridRecursion(tag));
        } else {
            l.insert(tag.clone());

            if let UpstreamKind::Hybrid(v) = &self
                .upstreams
                .get(&tag)
                .ok_or_else(|| DrouteError::MissingTag(tag.clone()))?
                .method
            {
                // Check if it is empty.
                if v.is_empty() {
                    return Err(DrouteError::EmptyHybrid(tag.clone()));
                }

                // Check if it is recursively defined.
                for t in v {
                    self.hybrid_search(l, t.clone())?
                }
            }
        }

        Ok(())
    }

    pub fn hybrid_check(&self) -> Result<L, bool> {
        for (tag, _) in self.upstreams.iter() {
            self.hybrid_search(&mut HashSet::new(), tag.clone())?
        }
        Ok(true)
    }

    pub fn exists(&self, tag: &L) -> Result<L, bool> {
        if self.upstreams.contains_key(tag) {
            Ok(true)
        } else {
            Err(DrouteError::MissingTag(tag.clone()))
        }
    }

    // Write out in this way to allow recursion for async functions
    pub fn resolve<'a>(
        &'a self,
        tag: &'a L,
        msg: &'a Message,
    ) -> BoxFuture<'a, Result<L, Message>> {
        async move {
            let u = self.upstreams.get(&tag).unwrap();
            Ok(match &u.method {
                UpstreamKind::Hybrid(v) => {
                    let v = v.iter().map(|t| self.resolve(t, msg));
                    let (r, _) = select_ok(v.clone()).await?;
                    r
                }
                _ => {
                    self.upstreams
                        .get(tag)
                        .unwrap()
                        .resolve(&self.resp_cache, self.client_cache.get(&tag).unwrap(), msg)
                        .await?
                }
            })
        }
        .boxed()
    }
}
