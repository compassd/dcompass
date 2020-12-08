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

//! Upstream defines how droute resolves queries ultimately.

mod client_cache;
/// Module which contains the error type for the `upstreams` section.
pub mod error;
mod resp_cache;

use self::{
    client_cache::ClientCache,
    error::{Result, UpstreamError},
    resp_cache::{RecordStatus::*, RespCache},
};
use crate::Label;
use futures::future::{select_ok, BoxFuture, FutureExt};
use hashbrown::{HashMap, HashSet};
#[cfg(feature = "serde-cfg")]
use serde::{Deserialize, Serialize};
use std::{borrow::Borrow, net::SocketAddr};
use tokio::time::{timeout, Duration};
use trust_dns_client::op::Message;
use trust_dns_proto::xfer::dns_handle::DnsHandle;

#[cfg_attr(feature = "serde-cfg", derive(Serialize, Deserialize))]
#[derive(Clone)]
/// Information needed for an upstream.
pub struct Upstream {
    /// The destination (tag) associated with the upstream.
    pub tag: Label,
    /// Querying method.
    pub method: UpstreamKind,
    /// How long to timeout.
    #[cfg_attr(feature = "serde-cfg", serde(default = "default_timeout"))]
    pub timeout: u64,
}

impl Upstream {
    // Send the query and handle caching schemes.
    async fn query(
        u: impl Borrow<Upstream>,
        client_cache: impl Borrow<ClientCache>,
        resp_cache: impl Borrow<RespCache>,
        msg: Message,
    ) -> Result<Message> {
        let (u, client_cache, resp_cache) =
            (u.borrow(), client_cache.borrow(), resp_cache.borrow());

        let mut client = client_cache.get_client(u).await?;
        let r = Message::from(timeout(Duration::from_secs(u.timeout), client.send(msg)).await??);

        // If the response can be obtained sucessfully, we then push back the client to the client cache
        client_cache.return_back(client);
        resp_cache.put(r.clone());
        Ok(r)
    }

    pub(self) async fn resolve(
        &self,
        resp_cache: &RespCache,
        client_cache: &ClientCache,
        msg: &Message,
    ) -> Result<Message> {
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
#[cfg(feature = "serde-cfg")]
fn default_timeout() -> u64 {
    5
}

#[cfg_attr(feature = "serde-cfg", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde-cfg", serde(rename_all = "lowercase"))]
#[derive(Clone)]
/// The methods of querying
pub enum UpstreamKind {
    /// Race various different upstreams concurrently. You can use it recursively, meaning Hybrid over (Hybrid over (DoH + UDP) + UDP) is legal.
    Hybrid(Vec<Label>),
    /// DNS over HTTPS (DoH).
    #[cfg(feature = "doh")]
    Https {
        /// The domain name of the server. e.g. `cloudflare-dns.com` for Cloudflare DNS.
        name: String,
        /// The address of the server. e.g. `1.1.1.1:443` for Cloudflare DNS.
        addr: SocketAddr,
        /// Set to `true` to not send SNI. This is useful to bypass firewalls and censorships.
        no_sni: bool,
    },
    /// DNS over TLS (DoT).
    #[cfg(feature = "dot")]
    Tls {
        /// The domain name of the server. e.g. `cloudflare-dns.com` for Cloudflare DNS.
        name: String,
        /// The address of the server. e.g. `1.1.1.1:853` for Cloudflare DNS.
        addr: SocketAddr,
        /// Set to `true` to not send SNI. This is useful to bypass firewalls and censorships.
        no_sni: bool,
    },
    /// UDP connection.
    Udp(SocketAddr),
}

/// `Upstream` aggregated, used to create `Router`.
pub struct Upstreams {
    upstreams: HashMap<Label, Upstream>,
    client_cache: HashMap<Label, ClientCache>,
    resp_cache: HashMap<Label, RespCache>,
}

impl Upstreams {
    /// Create a new `Upstreams` by passing a bunch of `Upstream`s and cache capacity.
    pub async fn new(upstreams: Vec<Upstream>, size: usize) -> Result<Self> {
        let mut r: HashMap<Label, Upstream> = HashMap::new();
        let mut c = HashMap::new();
        let mut resp_cache = HashMap::new();
        for u in upstreams {
            // Check if there is multiple definitions being passed in.
            match r.get(&u.tag) {
                Some(_) => return Err(UpstreamError::MultipleDef(u.tag)),
                None => {
                    c.insert(u.tag.clone(), ClientCache::new(&u).await?);
                    resp_cache.insert(u.tag.clone(), RespCache::new(size));
                    r.insert(u.tag.clone(), u);
                }
            };
        }
        let u = Self {
            upstreams: r,
            client_cache: c,
            resp_cache,
        };
        u.check()?;
        Ok(u)
    }

    // Check any upstream types
    // tag: current upstream node's tag
    // l: visited tags
    fn traverse(&self, l: &mut HashSet<Label>, tag: Label) -> Result<()> {
        if l.contains(&tag) {
            return Err(UpstreamError::HybridRecursion(tag));
        } else {
            l.insert(tag.clone());

            if let UpstreamKind::Hybrid(v) = &self
                .upstreams
                .get(&tag)
                .ok_or_else(|| UpstreamError::MissingTag(tag.clone()))?
                .method
            {
                // Check if it is empty.
                if v.is_empty() {
                    return Err(UpstreamError::EmptyHybrid(tag.clone()));
                }

                // Check if it is recursively defined.
                for t in v {
                    self.traverse(l, t.clone())?
                }
            }
        }

        Ok(())
    }

    /// Check if the upstream is legitimate. This is automatically done when you create a new `Upstreams`.
    pub fn check(&self) -> Result<bool> {
        for (tag, _) in self.upstreams.iter() {
            self.traverse(&mut HashSet::new(), tag.clone())?
        }
        Ok(true)
    }

    // Make it only visible in side `router`
    pub(super) fn exists(&self, tag: &Label) -> Result<bool> {
        if self.upstreams.contains_key(tag) {
            Ok(true)
        } else {
            Err(UpstreamError::MissingTag(tag.clone()))
        }
    }

    // Write out in this way to allow recursion for async functions
    // Should no be accessible from external crates
    pub(super) fn resolve<'a>(
        &'a self,
        tag: &'a Label,
        msg: &'a Message,
    ) -> BoxFuture<'a, Result<Message>> {
        async move {
            let u = self.upstreams.get(tag).unwrap();
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
                        .resolve(
                            &self.resp_cache.get(tag).unwrap(),
                            self.client_cache.get(tag).unwrap(),
                            msg,
                        )
                        .await?
                }
            })
        }
        .boxed()
    }
}
