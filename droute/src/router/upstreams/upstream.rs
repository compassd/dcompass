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

#[cfg(feature = "serde-cfg")]
use super::parsed::{ParUpstream, ParUpstreamKind};
use super::{
    client_pool::{ClientPool, ClientState::*},
    error::Result,
    resp_cache::{RecordStatus::*, RespCache},
};
use crate::Label;
use hashbrown::HashSet;
use std::borrow::Borrow;
use tokio::time::{timeout, Duration};
use trust_dns_client::op::Message;
use trust_dns_proto::xfer::dns_handle::DnsHandle;

/// Types of an upstream
#[derive(Clone)]
pub enum UpstreamKind {
    /// A hybrid upstream (no real client implementation included)
    Hybrid(HashSet<Label>),
    /// A real client implementation
    Client {
        /// Client pool
        pool: Box<dyn ClientPool>,
        /// Timeout length
        timeout: Duration,
    },
}

/// A single upstream. Opposite to the `Upstreams`.
#[derive(Clone)]
pub struct Upstream {
    inner: UpstreamKind,
    cache: RespCache,
}

impl Upstream {
    /// Create a new `Upstream`.
    /// - `timeout`: timeout length.
    /// - `inner`: type of the upstream.
    /// - `size`: response cache size.
    pub fn new(inner: UpstreamKind, size: usize) -> Self {
        Self {
            inner,
            cache: RespCache::new(size),
        }
    }

    /// Create an upstream with `ParUpstream`.
    #[cfg(feature = "serde-cfg")]
    pub async fn parse(u: ParUpstream<impl ParUpstreamKind>, size: usize) -> Result<Self> {
        Ok(Self {
            inner: u.method.build().await?,
            cache: RespCache::new(size),
        })
    }

    pub(super) fn try_hybrid(&self) -> Option<HashSet<&Label>> {
        match &self.inner {
            UpstreamKind::Hybrid(v) => Some(v.iter().collect()),
            UpstreamKind::Client {
                pool: _,
                timeout: _,
            } => None,
        }
    }

    // Send the query and handle caching schemes.
    // Using Borrow here to accept both Upstream and &Upstream
    async fn query(u: impl Borrow<Upstream>, msg: Message) -> Result<Message> {
        let u = u.borrow();

        let (pool, t) = match &u.inner {
            // This method shall not be called
            UpstreamKind::Hybrid(_) => unreachable!(),
            UpstreamKind::Client { pool, timeout } => (pool, timeout),
        };

        let mut client = pool.get_client().await?;
        let r = Message::from(match timeout(*t, client.send(msg)).await? {
            Ok(m) => m,
            Err(e) => {
                // Renew the client as it errored. Currently it is only applicable for UDP.
                pool.return_client(client, Failed).await?;
                return Err(e.into());
            }
        });

        // If the response can be obtained sucessfully, we then push back the client to the client cache
        pool.return_client(client, Succeeded).await?;
        u.cache.put(r.clone());
        Ok(r)
    }

    /// Resolve the query into a response.
    pub async fn resolve(&self, msg: &Message) -> Result<Message> {
        let id = msg.id();

        // Check if cache exists
        let mut r = match self.cache.get(&msg) {
            // Cache available within TTL constraints
            Some(Alive(r)) => r,
            Some(Expired(r)) => {
                // Cache records exists, but TTL exceeded.
                // We try to update the cache and return back the outdated value.
                tokio::spawn(Self::query(self.clone(), msg.clone()));
                r
            }
            None => Self::query(self, msg.clone()).await?,
        };
        r.set_id(id);
        Ok(r)
    }
}
