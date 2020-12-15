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
use super::parsed::ParsedUpstream;
use super::{
    client_pool::ClientPool,
    error::Result,
    resp_cache::{RecordStatus::*, RespCache},
};
use crate::Label;
use std::borrow::Borrow;
use tokio::time::{timeout, Duration};
use trust_dns_client::op::Message;
use trust_dns_proto::xfer::dns_handle::DnsHandle;

/// Types of an upstream
#[derive(Clone)]
pub enum UpstreamKind {
    /// A hybrid upstream (no real client implementation included)
    Hybrid(Vec<Label>),
    /// A real client implementation
    Client(Box<dyn ClientPool>),
}

/// A single upstream. Opposite to the `Upstreams`.
#[derive(Clone)]
pub struct Upstream {
    timeout: u64,
    inner: UpstreamKind,
    cache: RespCache,
}

impl Upstream {
    /// Create a new `Upstream`.
    /// - `timeout`: timeout length.
    /// - `inner`: type of the upstream.
    /// - `size`: response cache size.
    pub fn new(timeout: u64, inner: UpstreamKind, size: usize) -> Self {
        Self {
            timeout,
            inner,
            cache: RespCache::new(size),
        }
    }

    /// Create an upstream with `ParsedUpstream`.
    #[cfg(feature = "serde-cfg")]
    pub async fn with_parsed(u: ParsedUpstream, size: usize) -> Result<Self> {
        Ok(Self {
            timeout: u.timeout,
            inner: u.method.convert().await?,
            cache: RespCache::new(size),
        })
    }

    pub(super) fn try_hybrid(&self) -> Option<Vec<Label>> {
        match &self.inner {
            UpstreamKind::Hybrid(v) => Some(v.clone()),
            UpstreamKind::Client(_) => None,
        }
    }

    // Send the query and handle caching schemes.
    // Using Borrow here to accept both Upstream and &Upstream
    async fn query(u: impl Borrow<Upstream>, msg: Message) -> Result<Message> {
        let u = u.borrow();

        let inner = match &u.inner {
            // This method shall not be called
            UpstreamKind::Hybrid(_) => unreachable!(),
            UpstreamKind::Client(c) => c,
        };

        let mut client = inner.get_client().await?;
        let r = Message::from(timeout(Duration::from_secs(u.timeout), client.send(msg)).await??);

        // If the response can be obtained sucessfully, we then push back the client to the client cache
        inner.return_client(client).await;
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
