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

mod builder;
mod qhandle;
pub(crate) mod resp_cache;

pub use builder::UpstreamBuilder;
pub use qhandle::{QHandle, QHandleError};

use self::resp_cache::{RecordStatus::*, RespCache};
use super::{super::table::rule::actions::CacheMode, error::Result};
use crate::Label;
use std::{collections::HashSet, sync::Arc};
use trust_dns_client::op::Message;

/// A single upstream. Opposite to the `Upstreams`.
#[derive(Clone)]
pub enum Upstream {
    /// Hybrid upstream type
    Hybrid(HashSet<Label>),
    /// Other upstream types, like Zone or ClientPool.
    Others(Arc<dyn QHandle>),
}

impl Upstream {
    pub(super) fn try_hybrid(&self) -> Option<HashSet<&Label>> {
        match &self {
            Self::Hybrid(v) => Some(v.iter().collect()),
            _ => None,
        }
    }

    /// Resolve the query into a response.
    pub async fn resolve(
        &self,
        tag: &Label,
        cache: &RespCache,
        cache_mode: &CacheMode,
        msg: &Message,
    ) -> Result<Message> {
        if let Self::Others(inner) = &self {
            let id = msg.id();

            log::info!("querying with upstream: {}", tag);
            // Manage cache with caching policies
            let mut r = match cache_mode {
                CacheMode::Disabled => inner.query(msg.clone()).await?,
                CacheMode::Standard => match cache.get(tag, &msg) {
                    // Cache available within TTL constraints
                    Some(Alive(r)) => r,
                    // No cache or cache expired
                    Some(Expired(_)) | None => inner.query(msg.clone()).await?,
                },
                CacheMode::Persistent => match cache.get(tag, &msg) {
                    // Cache available within TTL constraints
                    Some(Alive(r)) => r,
                    Some(Expired(r)) => {
                        // Cache records exists, but TTL exceeded.
                        // We try to update the cache and return back the outdated value.
                        let inner = inner.clone();
                        // Arc inside
                        let cache = cache.clone();
                        let msg = msg.clone();
                        let tag = tag.clone();
                        tokio::spawn(async move {
                            // We have to update the cache though
                            // We don't care about failures here.
                            if let Ok(r) = inner.query(msg).await {
                                cache.put(tag, r)
                            }
                        });
                        r
                    }
                    None => inner.query(msg.clone()).await?,
                },
            };
            cache.put(tag.clone(), r.clone());
            r.set_id(id);
            log::info!("query successfully completed.");
            Ok(r)
        } else {
            unreachable!()
        }
    }
}
