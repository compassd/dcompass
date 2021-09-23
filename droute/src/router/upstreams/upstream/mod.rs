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

pub mod builder;
mod qhandle;

use std::sync::Arc;

use bytes::Bytes;
pub use qhandle::{QHandle, QHandleError};

use super::{super::table::rule::actions::CacheMode, error::Result};
use crate::{
    cache::{RecordStatus::*, RespCache},
    Label,
};
use domain::base::Message;

/// A single upstream. Opposite to the `Upstreams`.
#[derive(Clone)]
pub enum Upstream {
    /// Hybrid upstream type
    // We don't use HashSet because we don't need to look up
    Hybrid(Vec<Label>),
    /// Other upstream types, like Zone or ClientPool.
    Others(Arc<dyn QHandle>),
}

impl Upstream {
    pub(super) fn try_hybrid(&self) -> Option<Vec<&Label>> {
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
        msg: &Message<Bytes>,
    ) -> Result<Message<Bytes>> {
        if let Self::Others(inner) = &self {
            log::info!("querying with upstream: {}", tag);
            // Manage cache with caching policies
            let r = match cache_mode {
                CacheMode::Disabled => inner.query(msg).await?,
                CacheMode::Standard => match cache.get(tag, msg) {
                    // Cache available within TTL constraints
                    Some(Alive(r)) => r,
                    // No cache or cache expired
                    Some(Expired(_)) | None => inner.query(msg).await?,
                },
                CacheMode::Persistent => match cache.get(tag, msg) {
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
                            if let Ok(r) = inner.query(&msg).await {
                                cache.put(tag, &msg, r)
                            }
                        });
                        r
                    }
                    None => inner.query(msg).await?,
                },
            };
            if cache_mode != &CacheMode::Disabled {
                cache.put(tag.clone(), msg, r.clone());
            }
            log::info!("query successfully completed.");
            Ok(r)
        } else {
            unreachable!()
        }
    }
}
