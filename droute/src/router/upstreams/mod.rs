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

//! `Upstream` wraps around the `QHandle` to manage cache-related business. It is method (UDP, TCP, Zone File, etc.) agnostic.
//! `Upstreams` is a set of `Upstream` that manages `Hybrid` querying types and more.

pub mod builder;
/// Module which contains the error type for the `upstreams` section.
pub mod error;
mod upstream;

pub use builder::UpstreamsBuilder;
pub use upstream::*;

use self::{
    error::{Result, UpstreamError},
    upstream::resp_cache::RespCache,
};
use crate::{actions::CacheMode, Label, Validatable, ValidateCell};
use futures::future::{select_ok, BoxFuture, FutureExt};
use std::{
    collections::{HashMap, HashSet},
    num::NonZeroUsize,
};
use trust_dns_client::op::Message;

/// `Upstream` aggregated, used to create `Router`.
pub struct Upstreams {
    upstreams: HashMap<Label, Upstream>,
    cache: RespCache,
}

impl Validatable for Upstreams {
    type Error = UpstreamError;
    fn validate(&self, used: Option<&HashSet<Label>>) -> Result<()> {
        // A bucket used to count the time each rule being used.
        let mut bucket: HashMap<&Label, (ValidateCell, &Upstream)> = self
            .upstreams
            .iter()
            .map(|(k, v)| (k, (ValidateCell::default(), v)))
            .collect();
        for tag in used.unwrap_or(&HashSet::new()) {
            Self::traverse(&mut bucket, tag)?
        }
        let unused: HashSet<Label> = bucket
            .into_iter()
            .filter(|(_, (c, _))| !c.used())
            .map(|(k, _)| k)
            .cloned()
            .collect();
        if unused.is_empty() {
            Ok(())
        } else {
            Err(UpstreamError::UnusedUpstreams(unused))
        }
    }
}

impl Upstreams {
    /// Create a new `Upstreams` by passing a bunch of `Upstream`s, with their respective labels, and cache capacity.
    pub fn new(upstreams: HashMap<Label, Upstream>, cache_size: NonZeroUsize) -> Result<Self> {
        let u = Self {
            upstreams,
            cache: RespCache::new(cache_size),
        };
        // Validate on the assumption that every upstream is gonna be used.
        u.validate(Some(&u.tags()))?;
        Ok(u)
    }

    /// Return the tags of all the upstreams.
    pub fn tags(&self) -> HashSet<Label> {
        self.upstreams.keys().cloned().collect()
    }

    // Check any upstream types
    fn traverse(
        bucket: &mut HashMap<&Label, (ValidateCell, &Upstream)>,
        tag: &Label,
    ) -> Result<()> {
        let (val, u) = if let Some((c, u)) = bucket.get_mut(tag) {
            (c.val(), u.try_hybrid())
        } else {
            return Err(UpstreamError::MissingTag(tag.clone()));
        };
        if val < &1 {
            bucket.get_mut(tag).unwrap().0.add(1);
            // Check if it is empty.
            if let Some(v) = u {
                if v.is_empty() {
                    return Err(UpstreamError::EmptyHybrid(tag.clone()));
                }

                // Check if it is recursively defined.
                for t in v {
                    Self::traverse(bucket, t)?
                }
            }
            bucket.get_mut(tag).unwrap().0.sub(1);
        } else {
            return Err(UpstreamError::HybridRecursion(tag.clone()));
        };
        Ok(())
    }

    // Write out in this way to allow recursion for async functions
    // Should no be accessible from external crates
    pub(super) fn resolve<'a>(
        &'a self,
        tag: &'a Label,
        cache_mode: &'a CacheMode,
        msg: &'a Message,
    ) -> BoxFuture<'a, Result<Message>> {
        async move {
            let u = self.upstreams.get(tag).unwrap();
            Ok(if let Some(v) = u.try_hybrid() {
                // Hybrid will never call `u.resolve()`
                let v = v.iter().map(|t| self.resolve(t, cache_mode, msg));
                let (r, _) = select_ok(v.clone()).await?;
                r
            } else {
                u.resolve(tag, &self.cache, cache_mode, msg).await?
            })
        }
        .boxed()
    }
}

#[cfg(test)]
mod tests {
    use super::{UpstreamBuilder, UpstreamError, UpstreamsBuilder};

    #[tokio::test]
    async fn should_not_fail_recursion() {
        // This should not fail because for the hybrid1, graph is like hybrid1 -> ((hybrid2 -> foo), foo), which is not recursive.
        // Previous detection algorithm mistakingly identifies this as recursion.
        UpstreamsBuilder::new(
            vec![
                (
                    "udp",
                    UpstreamBuilder::Udp {
                        addr: "127.0.0.1:53533".parse().unwrap(),
                        dnssec: false,
                        timeout: 1,
                    },
                ),
                (
                    "hybrid1",
                    UpstreamBuilder::Hybrid(
                        vec!["udp".into(), "hybrid2".into()].into_iter().collect(),
                    ),
                ),
                (
                    "hybrid2",
                    UpstreamBuilder::Hybrid(vec!["udp".into()].into_iter().collect()),
                ),
            ]
            .into_iter()
            .collect(),
            std::num::NonZeroUsize::new(1).unwrap(),
        )
        .build()
        .await
        .ok()
        .unwrap();
    }

    #[tokio::test]
    async fn fail_recursion() {
        match UpstreamsBuilder::new(
            vec![
                (
                    "udp",
                    UpstreamBuilder::Udp {
                        addr: "127.0.0.1:53533".parse().unwrap(),
                        dnssec: false,
                        timeout: 1,
                    },
                ),
                (
                    "hybrid1",
                    UpstreamBuilder::Hybrid(
                        vec!["udp".into(), "hybrid2".into()].into_iter().collect(),
                    ),
                ),
                (
                    "hybrid2",
                    UpstreamBuilder::Hybrid(vec!["hybrid1".into()].into_iter().collect()),
                ),
            ]
            .into_iter()
            .collect(),
            std::num::NonZeroUsize::new(1).unwrap(),
        )
        .build()
        .await
        .err()
        .unwrap()
        {
            UpstreamError::HybridRecursion(_) => (),
            e => panic!("Not the right error type: {}", e),
        }
    }
}
