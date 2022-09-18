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

/// A module containing the builders for Upstreams, Upstream, and each client builder.
pub mod builder;
/// Module which contains the error type for the `upstreams` section.
pub mod error;
mod upstream;

use self::error::{Result, UpstreamError};
use crate::{cache::RespCache, Label, Validatable, ValidateCell};
use bytes::{Bytes, BytesMut};
use domain::base::Message;
use futures::future::{select_ok, BoxFuture, FutureExt};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, num::NonZeroUsize, str::FromStr};
pub use upstream::*;

#[derive(Deserialize, Serialize, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "rune-scripting", derive(rune::Any))]
#[serde(rename_all = "lowercase")]
/// Cache Policy per query. this only affect the cache results adoption, and it will NOT change the cache results storing behaviors.
pub enum CacheMode {
    #[cfg_attr(feature = "rune-scripting", rune(constructor))]
    /// Do not use any cached result
    Disabled,
    #[cfg_attr(feature = "rune-scripting", rune(constructor))]
    /// Use cache records within the TTL
    Standard,
    #[cfg_attr(feature = "rune-scripting", rune(constructor))]
    /// Use cache results regardless of the time elapsed, and update the results on need.
    Persistent,
}

impl Default for CacheMode {
    fn default() -> Self {
        Self::Standard
    }
}

// Used by rhai
impl FromStr for CacheMode {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "disabled" => Ok(Self::Disabled),
            "standard" => Ok(Self::Standard),
            "persistent" => Ok(Self::Persistent),
            _ => Err("unknown cache mode".to_string()),
        }
    }
}

/// [`Upstream`] aggregated, used to create `Router`.
#[derive(Clone)]
#[cfg_attr(feature = "rune-scripting", derive(rune::Any))]
pub struct Upstreams {
    upstreams: HashMap<Label, Upstream>,
    // All the responses are cached together, however, they are seperately tagged, so there should be no contamination in place.
    cache: RespCache,
}

impl Validatable for Upstreams {
    type Error = UpstreamError;
    fn validate(&self, _: Option<&Vec<Label>>) -> Result<()> {
        // A bucket used to count the time each upstream being used.
        let mut bucket: HashMap<&Label, (ValidateCell, &Upstream)> = self
            .upstreams
            .iter()
            .map(|(k, v)| (k, (ValidateCell::default(), v)))
            .collect();
        for tag in self.tags() {
            Self::traverse(&mut bucket, &tag)?
        }
        Ok(())
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
    pub fn tags(&self) -> Vec<Label> {
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
        // The following code is based on the assumption that only hybrid upstream would recurse into the next level and increment the counter
        // Therefore, if the counter for the same upstream is already one, that means recursion.
        if val < &1 {
            // We have checked that tag exists.

            // Increment the counter
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
            // Sub the counter on leave
            bucket.get_mut(tag).unwrap().0.sub(1);
        } else {
            return Err(UpstreamError::HybridRecursion(tag.clone()));
        };
        Ok(())
    }

    // Write out in this way to allow recursion for async functions
    /// Send the query to a tagged upstream and a given cache mode.
    pub fn send<'a>(
        &'a self,
        tag: &'a Label,
        cache_mode: &'a CacheMode,
        msg: &'a Message<Bytes>,
    ) -> BoxFuture<'a, Result<Message<Bytes>>> {
        async move {
            let u = self
                .upstreams
                .get(tag)
                .ok_or_else(|| UpstreamError::MissingTag(tag.clone()))?;
            let resp = if let Some(v) = u.try_hybrid() {
                // Hybrid will never call `u.send_internal()`
                let v = v.iter().map(|t| self.send(t, cache_mode, msg));
                let (r, _) = select_ok(v).await?;
                r
            } else {
                u.resolve(tag, &self.cache, cache_mode, msg).await?
            };

            // Set back the message ID
            let mut resp = Message::from_octets(BytesMut::from(resp.as_slice()))?;
            resp.header_mut().set_id(msg.header().id());

            Ok(Message::from_octets(resp.into_octets().freeze())?)
        }
        .boxed()
    }
}

#[cfg(test)]
mod tests {
    use crate::AsyncTryInto;

    use super::{
        builder::{HybridBuilder, UdpBuilder, UpstreamBuilder, UpstreamsBuilder},
        UpstreamError,
    };

    #[tokio::test]
    async fn should_not_fail_recursion() {
        // This should not fail because for the hybrid1, graph is like hybrid1 -> ((hybrid2 -> foo), foo), which is not recursive.
        // Previous detection algorithm mistakingly identifies this as recursion.
        UpstreamsBuilder::new(1)
            .unwrap()
            .add_upstream(
                "udp",
                UpstreamBuilder::Udp(UdpBuilder {
                    addr: "127.0.0.1:53533".parse().unwrap(),
                    max_pool_size: 32,
                    timeout: 1,
                    ratelimit: None,
                }),
            )
            .add_upstream(
                "hybrid1",
                UpstreamBuilder::Hybrid(HybridBuilder::new().add_tag("udp").add_tag("hybrid2")),
            )
            .add_upstream(
                "hybrid2",
                UpstreamBuilder::Hybrid(HybridBuilder::new().add_tag("udp")),
            )
            .async_try_into()
            .await
            .ok()
            .unwrap();
    }

    #[tokio::test]
    async fn fail_recursion() {
        match UpstreamsBuilder::new(1)
            .unwrap()
            .add_upstream(
                "udp",
                UpstreamBuilder::Udp(UdpBuilder {
                    addr: "127.0.0.1:53533".parse().unwrap(),
                    max_pool_size: 256,
                    timeout: 1,
                    ratelimit: None,
                }),
            )
            .add_upstream(
                "hybrid1",
                UpstreamBuilder::Hybrid(HybridBuilder::new().add_tag("hybrid2")),
            )
            .add_upstream(
                "hybrid2",
                UpstreamBuilder::Hybrid(HybridBuilder::new().add_tag("hybrid1")),
            )
            .async_try_into()
            .await
            .err()
            .unwrap()
        {
            UpstreamError::HybridRecursion(_) => (),
            e => panic!("Not the right error type: {}", e),
        }
    }
}
