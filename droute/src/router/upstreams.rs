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

/// Module which contains builtin client implementations and the trait for implement your own.
pub mod client_pool;
/// Module which contains the error type for the `upstreams` section.
pub mod error;
#[cfg(feature = "serde-cfg")]
pub mod parsed;
mod resp_cache;
mod upstream;

pub use upstream::*;

use self::error::{Result, UpstreamError};
#[cfg(feature = "serde-cfg")]
use self::parsed::{ParUpstream, ParUpstreamKind};
use crate::{Label, Validatable};
use futures::future::{select_ok, BoxFuture, FutureExt};
use hashbrown::{HashMap, HashSet};
use trust_dns_client::op::Message;

/// `Upstream` aggregated, used to create `Router`.
pub struct Upstreams {
    upstreams: HashMap<Label, Upstream>,
}

impl Validatable for Upstreams {
    type Error = UpstreamError;
    fn validate(&self, used: Option<&HashSet<Label>>) -> Result<()> {
        let mut keys = self.upstreams.keys().collect::<HashSet<&Label>>();
        for tag in used.unwrap_or(&HashSet::new()) {
            self.traverse(tag, &mut HashSet::new(), &mut keys)?
        }
        if keys.is_empty() {
            Ok(())
        } else {
            Err(UpstreamError::UnusedUpstreams(
                keys.into_iter().cloned().collect(),
            ))
        }
    }
}

impl Upstreams {
    /// Create a new `Upstreams` by passing a bunch of `Upstream`s, with their respective labels, and cache capacity.
    pub fn new(upstreams: Vec<(Label, Upstream)>) -> Result<Self> {
        let mut r = HashMap::new();
        for u in upstreams {
            // Check if there is multiple definitions being passed in.
            match r.get(&u.0) {
                Some(_) => return Err(UpstreamError::MultipleDef(u.0)),
                None => {
                    r.insert(u.0, u.1);
                }
            };
        }
        let u = Self { upstreams: r };
        // Validate on the assumption that every upstream is gonna be used.
        u.validate(Some(&u.tags()))?;
        Ok(u)
    }

    /// Create a new `Upstreams` with a set of ParUpstream.
    #[cfg(feature = "serde-cfg")]
    pub async fn parse(
        upstreams: Vec<ParUpstream<impl ParUpstreamKind>>,
        size: usize,
    ) -> Result<Self> {
        Self::new({
            let mut v = Vec::new();
            for u in upstreams {
                v.push((u.tag.clone(), Upstream::parse(u, size).await?));
            }
            v
        })
    }

    /// Return the tags of all the upstreams.
    pub fn tags(&self) -> HashSet<Label> {
        self.upstreams.keys().cloned().collect()
    }

    // Check any upstream types
    fn traverse(
        &self,
        tag: &Label,
        traversed: &mut HashSet<Label>,
        unused: &mut HashSet<&Label>,
    ) -> Result<()> {
        if traversed.contains(tag) {
            return Err(UpstreamError::HybridRecursion(tag.clone()));
        } else {
            unused.remove(tag);
            traversed.insert(tag.clone());

            if let Some(v) = &self
                .upstreams
                .get(tag)
                .ok_or_else(|| UpstreamError::MissingTag(tag.clone()))?
                .try_hybrid()
            {
                // Check if it is empty.
                if v.is_empty() {
                    return Err(UpstreamError::EmptyHybrid(tag.clone()));
                }

                // Check if it is recursively defined.
                for t in v {
                    self.traverse(t, traversed, unused)?
                }
            }
            traversed.remove(tag);
        }
        Ok(())
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
            Ok(if let Some(v) = u.try_hybrid() {
                let v = v.iter().map(|t| self.resolve(t, msg));
                let (r, _) = select_ok(v.clone()).await?;
                r
            } else {
                u.resolve(msg).await?
            })
        }
        .boxed()
    }
}

#[cfg(test)]
mod tests {
    use super::{client_pool::Udp, Upstream, UpstreamKind, Upstreams};

    #[tokio::test]
    async fn should_not_fail_recursion() {
        // This should not fail because for the hybrid1, graph is like hybrid1 -> ((hybrid2 -> foo), foo), which is not recursive.
        // Previous detection algorithm mistakingly identifies this as recursion.
        Upstreams::new(vec![
            (
                "udp".into(),
                Upstream::new(
                    UpstreamKind::Client {
                        pool: Box::new(
                            Udp::new(&"127.0.0.1:53533".parse().unwrap()).await.unwrap(),
                        ),
                        timeout: 1,
                    },
                    10,
                ),
            ),
            (
                "hybrid1".into(),
                Upstream::new(
                    UpstreamKind::Hybrid(
                        vec!["udp".into(), "hybrid2".into()].into_iter().collect(),
                    ),
                    10,
                ),
            ),
            (
                "hybrid2".into(),
                Upstream::new(
                    UpstreamKind::Hybrid(vec!["udp".into()].into_iter().collect()),
                    10,
                ),
            ),
        ])
        .ok()
        .unwrap();
    }
}
