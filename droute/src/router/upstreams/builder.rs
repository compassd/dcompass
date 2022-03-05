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

pub use super::upstream::builder::*;

use super::{
    error::{Result, UpstreamError},
    QHandleError, Upstreams,
};
use crate::{AsyncTryInto, Label, Upstream};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, num::NonZeroUsize};

fn default_cache_size() -> NonZeroUsize {
    NonZeroUsize::new(2048).unwrap()
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
/// The Builder for upstreams
pub struct UpstreamsBuilder<U: AsyncTryInto<Upstream, Error = QHandleError>> {
    upstreams: HashMap<Label, U>,
    #[serde(default = "default_cache_size")]
    cache_size: NonZeroUsize,
}

impl<U: AsyncTryInto<Upstream, Error = QHandleError>> UpstreamsBuilder<U> {
    /// Create an UpstreamsBuilder from a set of upstreams and the cache_size for all of them.
    pub fn from_map(upstreams: HashMap<impl Into<Label>, U>, cache_size: NonZeroUsize) -> Self {
        Self {
            upstreams: upstreams.into_iter().map(|(k, v)| (k.into(), v)).collect(),
            cache_size,
        }
    }

    /// Create an empty UpstreamsBuilder with a given cache_size
    pub fn new(cache_size: usize) -> Option<Self> {
        std::num::NonZeroUsize::new(cache_size).map(|c| Self {
            upstreams: HashMap::new(),
            cache_size: c,
        })
    }

    /// Add an upstream builder
    pub fn add_upstream(mut self, tag: impl Into<Label>, upstream: U) -> Self {
        self.upstreams.insert(tag.into(), upstream);
        self
    }
}

#[async_trait]
impl<U: AsyncTryInto<Upstream, Error = QHandleError>> AsyncTryInto<Upstreams>
    for UpstreamsBuilder<U>
{
    type Error = UpstreamError;

    /// Build the Upstreams from an UpstreamsBuilder
    async fn async_try_into(self) -> Result<Upstreams> {
        let mut v = HashMap::new();
        for (tag, u) in self.upstreams {
            v.insert(tag, u.async_try_into().await?);
        }
        Upstreams::new(v, self.cache_size)
    }
}
