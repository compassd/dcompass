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

use super::{error::Result, upstream::UpstreamBuilder, Upstreams};
use crate::Label;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[serde(rename_all = "lowercase")]
#[derive(Serialize, Deserialize, Clone)]
/// The Builder for upstreams
pub struct UpstreamsBuilder {
    upstreams: HashMap<Label, UpstreamBuilder>,
}

impl UpstreamsBuilder {
    pub fn new(upstreams: HashMap<impl Into<Label>, UpstreamBuilder>) -> Self {
        Self {
            upstreams: upstreams.into_iter().map(|(k, v)| (k.into(), v)).collect(),
        }
    }

    pub async fn build(self) -> Result<Upstreams> {
        let mut v = HashMap::new();
        for (tag, u) in self.upstreams {
            v.insert(tag, u.build().await?);
        }
        Upstreams::new(v)
    }
}
