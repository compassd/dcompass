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

use super::{
    super::super::{super::upstreams::Upstreams, State},
    Action, Result,
};
use crate::Label;
use async_trait::async_trait;

/// An action that send the query to an `Upstream` named with `tag`.
pub struct Query {
    tag: Label,
}

impl Query {
    /// Create a `Query` action with its associated upstream tag.
    pub fn new(tag: Label) -> Self {
        Self { tag }
    }
}

#[async_trait]
impl Action for Query {
    async fn act(&self, state: &mut State, upstreams: &Upstreams) -> Result<()> {
        state.resp = upstreams.resolve(&self.tag, &state.query).await?;
        Ok(())
    }

    fn used_upstream(&self) -> Option<Label> {
        Some(self.tag.clone())
    }
}
