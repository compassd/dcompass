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
    super::super::{super::upstreams::Upstreams, parsed::ParsedAction, State},
    Action, Result,
};
use crate::Label;
use async_trait::async_trait;

pub(crate) struct Query {
    tag: Label,
}

impl Query {
    pub fn new(spec: ParsedAction) -> Self {
        match spec {
            ParsedAction::Query(tag) => Self { tag },
            _ => unreachable!(),
        }
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
