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

//! Rules and other related concepts.

pub(super) mod actions;
pub(super) mod matchers;

use self::{actions::Action, matchers::Matcher};
use super::{
    super::upstreams::Upstreams,
    parsed::{ParsedAction, ParsedMatcher, ParsedRule},
    Result, State,
};
use crate::Label;
use hashbrown::HashSet;
use log::*;

pub struct Rule {
    matcher: Box<dyn Matcher>,
    // In the form of (Action, Next)
    on_match: (Box<dyn Action>, Label),
    no_match: (Box<dyn Action>, Label),
}

impl Rule {
    pub(crate) async fn new(rules: ParsedRule) -> Result<Self> {
        Ok(Self {
            matcher: ParsedMatcher::convert(rules.matcher).await?,
            on_match: (ParsedAction::convert(rules.on_match.0), rules.on_match.1),
            no_match: (ParsedAction::convert(rules.no_match.0), rules.no_match.1),
        })
    }

    pub fn on_match_next(&self) -> &Label {
        &self.on_match.1
    }

    pub fn no_match_next(&self) -> &Label {
        &self.no_match.1
    }

    pub fn used_upstreams(&self) -> HashSet<Label> {
        let mut h = HashSet::new();
        if let Some(l) = self.on_match.0.used_upstream() {
            h.insert(l);
        }
        if let Some(l) = self.no_match.0.used_upstream() {
            h.insert(l);
        }
        h
    }

    pub(crate) async fn route(
        &self,
        state: &mut State,
        upstreams: &Upstreams,
        name: &str,
        tag_name: &Label,
    ) -> Result<Label> {
        if self
            .matcher
            .matches(state.query.queries(), state.resp.answers())
        {
            info!("Domain \"{}\" matches at rule `{}`", name, tag_name);
            self.on_match.0.act(state, upstreams).await?;
            Ok(self.on_match.1.clone())
        } else {
            info!("Domain \"{}\" doesn't match at rule `{}`", name, tag_name);
            self.no_match.0.act(state, upstreams).await?;
            Ok(self.no_match.1.clone())
        }
    }
}
