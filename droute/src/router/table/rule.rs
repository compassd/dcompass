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

/// A module containing built-in actions, action trait, and more.
pub mod actions;
/// A module containing built-in matchers, matcher trait, and more.
pub mod matchers;

use self::{actions::Action, matchers::Matcher};
#[cfg(feature = "serde-cfg")]
use super::parsed::{ParAction, ParMatcher, ParRule};
use super::{super::upstreams::Upstreams, Result, State};
use crate::Label;
use hashbrown::HashSet;
use log::*;

/// A unit that composes the `Table`.
pub struct Rule {
    tag: Label,
    matcher: Box<dyn Matcher>,
    // In the form of (Action, Next)
    on_match: (Box<dyn Action>, Label),
    no_match: (Box<dyn Action>, Label),
}

impl Rule {
    /// Create a `Rule` from directly.
    /// - `tag`: the name of the `Rule`, which may be refered by other rules.
    /// - `matcher`: A trait object implementing the `Matcher` trait. It determines the action to take and what the next rule is.
    /// - `on_match` and `no_match`: The action to take and what the next rule is based on if it matches or not.
    pub fn new(
        tag: Label,
        matcher: Box<dyn Matcher>,
        on_match: (Box<dyn Action>, Label),
        no_match: (Box<dyn Action>, Label),
    ) -> Self {
        Self {
            tag,
            matcher,
            on_match,
            no_match,
        }
    }

    // Shall not be used by end-users. visible under `Router`.
    #[cfg(feature = "serde-cfg")]
    pub(in super::super) async fn parse(
        rules: ParRule<impl ParMatcher, impl ParAction>,
    ) -> Result<Self> {
        let matcher = rules.matcher.build().await?;
        let on_match = rules.on_match.0.build().await?;
        let no_match = rules.no_match.0.build().await?;
        Ok(Self::new(
            rules.tag,
            matcher,
            (on_match, rules.on_match.1),
            (no_match, rules.no_match.1),
        ))
    }

    pub(in super::super) fn tag(&self) -> &Label {
        &self.tag
    }

    pub(in super::super) fn on_match_next(&self) -> &Label {
        &self.on_match.1
    }

    pub(in super::super) fn no_match_next(&self) -> &Label {
        &self.no_match.1
    }

    pub(in super::super) fn used_upstreams(&self) -> HashSet<Label> {
        let mut h = HashSet::new();
        if let Some(l) = self.on_match.0.used_upstream() {
            h.insert(l);
        }
        if let Some(l) = self.no_match.0.used_upstream() {
            h.insert(l);
        }
        h
    }

    // Returns the label of the next rule.
    pub(in super::super) async fn route(
        &self,
        state: &mut State,
        upstreams: &Upstreams,
        name: &str,
        tag_name: &Label,
    ) -> Result<Label> {
        if self.matcher.matches(&state) {
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
