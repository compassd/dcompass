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

pub mod builder;

use self::{actions::Action, matchers::Matcher};
use super::{super::upstreams::Upstreams, Result, State};
use crate::Label;
use log::*;
use std::collections::HashSet;

/// A unit that composes the `Table`.
pub struct Rule {
    matcher: Box<dyn Matcher>,
    // In the form of (Action, Next)
    on_match: (Vec<Box<dyn Action>>, Label),
    no_match: (Vec<Box<dyn Action>>, Label),
}

impl Rule {
    /// Create a `Rule` from directly.
    /// - `matcher`: A trait object implementing the `Matcher` trait. It determines the action to take and what the next rule is.
    /// - `on_match` and `no_match`: A sequence of actions to take and what the next rule is based on if it matches or not.
    pub fn new(
        matcher: Box<dyn Matcher>,
        on_match: (Vec<Box<dyn Action>>, Label),
        no_match: (Vec<Box<dyn Action>>, Label),
    ) -> Self {
        Self {
            matcher,
            on_match,
            no_match,
        }
    }

    // The destination if the rule is matched
    pub(in super::super) fn on_match_next(&self) -> &Label {
        &self.on_match.1
    }

    // The destination if the rule is not matched
    pub(in super::super) fn no_match_next(&self) -> &Label {
        &self.no_match.1
    }

    pub(in super::super) fn used_upstreams(&self) -> HashSet<Label> {
        let mut h = HashSet::new();
        self.on_match
            .0
            .iter()
            .chain(self.no_match.0.iter()) // Put two iterators together
            .for_each(|a| {
                if let Some(l) = a.used_upstream() {
                    h.insert(l);
                }
            });
        h
    }

    // Returns the label of the next rule.
    pub(in super::super) async fn route(
        &self,
        tag: &Label,
        state: &mut State,
        upstreams: &Upstreams,
        name: &str,
    ) -> Result<Label> {
        if self.matcher.matches(&state) {
            info!("Domain \"{}\" matches at rule `{}`", name, tag);
            for action in &self.on_match.0 {
                action.act(state, upstreams).await?;
            }
            Ok(self.on_match.1.clone())
        } else {
            info!("Domain \"{}\" doesn't match at rule `{}`", name, tag);
            for action in &self.no_match.0 {
                action.act(state, upstreams).await?;
            }
            Ok(self.no_match.1.clone())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{State, Upstreams};
    use crate::builders::*;

    #[tokio::test]
    async fn rule_logic() {
        let rule = RuleBuilder::new(
            BuiltinMatcherBuilder::Any,
            BranchBuilder::<BuiltinActionBuilder>::new(vec![], "yes"),
            BranchBuilder::new(vec![], "no"),
        )
        .build()
        .await
        .unwrap();
        assert_eq!(
            rule.route(
                &"mock".into(), // This doesn't matter
                &mut State::default(),
                &Upstreams::new(vec![].into_iter().collect()).unwrap(),
                "foo"
            )
            .await
            .unwrap(),
            "yes".into()
        );
    }
}
