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
/// A module containing rule-related builder facilities.
pub mod builders;
/// A module containing built-in matchers, matcher trait, and more.
pub mod matchers;

use self::{actions::Action, matchers::Matcher};
use super::{super::upstreams::Upstreams, Result, State};
use crate::Label;
use async_trait::async_trait;
use log::*;
use std::collections::HashSet;

#[async_trait]
pub trait Rule: Send + Sync {
    // `name` refers to the name of the Rule itself
    // Returns the label of the next rule.
    async fn route(
        &self,
        tag: &Label,
        state: &mut State,
        upstreams: &Upstreams,
        name: &str,
    ) -> Result<Label>;

    // Possible destinations of this rule block
    // TODO: Can we change it to a more cost friendly version?
    fn dsts(&self) -> HashSet<Label>;

    fn used_upstreams(&self) -> HashSet<Label>;
}

/// If-like control flow rule
pub struct IfBlock {
    matcher: Box<dyn Matcher>,
    // In the form of (Action, Next)
    on_match: (Vec<Box<dyn Action>>, Label),
    no_match: (Vec<Box<dyn Action>>, Label),
}

impl IfBlock {
    /// Create a if-like `Rule` from directly.
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
}

#[async_trait]
impl Rule for IfBlock {
    fn used_upstreams(&self) -> HashSet<Label> {
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

    async fn route(
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

    fn dsts(&self) -> HashSet<Label> {
        let mut h = HashSet::new();
        h.insert(self.on_match.1.clone());
        h.insert(self.no_match.1.clone());
        h
    }
}

// TODO: Add an sequence rule

#[cfg(test)]
mod tests {
    use super::super::{State, Upstreams};
    use crate::{builders::*, AsyncTryInto};

    #[tokio::test]
    async fn rule_logic() {
        let rule = RuleBuilders::IfBlock(IfBlockBuilder {
            matcher: BuiltinMatcherBuilders::Any,
            on_match: BranchBuilder::<BuiltinActionBuilders>::new("yes"),
            no_match: BranchBuilder::<BuiltinActionBuilders>::new("no"),
        })
        .try_into()
        .await
        .unwrap();
        assert_eq!(
            rule.route(
                &"mock".into(), // This doesn't matter
                &mut State::default(),
                &Upstreams::new(
                    vec![].into_iter().collect(),
                    std::num::NonZeroUsize::new(1).unwrap()
                )
                .unwrap(),
                "foo"
            )
            .await
            .unwrap(),
            "yes".into()
        );
    }
}
