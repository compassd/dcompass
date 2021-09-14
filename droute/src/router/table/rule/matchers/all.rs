// Copyright 2021 LEXUGE
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

use super::{super::super::State, MatchError, Matcher};
use crate::AsyncTryInto;
use async_trait::async_trait;
use serde::Deserialize;

/// A matcher that matches if all sub matchers match.
pub struct All(Vec<Box<dyn Matcher>>);

impl All {
    /// Create a new All matcher
    pub fn new(v: Vec<Box<dyn Matcher>>) -> Self {
        Self(v)
    }
}

impl Matcher for All {
    fn matches(&self, s: &State) -> bool {
        self.0.iter().map(|x| x.matches(s)).all(|x| x)
    }
}

/// A builder for any matcher
#[derive(Deserialize, Clone)]
pub struct AllBuilder<M: AsyncTryInto<Box<dyn Matcher>, Error = MatchError>>(Vec<M>);

impl<M: AsyncTryInto<Box<dyn Matcher>, Error = MatchError>> Default for AllBuilder<M> {
    fn default() -> Self {
        Self::new()
    }
}

impl<M: AsyncTryInto<Box<dyn Matcher>, Error = MatchError>> AllBuilder<M> {
    /// Create a new any builder
    pub fn new() -> Self {
        Self(Vec::new())
    }

    /// Add a matcher builder
    pub fn add_matcher(mut self, m: M) -> Self {
        self.0.push(m);
        self
    }
}

#[async_trait]
impl<M: AsyncTryInto<Box<dyn Matcher>, Error = MatchError>> AsyncTryInto<All> for AllBuilder<M> {
    type Error = MatchError;

    async fn try_into(self) -> Result<All, MatchError> {
        let mut v = Vec::new();
        for builder in self.0 {
            v.push(builder.try_into().await?);
        }
        Ok(All(v))
    }
}

#[cfg(test)]
mod tests {
    use crate::matchers::Matcher;

    use super::{
        super::{always::Always, any::Any, not::Not},
        All, State,
    };

    #[test]
    fn basic() {
        assert!(All(vec![
            Box::new(Always),
            Box::new(Not::new(Box::new(Not::new(Box::new(Always))))),
            Box::new(Any::new(vec![
                Box::new(Always),
                Box::new(Not::new(Box::new(Always)))
            ]))
        ])
        .matches(&State::default()))
    }
}
