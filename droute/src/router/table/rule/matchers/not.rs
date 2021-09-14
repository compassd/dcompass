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

use super::{super::super::State, MatchError, Matcher};
use crate::AsyncTryInto;
use async_trait::async_trait;
use serde::Deserialize;

/// A matcher that matches if sub-matcher doesn't match.
pub struct Not(Box<dyn Matcher>);

impl Not {
    /// Create a new not matcher
    pub fn new(m: Box<dyn Matcher>) -> Self {
        Self(m)
    }
}

impl Matcher for Not {
    fn matches(&self, s: &State) -> bool {
        !self.0.matches(s)
    }
}

/// A builder for not matcher
#[derive(Deserialize, Clone)]
pub struct NotBuilder<M: AsyncTryInto<Box<dyn Matcher>, Error = MatchError>>(Box<M>);

impl<M: AsyncTryInto<Box<dyn Matcher>, Error = MatchError>> NotBuilder<M> {
    /// Create a new any builder
    pub fn new(m: M) -> Self {
        Self(Box::new(m))
    }
}

#[async_trait]
impl<M: AsyncTryInto<Box<dyn Matcher>, Error = MatchError>> AsyncTryInto<Not> for NotBuilder<M> {
    type Error = MatchError;

    async fn try_into(self) -> Result<Not, MatchError> {
        Ok(Not(self.0.try_into().await?))
    }
}

#[cfg(test)]
mod tests {
    use crate::matchers::Matcher;

    use super::{super::always::Always, Not, State};

    #[test]
    fn basic() {
        assert!(!Not(Box::new(Always)).matches(&State::default()));
        assert!(Not(Box::new(Not(Box::new(Always)))).matches(&State::default()))
    }
}
