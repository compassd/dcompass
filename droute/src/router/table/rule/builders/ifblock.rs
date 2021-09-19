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

use super::{super::actions::Action, BranchBuilder, IfBlock, Result};
use crate::{
    actions::ActionError,
    matchers::{expr::ExprParser, MatchError, Matcher},
    router::table::TableError,
    AsyncTryInto,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;

/// A rule composed of tag name, matcher, and branches.
#[derive(Deserialize, Serialize, Clone)]
#[serde(rename_all = "lowercase")]
#[serde(deny_unknown_fields)]
pub struct IfBlockBuilder<M, A>
where
    M: AsyncTryInto<Box<dyn Matcher>, Error = MatchError>,
    A: AsyncTryInto<Box<dyn Action>, Error = ActionError>,
{
    /// The matching expression.
    #[serde(rename = "if")]
    pub expr: String,

    /// If matcher matches, this branch specifies action and next rule name to route. Defaut to `(Vec::new(), "end".into())`
    #[serde(default = "BranchBuilder::default")]
    #[serde(rename = "then")]
    pub on_match: BranchBuilder<A>,

    /// If matcher doesn't, this branch specifies action and next rule name to route. Defaut to `(Vec::new(), "end".into())`
    #[serde(default = "BranchBuilder::default")]
    #[serde(rename = "else")]
    pub no_match: BranchBuilder<A>,

    #[serde(default)]
    _guard: PhantomData<M>,
}

impl<M, A> IfBlockBuilder<M, A>
where
    M: AsyncTryInto<Box<dyn Matcher>, Error = MatchError>,
    A: AsyncTryInto<Box<dyn Action>, Error = ActionError>,
{
    /// Create a new IfBlockBuilder
    pub fn new(
        expr: impl ToString,
        on_match: BranchBuilder<A>,
        no_match: BranchBuilder<A>,
    ) -> Self {
        Self {
            expr: expr.to_string(),
            on_match,
            no_match,
            _guard: PhantomData,
        }
    }
}

#[async_trait]
impl<M, A> AsyncTryInto<IfBlock> for IfBlockBuilder<M, A>
where
    for<'a> M: AsyncTryInto<Box<dyn Matcher>, Error = MatchError> + Deserialize<'a>,
    A: AsyncTryInto<Box<dyn Action>, Error = ActionError>,
{
    type Error = TableError;

    async fn try_into(self) -> Result<IfBlock> {
        let matcher = Box::new(
            ExprParser
                .build_node::<M>(&self.expr)?
                .trim()
                .try_into()
                .await?,
        );
        let on_match = self.on_match.try_into().await?;
        let no_match = self.no_match.try_into().await?;
        Ok(IfBlock::new(matcher, on_match, no_match))
    }
}
