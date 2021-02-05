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

use super::super::rule::actions::{Action, Disable, Query, Result as ActionResult};
use crate::Label;
use async_trait::async_trait;
use serde::Deserialize;

/// Trait for structs/enums that can convert themselves to actions.
#[async_trait]
pub trait ParActionTrait: Send {
    /// Convert itself to a boxed action
    async fn build(self) -> ActionResult<Box<dyn Action>>;
}

/// Builtin Parsed Actions
/// This is a default enum which implements serde's deserialize trait to help you parse stuff into an action.
/// You can rewrite your own parsed enum to support customized action and more functionalities on your needs.
#[serde(rename_all = "lowercase")]
#[derive(Clone, Deserialize)]
pub enum BuiltinParAction {
    /// Set response to a message that "disables" requestor to retry.
    Disable,

    /// Send query through an upstream with the specified tag name.
    Query(Label),
}

#[async_trait]
impl ParActionTrait for BuiltinParAction {
    // Should only be accessible from `Rule`.
    async fn build(self) -> ActionResult<Box<dyn Action>> {
        Ok(match self {
            Self::Disable => Box::new(Disable::default()),
            Self::Query(t) => Box::new(Query::new(t)),
        })
    }
}

/// Parsed Actions
/// You can customize/add more actions using `Extra` variant. If you are OK with the default, use `BuiltinParAction`.
#[serde(rename_all = "lowercase")]
#[derive(Clone, Deserialize)]
#[serde(untagged)]
pub enum ParAction<A: ParActionTrait> {
    /// Extra actions. When variants are of the same name, this is of higher priority and may override builtin matchers.
    Extra(A),

    /// Builtin actions
    Builtin(BuiltinParAction),
}

#[async_trait]
impl<A: ParActionTrait> ParActionTrait for ParAction<A> {
    // Should only be accessible from `Rule`.
    async fn build(self) -> ActionResult<Box<dyn Action>> {
        Ok(match self {
            Self::Builtin(a) => a.build().await?,
            Self::Extra(a) => A::build(a).await?,
        })
    }
}
