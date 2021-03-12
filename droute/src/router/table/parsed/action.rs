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

use super::super::rule::actions::{Action, Blackhole, CacheMode, Query, Result as ActionResult};
use crate::Label;
use async_trait::async_trait;
use serde::{Deserialize, Deserializer};

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
    Blackhole,

    /// Send query through an upstream with the specified tag name.
    #[serde(deserialize_with = "de_query")]
    Query(Label, CacheMode),
}

// Deserialize either a tag with default policy or a tag with a policy for query.
fn de_query<'de, D>(deserializer: D) -> Result<(Label, CacheMode), D::Error>
where
    D: Deserializer<'de>,
{
    #[serde(rename_all = "lowercase")]
    #[derive(Clone, Deserialize)]
    struct ExplicitQuery {
        tag: Label,
        cache_policy: CacheMode,
    }

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Either {
        Explicit(ExplicitQuery),
        Default(Label),
    }

    Ok(match Either::deserialize(deserializer)? {
        Either::Explicit(ExplicitQuery { tag, cache_policy }) => (tag, cache_policy),
        Either::Default(t) => (t, CacheMode::default()),
    })
}

#[async_trait]
impl ParActionTrait for BuiltinParAction {
    // Should only be accessible from `Rule`.
    async fn build(self) -> ActionResult<Box<dyn Action>> {
        Ok(match self {
            Self::Blackhole => Box::new(Blackhole::default()),
            Self::Query(t, m) => Box::new(Query::new(t, m)),
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
