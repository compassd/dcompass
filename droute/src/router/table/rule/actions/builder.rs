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

pub use super::query::QueryBuilder;
use super::{Action, ActionError, Blackhole, CacheMode, Result as ActionResult};
use crate::{AsyncTryInto, Label};
use async_trait::async_trait;
use serde::{Deserialize, Deserializer};

/// Builtin Parsed Actions
/// This is a default enum which implements serde's deserialize trait to help you parse stuff into an action.
/// You can rewrite your own parsed enum to support customized action and more functionalities on your needs.
#[derive(Clone, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BuiltinActionBuilders {
    /// Set response to a message that "disables" requestor to retry.
    Blackhole,

    /// Send query through an upstream with the specified tag name.
    #[serde(deserialize_with = "de_query")]
    Query(QueryBuilder),
}

// Deserialize either a tag with default policy or a tag with a policy for query.
fn de_query<'de, D>(deserializer: D) -> Result<QueryBuilder, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Clone, Deserialize)]
    #[serde(rename_all = "lowercase")]
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

    Ok(match Either::deserialize(deserializer) {
        Ok(Either::Explicit(ExplicitQuery { tag, cache_policy })) => QueryBuilder(tag, cache_policy),
        Ok(Either::Default(t)) => QueryBuilder(t, CacheMode::default()),
	// Currently, because BranchBuilder cannot provide precise information, this error message doesn't take effect.
	Err(_) => return Err(serde::de::Error::custom("Failed to parse query action using either explicit form (tag, cache_policy) or the simplified form (tag only)"))
    })
}

#[async_trait]
impl AsyncTryInto<Box<dyn Action>> for BuiltinActionBuilders {
    // Should only be accessible from `Rule`.
    async fn try_into(self) -> ActionResult<Box<dyn Action>> {
        Ok(match self {
            Self::Blackhole => Box::new(Blackhole),
            Self::Query(q) => Box::new(q.try_into().await?),
        })
    }

    type Error = ActionError;
}
