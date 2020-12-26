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

#[cfg(feature = "geoip")]
use super::rule::matchers::GeoIp;
use super::rule::{
    actions::{Action, Disable, Query, Result as ActionResult, Skip},
    matchers::{Any, Domain, IpCidr, IpTarget, Matcher, QType, Result as MatcherResult},
};
use crate::Label;
use async_trait::async_trait;
use hashbrown::HashSet;
use serde::Deserialize;
#[cfg(feature = "geoip")]
use std::path::PathBuf;
use trust_dns_proto::rr::record_type::RecordType;

/// Trait for structs/enums that can convert themselves to matchers
#[async_trait]
pub trait ParMatcher {
    /// Convert itself to a boxed matcher
    async fn build(self) -> MatcherResult<Box<dyn Matcher>>;
}

/// Trait for structs/enums that can convert themselves to actions.
#[async_trait]
pub trait ParAction: Default {
    /// Convert itself to a boxed action
    async fn build(self) -> ActionResult<Box<dyn Action>>;
}

/// Def(ault) Par(sed) Action
/// This is a default enum which implements serde's deserialize trait to help you parse stuff into an action.
/// You can rewrite your own parsed enum to support customized action and more functionalities on your needs.
#[serde(rename_all = "lowercase")]
#[derive(Clone, Deserialize)]
pub enum DefParAction {
    /// Set response to a message that "disables" requestor to retry.
    Disable,

    /// Do nothing on either response or query.
    Skip,

    /// Send query through an upstream with the specified tag name.
    Query(Label),
}

#[async_trait]
impl ParAction for DefParAction {
    // Should only be accessible from `Rule`.
    async fn build(self) -> ActionResult<Box<dyn Action>> {
        Ok(match self {
            Self::Disable => Box::new(Disable::default()),
            Self::Skip => Box::new(Skip::default()),
            Self::Query(t) => Box::new(Query::new(t)),
        })
    }
}

impl Default for DefParAction {
    fn default() -> Self {
        Self::Skip
    }
}

#[derive(Deserialize, Clone, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
#[cfg(feature = "geoip")]
/// Arguments of the GeoIp.
pub struct ParGeoIp {
    /// What to match on
    pub on: IpTarget,
    /// Country codes to match on
    pub codes: HashSet<String>,
    /// Path
    #[serde(default = "default_geoip_path")]
    pub path: Option<PathBuf>,
}

#[derive(Deserialize, Clone, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
/// Arguments of the IP CIDR matcher.
pub struct ParIpCidr {
    /// What to match on
    pub on: IpTarget,
    /// list of files that contain IP CIDR entries
    pub path: Vec<String>,
}

#[cfg(feature = "geoip")]
fn default_geoip_path() -> Option<PathBuf> {
    None
}

/// Def(ault) Par(sed) Matcher
/// This is a default enum which implements serde's deserialize trait to help you parse stuff into a matcher.
/// You can rewrite your own parsed enum to support customized matcher and more functionalities on your needs.
#[derive(Deserialize, Clone, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum DefParMatcher {
    /// Matches any query
    Any,

    /// Matches domains in domain list files specified.
    Domain(Vec<String>),

    /// Matches query types provided. Query types are like AAAA, A, TXT.
    QType(HashSet<RecordType>),

    /// Matches if IP address in the record of the first response is in the list of countries. If specified, this can also match against source IP.
    #[cfg(feature = "geoip")]
    GeoIp(ParGeoIp),

    /// Matches if IP address in the record of the first response is in the list of IP CIDR. If specified, this can also match against source IP.
    IpCidr(ParIpCidr),
}

#[async_trait]
impl ParMatcher for DefParMatcher {
    async fn build(self) -> MatcherResult<Box<dyn Matcher>> {
        Ok(match self {
            Self::Any => Box::new(Any::default()),
            Self::Domain(v) => Box::new(Domain::new(v).await?),
            Self::QType(types) => Box::new(QType::new(types)?),
            Self::IpCidr(s) => Box::new(IpCidr::new(s.on, s.path).await?),
            // By default, we don't provide any builtin database.
            #[cfg(feature = "geoip")]
            Self::GeoIp(s) => Box::new(GeoIp::new(s.on, s.codes, s.path, None)?),
        })
    }
}

/// A rule composed of tag name, matcher, and branches.
#[derive(Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub struct ParRule<M: ParMatcher, A: ParAction> {
    /// The tag name of the rule
    pub tag: Label,

    /// The matcher rule uses.
    #[serde(rename = "if")]
    pub matcher: M,

    /// If matcher matches, this branch specifies action and next rule name to route. Defaut to `(ParsedAction::Skip, "end".into())`
    #[serde(default = "default_branch")]
    #[serde(rename = "then")]
    pub on_match: (A, Label),

    /// If matcher doesn't, this branch specifies action and next rule name to route. Defaut to `(ParsedAction::Skip, "end".into())`
    #[serde(default = "default_branch")]
    #[serde(rename = "else")]
    pub no_match: (A, Label),
}

fn default_branch<A: ParAction>() -> (A, Label) {
    (A::default(), "end".into())
}
