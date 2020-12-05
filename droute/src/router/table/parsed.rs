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

use super::{
    rule::{
        actions::{
            disable::Disable as ActDisable, query::Query as ActQuery, skip::Skip as ActSkip, Action,
        },
        matchers::{
            any::Any as MatAny, domain::Domain as MatDomain, qtype::QType as MatQType, Matcher,
        },
    },
    Result,
};
use crate::Label;
use hashbrown::HashSet;
use serde::Deserialize;
use trust_dns_proto::rr::record_type::RecordType;

#[derive(Deserialize, Clone, Eq, PartialEq, Hash)]
#[serde(remote = "RecordType")]
enum RecordTypeDef {
    A,
    AAAA,
    ANAME,
    ANY,
    AXFR,
    CAA,
    CNAME,
    IXFR,
    MX,
    NAPTR,
    NS,
    NULL,
    OPENPGPKEY,
    OPT,
    PTR,
    SOA,
    SRV,
    SSHFP,
    TLSA,
    TXT,
    Unknown(u16),
    ZERO,
}

/// Type wrapper for `RecordType`.
/// TODO: remove after trust-dns-proto supports serde
#[derive(Clone, Deserialize, Eq, PartialEq, Hash)]
pub struct Adapter(#[serde(with = "RecordTypeDef")] RecordType);

/// Actions to take
#[derive(Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum ParsedAction {
    /// Set response to a message that "disables" requestor to retry.
    Disable,

    /// Do nothing on either response or query.
    Skip,

    /// Send query through an upstream with the specified tag name.
    Query(Label),
}

impl ParsedAction {
    pub(super) fn convert(self) -> Box<dyn Action> {
        match self {
            Self::Disable => Box::new(ActDisable::new(self)),
            Self::Skip => Box::new(ActSkip::new(self)),
            Self::Query(_) => Box::new(ActQuery::new(self)),
        }
    }
}

/// Matchers to use
#[derive(Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum ParsedMatcher {
    /// Matches any query
    Any,

    /// Matches domains in domain list files specified.
    Domain(Vec<String>),

    /// Matches query types provided. Query types are like AAAA, A, TXT.
    QType(HashSet<Adapter>),
}

impl ParsedMatcher {
    pub(super) async fn convert(self) -> Result<Box<dyn Matcher>> {
        Ok(match self {
            Self::Any => Box::new(MatAny::new()),
            Self::Domain(_) => Box::new(MatDomain::new(self).await?),
            Self::QType(types) => {
                let converted = types.iter().map(|s| s.0).collect();
                Box::new(MatQType::new(converted)?)
            }
        })
    }
}

/// A rule composed of tag name, matcher, and branches.
#[derive(Deserialize, Clone)]
pub struct ParsedRule {
    /// The tag name of the rule
    pub tag: Label,

    /// The matcher rule uses.
    #[serde(rename = "if")]
    pub matcher: ParsedMatcher,

    /// If matcher matches, this branch specifies action and next rule name to route. Defaut to `(ParsedAction::Skip, "end".into())`
    #[serde(default = "default_branch")]
    #[serde(rename = "then")]
    pub on_match: (ParsedAction, Label),

    /// If matcher doesn't, this branch specifies action and next rule name to route. Defaut to `(ParsedAction::Skip, "end".into())`
    #[serde(default = "default_branch")]
    #[serde(rename = "else")]
    pub no_match: (ParsedAction, Label),
}

fn default_branch() -> (ParsedAction, Label) {
    (ParsedAction::Skip, "end".into())
}
