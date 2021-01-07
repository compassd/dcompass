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
    actions::{Action, Disable, Query, Result as ActionResult},
    matchers::{Any, Domain, IpCidr, IpTarget, Matcher, QType, Result as MatcherResult},
};
use crate::Label;
use async_trait::async_trait;
use hashbrown::HashSet;
use serde::{
    de::{Deserializer, Error as _, SeqAccess, Visitor},
    Deserialize,
};
use std::marker::PhantomData;
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
pub trait ParAction {
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

    /// Send query through an upstream with the specified tag name.
    Query(Label),
}

#[async_trait]
impl ParAction for DefParAction {
    // Should only be accessible from `Rule`.
    async fn build(self) -> ActionResult<Box<dyn Action>> {
        Ok(match self {
            Self::Disable => Box::new(Disable::default()),
            Self::Query(t) => Box::new(Query::new(t)),
        })
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

/// A parsed branch of a rule.
#[derive(Clone)]
pub struct ParMatchArm<A> {
    seq: Vec<A>,
    next: Label,
}

// This customized deserialization process accept branches of this form:
// ```
// - Action1
// - Action2
// - ...
// - next
// ```
// Here the lifetime constraints are compatible with the ones from serde derivation. We are not adding them to `ParAction` as they are gonna be automatically generated by serde.
impl<'de, A: ParAction + Deserialize<'de>> Deserialize<'de> for ParMatchArm<A> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Either<A: ParAction> {
            Action(A),
            Tag(Label),
        }

        struct ArmVisitor<A> {
            // Dummy variable for visitor to be constrained by `A`.
            t: PhantomData<A>,
        }

        impl<'de, A: ParAction + Deserialize<'de>> Visitor<'de> for ArmVisitor<A> {
            type Value = ParMatchArm<A>;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a list of actions with the tag of the next rule as the last element")
            }

            fn visit_seq<V: SeqAccess<'de>>(self, mut sv: V) -> Result<Self::Value, V::Error> {
                let mut seq = Vec::new();

                // Get the `next` from the first element of the type Label.
                let next = loop {
                    match sv.next_element::<Either<A>>()? {
                        Some(Either::Action(a)) => seq.push(a),
                        Some(Either::Tag(l)) => break l,
                        None => return Err(V::Error::custom("Missing the tag of the next rule")),
                    }
                };

                // Verify that this is indeed the last element.
                if sv.next_element::<Either<A>>()?.is_some() {
                    return Err(V::Error::custom("Extra element after the tag"));
                }

                Ok(Self::Value { seq, next })
            }
        }

        deserializer.deserialize_seq(ArmVisitor::<A> { t: PhantomData })
    }
}

impl<A: ParAction> ParMatchArm<A> {
    // Build the ParMatchArm into the internal used tuple by `Rule`.
    pub(super) async fn build(self) -> ActionResult<(Vec<Box<dyn Action>>, Label)> {
        let mut built: Vec<Box<dyn Action>> = Vec::new();
        for a in self.seq {
            // TODO: Can we make this into a map?
            built.push(a.build().await?);
        }
        Ok((built, self.next))
    }
}

impl<A> Default for ParMatchArm<A> {
    fn default() -> Self {
        Self {
            seq: vec![],
            next: "end".into(),
        }
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

    /// If matcher matches, this branch specifies action and next rule name to route. Defaut to `(Vec::new(), "end".into())`
    // `serde` erroneously asserts `A: Default`, this is used to mitigate that assertion.
    #[serde(default = "ParMatchArm::default")]
    #[serde(rename = "then")]
    pub on_match: ParMatchArm<A>,

    /// If matcher doesn't, this branch specifies action and next rule name to route. Defaut to `(Vec::new(), "end".into())`
    #[serde(default = "ParMatchArm::default")]
    #[serde(rename = "else")]
    pub no_match: ParMatchArm<A>,
}
