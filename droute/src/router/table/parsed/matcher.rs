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

#[cfg(feature = "geoip")]
use super::super::rule::matchers::GeoIp;
use super::super::rule::matchers::{Any, Domain, IpCidr, Matcher, QType, Result as MatcherResult};
use async_trait::async_trait;
use serde::Deserialize;
use std::collections::HashSet;
#[cfg(feature = "geoip")]
use std::path::PathBuf;
use trust_dns_proto::rr::record_type::RecordType;

/// Trait for structs/enums that can convert themselves to matchers
#[async_trait]
pub trait ParMatcherTrait: Send {
    /// Convert itself to a boxed matcher
    async fn build(self) -> MatcherResult<Box<dyn Matcher>>;
}

#[derive(Deserialize, Clone, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
#[cfg(feature = "geoip")]
/// Arguments of the GeoIp.
pub struct ParGeoIp {
    /// Country codes to match on
    pub codes: HashSet<String>,
    /// Path
    pub path: PathBuf,
}

#[cfg(feature = "geoip")]
#[async_trait]
impl ParMatcherTrait for ParGeoIp {
    async fn build(self) -> MatcherResult<Box<dyn Matcher>> {
        // By default, we don't provide any builtin database.
        Ok(Box::new(GeoIp::new(
            self.codes,
            tokio::fs::read(self.path).await?,
        )?))
    }
}

/// Builtin Matchers
/// TODO: Doc
#[derive(Deserialize, Clone, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum BuiltinParMatcher {
    /// Matches any query
    Any,

    /// Matches domains in domain list files specified.
    Domain(Vec<String>),

    /// Matches query types provided. Query types are like AAAA, A, TXT.
    QType(HashSet<RecordType>),

    /// Matches if IP address in the record of the first response is in the list of countries.
    #[cfg(feature = "geoip")]
    GeoIp(ParGeoIp),

    /// Matches if IP address in the record of the first response is in the list of IP CIDR.
    IpCidr(Vec<String>),
}

#[async_trait]
impl ParMatcherTrait for BuiltinParMatcher {
    async fn build(self) -> MatcherResult<Box<dyn Matcher>> {
        Ok(match self {
            Self::Any => Box::new(Any::default()),
            Self::Domain(v) => Box::new(Domain::new(v).await?),
            Self::QType(types) => Box::new(QType::new(types)?),
            Self::IpCidr(s) => Box::new(IpCidr::new(s).await?),
            #[cfg(feature = "geoip")]
            Self::GeoIp(s) => s.build().await?,
        })
    }
}

/// Parsed Matcher
/// You can customize/add more actions using `Extra` variant. If you are OK with the default, use `BuiltinParAction`.
#[derive(Deserialize, Clone, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
#[serde(untagged)]
pub enum ParMatcher<M: ParMatcherTrait> {
    /// Extra matchers. When variants are of the same name, this is of higher priority and may override builtin matchers.
    Extra(M),
    /// Builtin matchers
    Builtin(BuiltinParMatcher),
}

#[async_trait]
impl<M: ParMatcherTrait> ParMatcherTrait for ParMatcher<M> {
    async fn build(self) -> MatcherResult<Box<dyn Matcher>> {
        Ok(match self {
            Self::Builtin(m) => m.build().await?,
            Self::Extra(m) => M::build(m).await?,
        })
    }
}
