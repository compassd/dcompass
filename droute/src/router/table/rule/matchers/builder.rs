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
use super::GeoIp;
use super::{Any, Domain, IpCidr, Matcher, QType, ResourceType, Result as MatcherResult};
use async_trait::async_trait;
use serde::{de::Deserializer, Deserialize};
use std::collections::HashSet;
#[cfg(feature = "geoip")]
use std::path::PathBuf;
use trust_dns_proto::rr::record_type::RecordType;

/// Trait for structs/enums that can build themselves into matchers
#[async_trait]
pub trait MatcherBuilder: Send {
    /// Convert itself to a boxed matcher
    async fn build(self) -> MatcherResult<Box<dyn Matcher>>;
}

#[derive(Deserialize, Clone, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
#[cfg(feature = "geoip")]
/// Arguments of the GeoIp.
pub struct GeoIpBuilder {
    /// Country codes to match on
    pub codes: HashSet<String>,
    /// Path
    pub path: PathBuf,
}

#[cfg(feature = "geoip")]
#[async_trait]
impl MatcherBuilder for GeoIpBuilder {
    async fn build(self) -> MatcherResult<Box<dyn Matcher>> {
        // By default, we don't provide any builtin database.
        Ok(Box::new(GeoIp::new(
            self.codes,
            tokio::fs::read(self.path).await?,
        )?))
    }
}

/// The builder for Builtin Matchers
#[derive(Deserialize, Clone, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum BuiltinMatcherBuilder {
    /// Matches any query
    Any,

    /// Matches domains in domain list files specified.
    Domain(Vec<ResourceType>),

    /// Matches query types provided. Query types are like AAAA, A, TXT.
    QType(HashSet<RecordType>),

    /// Matches if IP address in the record of the first response is in the list of countries.
    #[cfg(feature = "geoip")]
    GeoIp(GeoIpBuilder),

    /// Matches if IP address in the record of the first response is in the list of IP CIDR.
    IpCidr(Vec<String>),
}

#[async_trait]
impl MatcherBuilder for BuiltinMatcherBuilder {
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
#[derive(Clone, Eq, PartialEq)]
pub enum AggregatedMatcherBuilder<M: MatcherBuilder> {
    /// Extra matchers. When variants are of the same name, this is of higher priority and may override builtin matchers.
    Extra(M),
    /// Builtin matchers
    Builtin(BuiltinMatcherBuilder),
}

impl<'de, M: MatcherBuilder + Deserialize<'de>> Deserialize<'de> for AggregatedMatcherBuilder<M> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Either<M: MatcherBuilder> {
            Other(M),
            Default(BuiltinMatcherBuilder),
        }

        Ok(match Either::deserialize(deserializer) {
            Ok(Either::Other(m)) => AggregatedMatcherBuilder::Extra(m),
            Ok(Either::Default(m)) => AggregatedMatcherBuilder::Builtin(m),
            Err(_) => return Err(serde::de::Error::custom("Make sure you are using an existing matcher format and the fields are of correct types. Failed to parse the matcher")),
        })
    }
}

#[async_trait]
impl<M: MatcherBuilder> MatcherBuilder for AggregatedMatcherBuilder<M> {
    async fn build(self) -> MatcherResult<Box<dyn Matcher>> {
        Ok(match self {
            Self::Builtin(m) => m.build().await?,
            Self::Extra(m) => M::build(m).await?,
        })
    }
}
