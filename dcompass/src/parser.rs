// Copyright 2020, 2021 LEXUGE
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

use async_trait::async_trait;
use droute::{builders::*, matchers::*, AsyncTryInto, Label};
use log::LevelFilter;
use serde::Deserialize;
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    num::{NonZeroU32, NonZeroUsize},
    path::PathBuf,
};

#[derive(Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
#[serde(remote = "LevelFilter")]
enum LevelFilterDef {
    Off,
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

// Customized matchers
#[derive(Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum MatcherBuilders {
    /// Matches any query
    Any,

    /// Matches domains in domain list files specified.
    Domain(DomainBuilder),

    /// Matches query types provided. Query types are like AAAA, A, TXT.
    QType(QTypeBuilder),

    /// Matches if IP address in the record of the first response is in the list of countries.
    GeoIp(MyGeoIp),

    /// Matches if IP address in the record of the first response is in the list of IP CIDR.
    IpCidr(IpCidrBuilder),
}

// TODO: This should be derived
#[async_trait]
impl AsyncTryInto<Box<dyn Matcher>> for MatcherBuilders {
    async fn try_into(self) -> Result<Box<dyn Matcher>> {
        Ok(match self {
            Self::Any => Box::new(Any),
            Self::Domain(v) => Box::new(v.try_into().await?),
            Self::QType(q) => Box::new(q.try_into().await?),
            Self::IpCidr(s) => Box::new(s.try_into().await?),
            Self::GeoIp(g) => Box::new(g.try_into().await?),
        })
    }

    type Error = MatchError;
}

#[derive(Deserialize, Clone, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
#[serde(rename = "geoip")]
#[serde(deny_unknown_fields)]
pub struct MyGeoIp {
    codes: HashSet<String>,
    #[serde(default)]
    path: Option<PathBuf>,
}

#[async_trait]
impl AsyncTryInto<GeoIp> for MyGeoIp {
    type Error = MatchError;

    async fn try_into(self) -> Result<GeoIp> {
        Ok(GeoIp::new(
            self.codes,
            if let Some(p) = self.path {
                tokio::fs::read(p).await?
            } else {
                get_builtin_db()?
            },
        )?)
    }
}

// If both geoip-maxmind and geoip-cn are enabled, geoip-maxmind will be used
fn get_builtin_db() -> Result<Vec<u8>> {
    #[cfg(feature = "geoip-maxmind")]
    return Ok(include_bytes!("../../data/full.mmdb").to_vec());
    #[cfg(all(feature = "geoip-cn", not(feature = "geoip-maxmind")))]
    return Ok(include_bytes!("../../data/cn.mmdb").to_vec());
    #[cfg(not(any(feature = "geoip-cn", feature = "geoip-maxmind")))]
    Err(MatchError::NoBuiltInDb)
}

fn default_cache_size() -> NonZeroUsize {
    NonZeroUsize::new(2048).unwrap()
}

fn default_rate_limit() -> NonZeroU32 {
    // Is this a good default?
    NonZeroU32::new(100).unwrap()
}

#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Parsed {
    pub table: TableBuilder<RuleBuilders<MatcherBuilders, BuiltinActionBuilders>>,
    // We are not using UpstreamsBuilder because flatten ruins error location.
    pub upstreams: HashMap<Label, UpstreamBuilder>,
    #[serde(default = "default_cache_size")]
    pub cache_size: NonZeroUsize,
    pub address: SocketAddr,
    #[serde(with = "LevelFilterDef")]
    pub verbosity: LevelFilter,
    // Set default ratelimit to maximum, resulting in non-blocking (non-throttling) mode forever as the burst time is infinity.
    #[serde(default = "default_rate_limit")]
    pub ratelimit: NonZeroU32,
}
