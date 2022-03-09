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
#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "lowercase")]
pub enum MatcherBuilders {
    /// Matches domains in domain list files specified.
    Domain(DomainBuilder),

    /// Matches query types provided. Query types are like AAAA, A, TXT.
    QType(QTypeBuilder),

    /// Matches if IP address in the record of the first response is in the list of countries.
    GeoIp {
        codes: HashSet<String>,
        #[serde(default)]
        path: Option<PathBuf>,
    },

    /// Matches if IP address in the record of the first response is in the list of IP CIDR.
    IpCidr(IpCidrBuilder),

    /// Matches if header fulfills given condition
    Header {
        /// Matching condition
        cond: HeaderCond,
        /// Should we match on query msg?
        #[serde(default)]
        query: bool,
    },
}

// TODO: This should be derived
#[async_trait]
impl AsyncTryInto<Box<dyn Matcher>> for MatcherBuilders {
    async fn async_try_into(self) -> Result<Box<dyn Matcher>> {
        Ok(match self {
            Self::Domain(v) => Box::new(v.async_try_into().await?),
            Self::QType(q) => Box::new(q.async_try_into().await?),
            Self::Header { cond, query } => Box::new(Header { cond, query }),
            Self::IpCidr(s) => Box::new(s.async_try_into().await?),
            Self::GeoIp { path, codes } => Box::new(GeoIp::new(
                codes,
                if let Some(p) = path {
                    tokio::fs::read(p).await?
                } else {
                    get_builtin_db()?
                },
            )?),
        })
    }

    type Error = MatchError;
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
    // This seems to be impossible to reach.
    NonZeroU32::new(6000).unwrap()
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
