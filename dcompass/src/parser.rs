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
use droute::{
    matchers::*,
    parsed::{
        BuiltinParAction, DefParUpstreamKind, ParMatcher, ParMatcherTrait, ParRule, ParUpstream,
    },
};
use log::LevelFilter;
use serde::Deserialize;
use std::{collections::HashSet, net::SocketAddr, path::PathBuf};

pub const GET_U32_MAX: fn() -> u32 = || u32::MAX;

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

#[derive(Deserialize, Clone, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
#[serde(deny_unknown_fields)]
pub enum MyGeoIp {
    GeoIp {
        codes: HashSet<String>,
        #[serde(default = "default_geoip_path")]
        path: Option<PathBuf>,
    },
}

fn default_geoip_path() -> Option<PathBuf> {
    None
}

#[async_trait]
impl ParMatcherTrait for MyGeoIp {
    async fn build(self) -> Result<Box<dyn Matcher>> {
        Ok(match self {
            Self::GeoIp { codes, path } => Box::new(GeoIp::new(
                codes,
                if let Some(p) = path {
                    tokio::fs::read(p).await?
                } else {
                    get_builtin_db()?
                },
            )?),
        })
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

#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Parsed {
    pub table: Vec<ParRule<ParMatcher<MyGeoIp>, BuiltinParAction>>,
    pub upstreams: Vec<ParUpstream<DefParUpstreamKind>>,
    pub address: SocketAddr,
    pub cache_size: usize,
    #[serde(with = "LevelFilterDef")]
    pub verbosity: LevelFilter,
    // Set default ratelimit to maximum, resulting in non-blocking (non-throttling) mode forever as the burst time is infinity.
    #[serde(default = "GET_U32_MAX")]
    pub ratelimit: u32,
}
