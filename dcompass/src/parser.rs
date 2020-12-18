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

use async_trait::async_trait;
use droute::{
    matchers::*,
    parsed::{DefParAction, DefParUpstreamKind, ParGeoIp, ParMatcher, ParRule, ParUpstream},
};
use hashbrown::HashSet;
use log::LevelFilter;
use serde::Deserialize;
use std::net::SocketAddr;
use trust_dns_proto::rr::record_type::RecordType;

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
pub enum MyParMatcher {
    Any,
    Domain(Vec<String>),
    QType(HashSet<RecordType>),
    GeoIp(ParGeoIp),
}

#[async_trait]
impl ParMatcher for MyParMatcher {
    async fn build(self) -> Result<Box<dyn Matcher>> {
        Ok(match self {
            Self::Any => Box::new(Any::default()),
            Self::Domain(v) => Box::new(Domain::new(v).await?),
            Self::QType(types) => Box::new(QType::new(types)?),
            Self::GeoIp(s) => Box::new(GeoIp::new(s.on, s.codes, s.path, get_builtin_db())?),
        })
    }
}

fn get_builtin_db() -> Option<Vec<u8>> {
    #[cfg(feature = "geoip-maxmind")]
    return Some(include_bytes!("../../data/full.mmdb").to_vec());
    #[cfg(all(feature = "geoip-cn", not(feature = "geoip-maxmind")))]
    return Some(include_bytes!("../../data/cn.mmdb").to_vec());
    #[cfg(not(any(feature = "geoip-cn", feature = "geoip-maxmind")))]
    None
}

#[derive(Deserialize, Clone)]
pub struct Parsed {
    pub table: Vec<ParRule<MyParMatcher, DefParAction>>,
    pub upstreams: Vec<ParUpstream<DefParUpstreamKind>>,
    pub address: SocketAddr,
    pub cache_size: usize,
    #[serde(with = "LevelFilterDef")]
    pub verbosity: LevelFilter,
    // Set default ratelimit to maximum, resulting in non-blocking (non-throttling) mode forever as the burst time is infinity.
    #[serde(default = "GET_U32_MAX")]
    pub ratelimit: u32,
}
