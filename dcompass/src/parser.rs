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

use droute::router::{filter::Rule, upstream::Upstream};
use log::LevelFilter;
use serde::Deserialize;
use std::net::SocketAddr;

pub const GET_U32_MAX: fn() -> u32 = || u32::MAX;

#[derive(Deserialize, Clone)]
#[serde(remote = "LevelFilter")]
enum LevelFilterDef {
    Off,
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

#[derive(Deserialize, Clone)]
pub struct Parsed<L> {
    pub rules: Vec<Rule<L>>,
    pub upstreams: Vec<Upstream<L>>,
    pub default_tag: L,
    pub address: SocketAddr,
    pub disable_ipv6: bool,
    pub cache_size: usize,
    #[serde(with = "LevelFilterDef")]
    pub verbosity: LevelFilter,
    // Set default ratelimit to maximum, resulting in non-blocking (non-throttling) mode forever as the burst time is infinity.
    #[serde(default = "GET_U32_MAX")]
    pub ratelimit: u32,
}
