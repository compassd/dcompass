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

use super::upstream::Upstream;
use dmatcher::Label;
use log::LevelFilter;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

#[derive(Serialize, Deserialize, Clone)]
pub struct Rule {
    pub dst: Label,
    pub path: String,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(remote = "LevelFilter")]
enum LevelFilterDef {
    Off,
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Parsed {
    pub rules: Vec<Rule>,
    pub upstreams: Vec<Upstream>,
    pub default_tag: Label,
    pub address: SocketAddr,
    pub disable_ipv6: bool,
    pub cache_size: usize,
    #[serde(with = "LevelFilterDef")]
    pub verbosity: LevelFilter,
}
