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

use droute::builders::*;
use log::LevelFilter;
use serde::Deserialize;
use std::net::SocketAddr;

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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Parsed {
    pub script: ScriptBuilder,
    // We are not using UpstreamsBuilder because flatten ruins error location.
    #[serde(flatten)]
    pub upstreams: UpstreamsBuilder<UpstreamBuilder>,
    pub address: SocketAddr,
    #[serde(with = "LevelFilterDef")]
    pub verbosity: LevelFilter,
}
