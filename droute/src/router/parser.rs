use super::upstream::Upstream;
use log::LevelFilter;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

#[derive(Serialize, Deserialize, Clone)]
pub struct Rule {
    pub dst: usize,
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
    pub default_tag: usize,
    pub address: SocketAddr,
    pub disable_ipv6: bool,
    #[serde(with = "LevelFilterDef")]
    pub verbosity: LevelFilter,
}
