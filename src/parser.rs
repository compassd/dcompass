use log::LevelFilter;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};

#[derive(Serialize, Deserialize)]
pub struct Rule {
    pub dst: String,
    pub path: String,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "LevelFilter")]
enum LevelFilterDef {
    Off,
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

#[derive(Serialize, Deserialize)]
pub enum UpstreamKind {
    Https(String),
    Tls(String),
    Udp,
}

#[derive(Serialize, Deserialize)]
pub struct Upstream {
    pub name: String,
    pub method: UpstreamKind,
    pub port: u16,
    pub ips: Vec<IpAddr>,
    pub cache_size: usize,
    pub timeout: u64,
}

#[derive(Serialize, Deserialize)]
pub struct Parsed {
    pub rules: Vec<Rule>,
    pub upstreams: Vec<Upstream>,
    pub default: String,
    pub address: SocketAddr,
    pub workers: i32,
    pub disable_ipv6: bool,
    #[serde(with = "LevelFilterDef")]
    pub verbosity: LevelFilter,
}
