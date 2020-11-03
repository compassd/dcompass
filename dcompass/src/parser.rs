use log::LevelFilter;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};

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
pub enum UpstreamKind {
    Https(String),
    Tls(String),
    Udp,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Upstream {
    pub tag: usize,
    pub method: UpstreamKind,
    pub port: u16,
    pub ips: Vec<IpAddr>,
    pub cache_size: usize,
    pub timeout: u64,
    pub num_conn: usize,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Parsed {
    pub rules: Vec<Rule>,
    pub upstreams: Vec<Upstream>,
    pub default_tag: usize,
    pub address: SocketAddr,
    pub workers: usize,
    pub pools: usize,
    pub disable_ipv6: bool,
    #[serde(with = "LevelFilterDef")]
    pub verbosity: LevelFilter,
}
