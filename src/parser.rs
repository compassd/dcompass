use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};

#[derive(Serialize, Deserialize)]
pub struct Rule {
    pub dst: String,
    pub path: String,
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
}
