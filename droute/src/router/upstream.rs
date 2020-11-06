use crate::error::DrouteError;
use crate::error::Result;
use hashbrown::HashMap;
use log::*;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use trust_dns_client::client::AsyncClient;
use trust_dns_client::op::Message;
use trust_dns_client::op::ResponseCode;
use trust_dns_client::udp::UdpClientStream;
use trust_dns_https::HttpsClientStreamBuilder;
use trust_dns_proto::xfer::dns_handle::DnsHandle;

const ALPN_H2: &[u8] = b"h2";

#[derive(Serialize, Deserialize, Clone)]
pub enum UpstreamKind {
    Https {
        name: String,
        addr: SocketAddr,
        no_sni: bool,
    },
    // Drop TLS support until we figure out how to do without OpenSSL
    // Tls(String, SocketAddr),
    Udp(SocketAddr),
}

pub struct Upstreams {
    upstreams: HashMap<usize, Upstream>,
}

impl Upstreams {
    pub fn new(upstreams: Vec<Upstream>) -> Self {
        let mut r = HashMap::new();
        for u in upstreams {
            r.insert(u.tag, u);
        }
        Self { upstreams: r }
    }

    pub fn exists(&self, tag: usize) -> Result<bool> {
        if self.upstreams.contains_key(&tag) {
            Ok(true)
        } else {
            Err(DrouteError::MissingTag(tag))
        }
    }

    pub async fn resolve(&self, tag: usize, msg: Message) -> Result<Message> {
        let id = msg.id();
        let op_code = msg.op_code();
        let u = self
            .upstreams
            .get(&tag)
            .ok_or_else(|| DrouteError::MissingTag(tag))?;
        Ok(match u.method.clone() {
            UpstreamKind::Udp(s) => {
                let stream = UdpClientStream::<UdpSocket>::new(s);
                let (mut client, bg) = AsyncClient::connect(stream).await?;
                tokio::spawn(bg);
                let mut resp = match timeout(Duration::from_secs(u.timeout), client.send(msg)).await
                {
                    Ok(m) => Message::from(m?),
                    Err(_) => {
                        warn!("Timeout reached!");
                        Message::error_msg(id, op_code, ResponseCode::ServFail)
                    }
                };
                resp.set_id(id);
                resp
            }
            UpstreamKind::Https { name, addr, no_sni } => {
                use rustls::{ClientConfig, KeyLogFile, ProtocolVersion, RootCertStore};
                use std::sync::Arc;

                let mut root_store = RootCertStore::empty();
                root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
                let versions = vec![ProtocolVersion::TLSv1_2];

                let mut client_config = ClientConfig::new();
                client_config.root_store = root_store;
                client_config.versions = versions;
                client_config.alpn_protocols.push(ALPN_H2.to_vec());
                client_config.key_log = Arc::new(KeyLogFile::new());
                if no_sni {
                    client_config.enable_sni = false;
                }

                let client_config = Arc::new(client_config);

                let stream =
                    HttpsClientStreamBuilder::with_client_config(client_config).build(addr, name);
                let (mut client, bg) = AsyncClient::connect(stream).await?;
                tokio::spawn(bg);
                let mut resp = match timeout(Duration::from_secs(u.timeout), client.send(msg)).await
                {
                    Ok(m) => Message::from(m?),
                    Err(_) => {
                        warn!("Timeout reached!");
                        Message::error_msg(id, op_code, ResponseCode::ServFail)
                    }
                };
                resp.set_id(id);
                resp
            }
        })
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Upstream {
    pub tag: usize,
    pub method: UpstreamKind,
    pub cache_size: usize,
    pub timeout: u64,
}
