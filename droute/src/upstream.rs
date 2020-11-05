use crate::error::Result;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use trust_dns_client::client::AsyncClient;
use trust_dns_client::op::Message;
use trust_dns_client::udp::UdpClientStream;
use trust_dns_https::HttpsClientStreamBuilder;
use trust_dns_proto::xfer::dns_handle::DnsHandle;

const ALPN_H2: &[u8] = b"h2";

#[derive(Serialize, Deserialize, Clone)]
pub enum UpstreamKind {
    Https { name: String, addr: SocketAddr },
    // Drop TLS support until we figure out how to do without OpenSSL
    // Tls(String, SocketAddr),
    Udp(SocketAddr),
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Upstream {
    pub tag: usize,
    pub method: UpstreamKind,
    pub cache_size: usize,
    pub timeout: u64,
}

impl Upstream {
    pub async fn resolve(&self, msg: Message) -> Result<Message> {
        Ok(match self.method.clone() {
            UpstreamKind::Udp(s) => {
                let id = msg.id();
                let stream = UdpClientStream::<UdpSocket>::new(s);
                let (mut client, bg) = AsyncClient::connect(stream).await?;
                tokio::spawn(bg);
                let mut resp = Message::from(client.send(msg).await?);
                resp.set_id(id);
                resp
            }
            UpstreamKind::Https { name, addr } => {
                use rustls::{ClientConfig, KeyLogFile, ProtocolVersion, RootCertStore};
                use std::sync::Arc;

                let id = msg.id();

                let mut root_store = RootCertStore::empty();
                root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
                let versions = vec![ProtocolVersion::TLSv1_2];

                let mut client_config = ClientConfig::new();
                client_config.root_store = root_store;
                client_config.versions = versions;
                client_config.alpn_protocols.push(ALPN_H2.to_vec());
                client_config.key_log = Arc::new(KeyLogFile::new());

                let client_config = Arc::new(client_config);

                let stream =
                    HttpsClientStreamBuilder::with_client_config(client_config).build(addr, name);
                let (mut client, bg) = AsyncClient::connect(stream).await?;
                tokio::spawn(bg);
                let mut resp = Message::from(client.send(msg).await?);
                resp.set_id(id);
                resp
            }
        })
    }
}
