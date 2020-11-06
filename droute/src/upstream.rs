use crate::error::Result;
use futures::Future;
use log::*;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use trust_dns_client::{
    client::AsyncClient,
    op::{DnsResponse, Message, ResponseCode},
    udp::UdpClientStream,
};
use trust_dns_https::{HttpsClientResponse, HttpsClientStreamBuilder};
use trust_dns_proto::{error::ProtoError, udp::UdpResponse, xfer::dns_handle::DnsHandle};

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

#[derive(Serialize, Deserialize, Clone)]
pub struct UpstreamInfo {
    pub tag: usize,
    pub method: UpstreamKind,
    pub cache_size: usize,
    pub timeout: u64,
}

#[derive(Clone)]
enum ClientType {
    Https(AsyncClient<HttpsClientResponse>),
    Udp(AsyncClient<UdpResponse>),
}

pub struct Upstream {
    client: ClientType,
    timeout: u64,
}

impl Upstream {
    pub async fn new(info: UpstreamInfo) -> Result<Self> {
        let client: ClientType;
        match info.method {
            UpstreamKind::Udp(s) => {
                let stream = UdpClientStream::<UdpSocket>::new(s);
                let (c, bg) = AsyncClient::connect(stream).await?;
                tokio::spawn(bg);
                client = ClientType::Udp(c);
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

                let (c, bg) = AsyncClient::connect(stream).await?;
                tokio::spawn(bg);

                client = ClientType::Https(c);
            }
        };
        Ok(Self {
            client,
            timeout: info.timeout,
        })
    }

    async fn query<R>(t: u64, mut client: AsyncClient<R>, msg: Message) -> Result<Message>
    where
        R: Future<Output = std::result::Result<DnsResponse, ProtoError>> + 'static + Send + Unpin,
    {
        let id = msg.id();
        let op_code = msg.op_code();

        let mut resp = match timeout(Duration::from_secs(t), client.send(msg)).await {
            Ok(m) => Message::from(m?),
            Err(_) => {
                warn!("Timeout reached!");
                Message::error_msg(id, op_code, ResponseCode::ServFail)
            }
        };
        resp.set_id(id);
        Ok(resp)
    }

    pub async fn resolve(&self, msg: Message) -> Result<Message> {
        match self.client.clone() {
            ClientType::Https(client) => {
                Self::query::<HttpsClientResponse>(self.timeout, client, msg).await
            }
            ClientType::Udp(client) => Self::query::<UdpResponse>(self.timeout, client, msg).await,
        }
    }
}
