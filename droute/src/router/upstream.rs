use crate::error::DrouteError;
use crate::error::Result;
use futures::future::select_ok;
use futures::future::FutureExt;
use futures::Future;
use hashbrown::HashMap;
use log::*;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::time::timeout;
use trust_dns_client::{
    client::AsyncClient,
    op::{DnsResponse, Message},
    udp::UdpClientStream,
};
use trust_dns_https::{HttpsClientResponse, HttpsClientStreamBuilder};
use trust_dns_proto::{error::ProtoError, udp::UdpResponse, xfer::dns_handle::DnsHandle};

const ALPN_H2: &[u8] = b"h2";

#[derive(Clone)]
enum ClientType {
    Https(AsyncClient<HttpsClientResponse>),
    Udp(AsyncClient<UdpResponse>),
}

#[derive(Serialize, Deserialize, Clone)]
pub enum UpstreamKind {
    Hybrid(Vec<usize>),
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
    clients: Mutex<HashMap<usize, VecDeque<ClientType>>>,
}

impl Upstreams {
    pub fn new(upstreams: Vec<Upstream>) -> Self {
        let mut r = HashMap::new();
        for u in upstreams {
            r.insert(u.tag, u);
        }
        Self {
            upstreams: r,
            clients: Mutex::new(HashMap::new()),
        }
    }

    pub fn hybrid_check(&self) -> Result<bool> {
        for (tag, u) in self.upstreams.iter() {
            if let UpstreamKind::Hybrid(v) = &u.method {
                if v.is_empty() {
                    return Err(DrouteError::EmptyHybrid(*tag));
                }
                if let Some(t) = v.iter().find(|tag| self.exists(*tag).is_err()) {
                    return Err(DrouteError::MissingTag(*t));
                }
            }
        }
        Ok(true)
    }

    pub fn exists(&self, tag: &usize) -> Result<bool> {
        if self.upstreams.contains_key(tag) {
            Ok(true)
        } else {
            Err(DrouteError::MissingTag(*tag))
        }
    }

    async fn query<R>(t: u64, mut client: AsyncClient<R>, msg: Message) -> Result<Message>
    where
        R: Future<Output = std::result::Result<DnsResponse, ProtoError>> + 'static + Send + Unpin,
    {
        let id = msg.id();
        let mut resp = Message::from(timeout(Duration::from_secs(t), client.send(msg)).await??);
        resp.set_id(id);
        Ok(resp)
    }

    async fn create_client(&self, tag: usize) -> Result<ClientType> {
        let u = self
            .upstreams
            .get(&tag)
            .ok_or_else(|| DrouteError::MissingTag(tag))?;
        Ok(match &u.method {
            UpstreamKind::Udp(s) => {
                let stream = UdpClientStream::<UdpSocket>::new(*s);
                let (client, bg) = AsyncClient::connect(stream).await?;
                tokio::spawn(bg);
                ClientType::Udp(client)
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
                client_config.enable_sni = !no_sni;

                let client_config = Arc::new(client_config);

                let stream = HttpsClientStreamBuilder::with_client_config(client_config)
                    .build(*addr, name.to_string());
                let (client, bg) = AsyncClient::connect(stream).await?;
                tokio::spawn(bg);
                ClientType::Https(client)
            }
            // We don't create client for Hybrid
            _ => return Err(DrouteError::HybridRecursion),
        })
    }

    async fn final_resolve(&self, tag: usize, msg: Message) -> Result<Message> {
        let u = self
            .upstreams
            .get(&tag)
            .ok_or_else(|| DrouteError::MissingTag(tag))?;
        let client = {
            let mut clients = self.clients.lock().await;
            let queue = clients.entry(tag).or_insert(VecDeque::new());
            if queue.is_empty() {
                info!(
                    "Client cache is empty for tag {}, creating new clients",
                    tag
                );
                self.create_client(tag).await?
            } else {
                let c = queue.pop_front().unwrap();
                info!(
                    "Client cache hit for tag {}, remaining client in queue: {}",
                    tag,
                    queue.len()
                );
                c
            }
        };
        let resp = match &u.method {
            UpstreamKind::Udp(_) => {
                if let ClientType::Udp(client) = client.clone() {
                    Self::query(u.timeout, client, msg).await?
                } else {
                    unreachable!();
                }
            }
            UpstreamKind::Https {
                name: _,
                addr: _,
                no_sni: _,
            } => {
                if let ClientType::Https(client) = client.clone() {
                    Self::query(u.timeout, client, msg).await?
                } else {
                    unreachable!();
                }
            }
            // final_resolve should not be used on another `hybrid` upstream
            _ => return Err(DrouteError::HybridRecursion),
        };
        // If the response can be obtained sucessfully, we then push back the client to the queue
        {
            info!("Push back client cache for tag {}", tag);
            let mut clients = self.clients.lock().await;
            let queue = clients.entry(tag).or_insert(VecDeque::new());
            queue.push_back(client);
        }
        Ok(resp)
    }

    pub async fn resolve(&self, tag: usize, msg: Message) -> Result<Message> {
        let u = self
            .upstreams
            .get(&tag)
            .ok_or_else(|| DrouteError::MissingTag(tag))?;
        Ok(match &u.method {
            UpstreamKind::Hybrid(v) => {
                let v = v
                    .iter()
                    .map(|u| self.final_resolve(*u, msg.clone()).boxed());
                let (resp, _) = timeout(Duration::from_secs(u.timeout), select_ok(v)).await??;
                resp
            }
            _ => self.final_resolve(tag, msg).await?,
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
