mod client_cache;

use self::client_cache::{ClientCache, ClientType};
use crate::error::DrouteError;
use crate::error::Result;
use futures::future::select_ok;
use futures::future::FutureExt;
use futures::Future;
use hashbrown::HashMap;
use log::*;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::timeout;
use trust_dns_client::{
    client::AsyncClient,
    op::{DnsResponse, Message},
};
use trust_dns_proto::{error::ProtoError, xfer::dns_handle::DnsHandle};

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
    clients: Mutex<HashMap<usize, ClientCache>>,
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

    async fn final_resolve(&self, tag: usize, msg: Message) -> Result<Message> {
        let u = self
            .upstreams
            .get(&tag)
            .ok_or_else(|| DrouteError::MissingTag(tag))?;
        let client = {
            let mut clients = self.clients.lock().await;
            let cache = clients.entry(tag).or_insert(ClientCache::new(u).await?);
            cache.get_client(u).await?
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
            let cache = clients.entry(tag).or_insert(ClientCache::new(u).await?);
            cache.return_back(client);
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
