use crate::parser::{Parsed, Rule, Upstream, UpstreamKind};
use anyhow::{anyhow, Result};
use dmatcher::Dmatcher;
use hashbrown::HashMap;
use log::*;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::fs::File;
use tokio::prelude::*;
use tokio_compat_02::FutureExt;
use trust_dns_proto::{
    rr::{Record, RecordType},
    xfer::dns_request::DnsRequestOptions,
};
use trust_dns_resolver::{config::*, TokioAsyncResolver};

pub struct Filter {
    resolvers: HashMap<String, TokioAsyncResolver>,
    default_name: String,
    matcher: Dmatcher,
}

impl Filter {
    pub fn new() -> Self {
        Self {
            resolvers: HashMap::new(),
            matcher: Dmatcher::new(),
            default_name: String::new(),
        }
    }

    pub async fn insert_rule(&mut self, rule: Rule) -> Result<()> {
        let mut file = File::open(rule.path).await?;
        let mut data = String::new();
        file.read_to_string(&mut data).await?;
        self.matcher.insert_lines(data, rule.dst)?;
        Ok(())
    }

    pub async fn insert_upstream(&mut self, upstream: Upstream) -> Result<()> {
        let mut opts = ResolverOpts::default();
        opts.cache_size = upstream.cache_size;
        opts.timeout = Duration::from_secs(upstream.timeout);

        self.resolvers.insert(
            upstream.name,
            TokioAsyncResolver::tokio(
                ResolverConfig::from_parts(
                    None,
                    vec![],
                    match upstream.method {
                        UpstreamKind::Tls(tls_name) => NameServerConfigGroup::from_ips_tls(
                            &upstream.ips,
                            upstream.port,
                            tls_name,
                        ),
                        UpstreamKind::Udp => {
                            NameServerConfigGroup::from_ips_clear(&upstream.ips, upstream.port)
                        }
                        UpstreamKind::Https(tls_name) => NameServerConfigGroup::from_ips_tls(
                            &upstream.ips,
                            upstream.port,
                            tls_name,
                        ),
                    },
                ),
                opts,
            )
            .compat()
            .await?,
        );
        Ok(())
    }

    pub async fn from_json(data: &str) -> Result<(Self, SocketAddr, i32)> {
        let mut filter = Self::new();
        let p: Parsed = serde_json::from_str(data)?;
        for u in p.upstreams {
            filter.insert_upstream(u).await?;
        }
        // Check before inserting
        Filter::check(&filter, &p.rules)?;
        for r in p.rules {
            filter.insert_rule(r).await?;
        }
        filter.default_name = p.default;
        Ok((filter, p.address, p.workers))
    }

    fn check(filter: &Self, rules: &[Rule]) -> Result<()> {
        for r in rules {
            filter
                .resolvers
                .get(&r.dst)
                .ok_or_else(|| anyhow!("Missing resolver: {}", &r.dst))?;
        }
        Ok(())
    }

    pub async fn resolve(&self, domain: String, qtype: RecordType) -> Result<Vec<Record>> {
        Ok((match self.matcher.matches(domain.as_str())? {
            Some(u) => {
                info!("Routed via {}", u);
                self.resolvers
                    .get(u)
                    .ok_or_else(|| anyhow!("Missing resolver: {}", &u))? // These won't be reached unless it is unchecked.
            }
            None => {
                info!("Routed via default: {}", &self.default_name);
                self.resolvers
                    .get(&self.default_name)
                    .ok_or_else(|| anyhow!("Missing resolver: {}", &self.default_name))?
            }
        })
        .lookup(
            domain,
            qtype,
            DnsRequestOptions {
                expects_multiple_responses: false,
            },
        )
        .compat()
        .await?
        .record_iter()
        .cloned()
        .collect())
    }
}
