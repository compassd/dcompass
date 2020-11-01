use crate::parser::{Parsed, Rule, Upstream, UpstreamKind};
use dmatcher::Dmatcher;
use hashbrown::HashMap;
use log::*;
use std::fs::File;
use std::io::Read;
use trust_dns_proto::{
    rr::{Record, RecordType},
    xfer::dns_request::DnsRequestOptions,
};
use trust_dns_resolver::{config::*, error::ResolveResult, TokioAsyncResolver};

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

    pub fn insert_rule(&mut self, rule: Rule) {
        let mut file = File::open(rule.path).unwrap();
        let mut data = String::new();
        file.read_to_string(&mut data).unwrap();
        self.matcher.insert_lines(data, rule.dst).unwrap();
    }

    pub async fn insert_upstream(&mut self, upstream: Upstream) {
        let mut opts = ResolverOpts::default();
        opts.cache_size = upstream.cache_size;

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
            .await
            .unwrap(),
        );
    }

    pub async fn from_json(data: &str) -> Self {
        let mut filter = Self::new();
        let p: Parsed = serde_json::from_str(data).unwrap();
        for r in p.rules {
            filter.insert_rule(r);
        }
        for u in p.upstreams {
            filter.insert_upstream(u).await;
        }
        filter.default_name = p.default;
        filter
    }

    pub async fn resolve(&self, domain: String, qtype: RecordType) -> ResolveResult<Vec<Record>> {
        Ok((match self.matcher.matches(domain.clone()).unwrap() {
            Some(u) => {
                info!("Routed via {}", u);
                self.resolvers.get(u).unwrap()
            }
            None => {
                info!("Routed via default: {}", &self.default_name);
                self.resolvers.get(&self.default_name).unwrap()
            }
        })
        .lookup(
            domain,
            qtype,
            DnsRequestOptions {
                expects_multiple_responses: false,
            },
        )
        .await?
        .record_iter()
        .cloned()
        .collect())
    }
}
