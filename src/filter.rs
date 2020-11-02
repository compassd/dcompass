use crate::parser::{Parsed, Rule, Upstream, UpstreamKind};
use anyhow::{anyhow, Result};
use dmatcher::Dmatcher;
use hashbrown::HashMap;
use log::*;
use std::{net::SocketAddr, time::Duration};
use tokio::{fs::File, prelude::*};
use tokio_compat_02::FutureExt;
use trust_dns_proto::{
    op::{response_code::ResponseCode, Message},
    rr::{Record, RecordType},
    xfer::dns_request::DnsRequestOptions,
};
use trust_dns_resolver::{config::*, TokioAsyncResolver};

pub struct Filter {
    resolvers: HashMap<String, TokioAsyncResolver>,
    default_name: String,
    disable_ipv6: bool,
    matcher: Dmatcher,
}

impl Filter {
    fn new() -> Self {
        Self {
            resolvers: HashMap::new(),
            matcher: Dmatcher::new(),
            default_name: String::new(),
            disable_ipv6: false,
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

    pub async fn from_json(data: &str) -> Result<(Self, SocketAddr, i32, LevelFilter)> {
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
        filter.disable_ipv6 = p.disable_ipv6;
        Ok((filter, p.address, p.workers, p.verbosity))
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

    fn get_resolver(&self, domain: &str) -> Result<&TokioAsyncResolver> {
        Ok(match self.matcher.matches(domain)? {
            Some(u) => {
                info!("Routed via {}", u);
                self.resolvers
                    .get(u)
                    .ok_or_else(|| anyhow!("Missing resolver: {}", &u))?
                // These won't be reached unless it is unchecked.
            }
            None => {
                info!("Routed via default: {}", &self.default_name);
                self.resolvers
                    .get(&self.default_name)
                    .ok_or_else(|| anyhow!("Missing resolver: {}", &self.default_name))?
            }
        })
    }

    pub async fn resolve(
        &self,
        domain: String,
        qtype: RecordType,
        mut req: Message,
    ) -> Result<Message> {
        Ok(if (qtype == RecordType::AAAA) && (self.disable_ipv6) {
            // If `disable_ipv6` has been set, return immediately NXDomain.
            Message::error_msg(req.id(), req.op_code(), ResponseCode::NXDomain)
        } else {
            // Get the corresponding resolver
            match self
                .get_resolver(domain.as_str())?
                .lookup(
                    domain,
                    qtype,
                    DnsRequestOptions {
                        expects_multiple_responses: false,
                    },
                )
                .compat()
                .await
            {
                Err(e) => {
                    warn!("Resolve failed: {}", e);
                    // TODO: We should specify different errors and return them back respectively.
                    Message::error_msg(req.id(), req.op_code(), ResponseCode::NXDomain)
                }
                Ok(r) => {
                    req.add_answers(r.record_iter().cloned().collect::<Vec<Record>>());
                    req
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::Filter;
    use futures::executor::block_on;

    #[test]
    fn parse() {
        block_on(Filter::from_json(include_str!("./config.json"))).unwrap();
    }
}
