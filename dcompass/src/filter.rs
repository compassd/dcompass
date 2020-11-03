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
    pools: Vec<HashMap<usize, TokioAsyncResolver>>,
    default_tag: usize,
    disable_ipv6: bool,
    matcher: Dmatcher<usize>,
    num_workers: usize,
    dsts: Vec<usize>,
}

impl Filter {
    async fn insert_rules(rules: Vec<Rule>) -> Result<(Dmatcher<usize>, Vec<usize>)> {
        let mut matcher = Dmatcher::new();
        let mut v = vec![];
        for r in rules {
            let mut file = File::open(r.path).await?;
            let mut data = String::new();
            file.read_to_string(&mut data).await?;
            matcher.insert_lines(data, r.dst)?;
            v.push(r.dst);
        }
        Ok((matcher, v))
    }

    async fn insert_upstreams(
        upstreams: Vec<Upstream>,
        num_pools: usize,
    ) -> Result<Vec<HashMap<usize, TokioAsyncResolver>>> {
        let mut v = Vec::new();
        for _ in 1..=num_pools {
            let mut r = HashMap::new();

            for upstream in upstreams.clone() {
                let mut opts = ResolverOpts::default();
                opts.cache_size = upstream.cache_size;
                opts.attempts = 1;
                opts.num_concurrent_reqs = upstream.num_conn;
                opts.timeout = Duration::from_secs(upstream.timeout);

                opts.distrust_nx_responses = false; // This slows down resolution and does no good.
                opts.preserve_intermediates = true;

                r.insert(
                    upstream.tag,
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
                                UpstreamKind::Udp => NameServerConfigGroup::from_ips_clear(
                                    &upstream.ips,
                                    upstream.port,
                                ),
                                UpstreamKind::Https(tls_name) => {
                                    NameServerConfigGroup::from_ips_tls(
                                        &upstream.ips,
                                        upstream.port,
                                        tls_name,
                                    )
                                }
                            },
                        ),
                        opts,
                    )
                    .compat()
                    .await?,
                );
            }
            v.push(r);
        }
        Ok(v)
    }

    pub async fn new(data: &str) -> Result<(Self, SocketAddr, usize, LevelFilter)> {
        let p: Parsed = serde_json::from_str(data)?;

        if p.workers < 1 {
            return Err(anyhow!(
                "Cannot have number of workers less than 1: {}",
                p.workers
            ));
        }
        if p.pools < 1 {
            return Err(anyhow!(
                "Cannot have number of pools less than 1: {}",
                p.pools
            ));
        }

        let (matcher, dsts) = Filter::insert_rules(p.rules).await?;
        let filter = Filter {
            matcher,
            pools: Filter::insert_upstreams(p.upstreams, p.pools).await?,
            default_tag: p.default_tag,
            disable_ipv6: p.disable_ipv6,
            num_workers: p.workers,
            dsts,
        };
        filter.check(filter.default_tag)?;
        Ok((filter, p.address, p.workers, p.verbosity))
    }

    pub fn check(&self, default: usize) -> Result<()> {
        // All pools are same for each element in vector.
        for dst in &self.dsts {
            self.pools[0]
                .get(&dst)
                .ok_or_else(|| anyhow!("Missing resolver: {}", dst))?;
        }
        self.pools[0]
            .get(&default)
            .ok_or_else(|| anyhow!("Missing default resolver: {}", default))?;
        Ok(())
    }

    fn get_resolver(&self, domain: &str, worker_id: usize) -> Result<&TokioAsyncResolver> {
        // This ensures that the generated pool_id is in [0, pools.len()). pool_id starts from 0
        let pool_id = (worker_id + 1) * (self.pools.len() - 1) / self.num_workers;
        Ok(match self.matcher.matches(domain)? {
            Some(u) => {
                info!(
                    "[Worker {}] Routed via upstream with tag {} in pool {}",
                    worker_id, u, pool_id
                );
                self.pools[pool_id]
                    .get(&u)
                    .ok_or_else(|| anyhow!("Missing resolver: {}", &u))?
                // These won't be reached unless it is unchecked.
            }
            None => {
                info!(
                    "[Worker {}] Routed via default upstream with tag {} in pool {}",
                    worker_id, &self.default_tag, pool_id
                );
                self.pools[pool_id]
                    .get(&self.default_tag)
                    .ok_or_else(|| anyhow!("Missing default resolver: {}", &self.default_tag))?
            }
        })
    }

    pub async fn resolve(
        &self,
        domain: String,
        qtype: RecordType,
        mut req: Message,
        worker_id: usize,
    ) -> Result<Message> {
        Ok(if (qtype == RecordType::AAAA) && (self.disable_ipv6) {
            // If `disable_ipv6` has been set, return immediately NXDomain.
            Message::error_msg(req.id(), req.op_code(), ResponseCode::NXDomain)
        } else {
            // Get the corresponding resolver
            match self
                .get_resolver(domain.as_str(), worker_id)?
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
                    // If recursion is desired, then we respond that we did it.
                    if req.recursion_desired() {
                        req.set_recursion_available(true);
                    }
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
    use tokio_test::block_on;

    #[test]
    fn parse() {
        assert_eq!(
            block_on(Filter::new(include_str!("../configs/default.json"))).is_ok(),
            true
        );
    }

    #[test]
    fn check_fail_rule() {
        // Notice that data dir is relative to cargo test path.
        assert_eq!(
            block_on(Filter::new(include_str!("../configs/fail_rule.json"))).is_err(),
            true
        );
    }

    #[test]
    fn check_fail_default() {
        assert_eq!(
            block_on(Filter::new(include_str!("../configs/fail_default.json"))).is_err(),
            true
        );
    }
}
