use crate::error::DrouteError;
use crate::error::Result;
use crate::parser::{Parsed, Rule};
use crate::upstream::Upstream;
use dmatcher::Dmatcher;
use hashbrown::HashMap;
use log::*;
use std::net::SocketAddr;
use tokio::{fs::File, prelude::*};
use trust_dns_client::op::Message;
use trust_dns_client::op::ResponseCode;
use trust_dns_client::rr::RecordType;
// use tokio_compat_02::FutureExt;

pub struct Filter {
    upstreams: HashMap<usize, Upstream>,
    default_tag: usize,
    disable_ipv6: bool,
    matcher: Dmatcher<usize>,
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

    async fn insert_upstreams(upstreams: Vec<Upstream>) -> Result<HashMap<usize, Upstream>> {
        let mut r = HashMap::new();
        for u in upstreams {
            r.insert(u.tag, u);
        }
        Ok(r)
    }

    pub async fn new(data: &str) -> Result<(Self, SocketAddr, usize, LevelFilter)> {
        let p: Parsed = serde_json::from_str(data)?;

        if p.workers < 1 {
            return Err(DrouteError::InvalidWorker(p.workers));
        }

        let (matcher, dsts) = Filter::insert_rules(p.rules).await?;
        let filter = Filter {
            matcher,
            upstreams: Filter::insert_upstreams(p.upstreams).await?,
            default_tag: p.default_tag,
            disable_ipv6: p.disable_ipv6,
            dsts,
        };
        filter.check(filter.default_tag)?;
        Ok((filter, p.address, p.workers, p.verbosity))
    }

    pub fn check(&self, default: usize) -> Result<()> {
        // All pools are same for each element in vector.
        for dst in &self.dsts {
            self.upstreams
                .get(&dst)
                .ok_or_else(|| DrouteError::MissingTag(*dst))?;
        }
        self.upstreams
            .get(&default)
            .ok_or_else(|| DrouteError::MissingTag(default))?;
        Ok(())
    }

    fn get_upstream(&self, domain: &str) -> Result<&Upstream> {
        Ok(match self.matcher.matches(domain)? {
            Some(u) => {
                info!("{} routed via upstream with tag {}", domain, u);
                self.upstreams
                    .get(&u)
                    .ok_or_else(|| DrouteError::MissingTag(u))?
                // These won't be reached unless it is unchecked.
            }
            None => {
                info!(
                    "{} routed via upstream with default tag {}",
                    domain, self.default_tag
                );
                self.upstreams
                    .get(&self.default_tag)
                    .ok_or_else(|| DrouteError::MissingTag(self.default_tag))?
            }
        })
    }

    pub async fn resolve(&self, msg: Message) -> Result<Message> {
        Ok(
            // Get the corresponding resolver
            if msg.query_count() == 1 {
                let q = msg.queries().iter().next().unwrap();
                if (q.query_type() == RecordType::AAAA) && (self.disable_ipv6) {
                    // If `disable_ipv6` has been set, return immediately NXDomain.
                    Message::error_msg(msg.id(), msg.op_code(), ResponseCode::NXDomain)
                } else {
                    self.get_upstream(
                        msg.queries()
                            .iter()
                            .next()
                            .unwrap()
                            .name()
                            .to_utf8()
                            .as_str(),
                    )?
                    .resolve(msg)
                    .await?
                }
            } else {
                warn!("DNS message contains multiple queries, using default_tag to route. IPv6 disable functionality is NOT taking effect.");
                self.upstreams
                    .get(&self.default_tag)
                    .ok_or_else(|| DrouteError::MissingTag(self.default_tag))?
                    .resolve(msg)
                    .await?
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::Filter;
    use crate::error::DrouteError;
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
            match block_on(Filter::new(include_str!("../configs/fail_rule.json")))
                .err()
                .unwrap()
            {
                DrouteError::MissingTag(tag) => tag,
                e => panic!("Not the right error type: {}", e),
            },
            2
        );
    }

    #[test]
    fn check_fail_default() {
        assert_eq!(
            match block_on(Filter::new(include_str!("../configs/fail_default.json")))
                .err()
                .unwrap()
            {
                DrouteError::MissingTag(tag) => tag,
                e => panic!("Not the right error type: {}", e),
            },
            5
        );
    }
}
