mod filter;
mod parser;
mod upstream;

use self::filter::Filter;
use self::parser::Parsed;
use self::upstream::Upstreams;
use crate::error::Result;
use log::LevelFilter;
use log::*;
use std::net::SocketAddr;
use trust_dns_client::op::Message;
use trust_dns_client::op::ResponseCode;
use trust_dns_client::rr::RecordType;

pub struct Router {
    filter: Filter,
    disable_ipv6: bool,
    upstreams: Upstreams,
    addr: SocketAddr,
    verbosity: LevelFilter,
    dsts: Vec<usize>,
}

impl Router {
    pub fn verbosity(&self) -> LevelFilter {
        self.verbosity
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub async fn new(data: &str) -> Result<Self> {
        let p: Parsed = serde_json::from_str(data)?;

        let (filter, dsts) = Filter::new(p.default_tag, p.rules).await?;
        let router = Self {
            disable_ipv6: p.disable_ipv6,
            dsts,
            upstreams: Upstreams::new(p.upstreams),
            filter,
            addr: p.address,
            verbosity: p.verbosity,
        };
        router.check()?;
        Ok(router)
    }

    pub fn check(&self) -> Result<bool> {
        // All pools are same for each element in vector.
        for dst in &self.dsts {
            self.upstreams.exists(*dst)?;
        }
        self.upstreams.exists(self.filter.default_tag())?;
        Ok(true)
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
                    self.upstreams
                        .resolve(
                            self.filter.get_upstream(
                                msg.queries()
                                    .iter()
                                    .next()
                                    .unwrap()
                                    .name()
                                    .to_utf8()
                                    .as_str(),
                            )?,
                            msg,
                        )
                        .await?
                }
            } else {
                warn!("DNS message contains multiple queries, using default_tag to route. IPv6 disable functionality is NOT taking effect.");
                self.upstreams
                    .resolve(self.filter.default_tag(), msg)
                    .await?
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::Router;
    use crate::error::DrouteError;
    use tokio_test::block_on;

    #[test]
    fn parse() {
        assert_eq!(
            block_on(Router::new(include_str!("../../configs/default.json"))).is_ok(),
            true
        );
    }

    #[test]
    fn check_fail_rule() {
        // Notice that data dir is relative to cargo test path.
        assert_eq!(
            match block_on(Router::new(include_str!("../../configs/fail_rule.json")))
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
    fn check_success_rule() {
        assert_eq!(
            block_on(Router::new(include_str!("../../configs/success_rule.json"))).is_ok(),
            true
        );
    }

    #[test]
    fn check_fail_default() {
        assert_eq!(
            match block_on(Router::new(include_str!("../../configs/fail_default.json")))
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
