// Copyright 2020 LEXUGE
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! Router is the core concept of `droute`.

mod filter;
mod parser;
mod upstream;

use self::filter::Filter;
use self::parser::Parsed;
use self::upstream::Upstreams;
use crate::error::Result;
use dmatcher::Label;
use log::LevelFilter;
use log::*;
use std::net::SocketAddr;
use trust_dns_client::op::Message;
use trust_dns_client::op::ResponseCode;
use trust_dns_client::rr::RecordType;

/// Router implementation.
pub struct Router {
    filter: Filter,
    disable_ipv6: bool,
    upstreams: Upstreams,
    addr: SocketAddr,
    verbosity: LevelFilter,
    dsts: Vec<Label>,
}

impl Router {
    /// Get the verbosity defined in the configuration file.
    pub fn verbosity(&self) -> LevelFilter {
        self.verbosity
    }

    /// Get the address to bind as it is defined in the configuration file.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Create a new `Router` from configuration and check the validity. `data` is the content of the configuration file.
    pub async fn new(data: &str) -> Result<Self> {
        let p: Parsed = serde_json::from_str(data)?;

        let (filter, dsts) = Filter::new(p.default_tag, p.rules).await?;
        let router = Self {
            disable_ipv6: p.disable_ipv6,
            dsts,
            upstreams: Upstreams::new(p.upstreams, p.cache_size).await?,
            filter,
            addr: p.address,
            verbosity: p.verbosity,
        };
        router.check()?;
        Ok(router)
    }

    /// Validate the internal rules defined. This is automatically performed by `new` method.
    pub fn check(&self) -> Result<bool> {
        self.upstreams.hybrid_check()?;
        for dst in &self.dsts {
            self.upstreams.exists(dst)?;
        }
        self.upstreams.exists(&self.filter.default_tag())?;
        Ok(true)
    }

    /// Resolve the DNS query with routing rules defined.
    pub async fn resolve(&self, msg: Message) -> Result<Message> {
        let (id, op_code) = (msg.id(), msg.op_code());
        Ok(match self.upstreams.resolve(if msg.query_count() == 1 {
                let q = msg.queries().iter().next().unwrap(); // Safe unwrap here because query_count == 1
                if (q.query_type() == RecordType::AAAA) && (self.disable_ipv6) {
                    // If `disable_ipv6` has been set, return immediately NXDomain.
                    return Ok(Message::error_msg(
                        msg.id(),
                        msg.op_code(),
                        ResponseCode::NXDomain,
                    ));
                } else {self.filter.get_upstream(q.name().to_utf8().as_str())?}
            } else {
                warn!("DNS message contains multiple queries, using default_tag to route. IPv6 disable functionality is NOT taking effect.");
                self.filter.default_tag()
        }, msg).await {
	    Ok(m) => m,
	    Err(e) => {
		// Catch all server failure here and return server fail
		warn!("Upstream encountered error: {}, returning SERVFAIL", e);
		Message::error_msg(id, op_code, ResponseCode::ServFail)
	    },
	})
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
            "undefined".into()
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
            "undefined".into()
        );
    }
}
