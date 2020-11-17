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

pub mod filter;
pub mod matcher;
pub mod upstream;

use self::filter::Filter;
use self::filter::Rule;
use self::matcher::Matcher;
use self::upstream::{Upstream, Upstreams};
use crate::error::Result;
use lazy_static::lazy_static;
use log::warn;
use std::fmt::{Debug, Display};
use std::hash::Hash;
use trust_dns_client::op::Message;
use trust_dns_client::op::ResponseCode;
use trust_dns_client::rr::{
    rdata::soa::SOA, record_data::RData, resource::Record, Name, RecordType,
};

// Maximum TTL as defined in https://tools.ietf.org/html/rfc2181, 2147483647
//   Setting this to a value of 1 day, in seconds
pub(self) const MAX_TTL: u32 = 86400_u32;

// Data from smartdns. https://github.com/pymumu/smartdns/blob/42b3e98b2a3ca90ea548f8cb5ed19a3da6011b74/src/dns_server.c#L651
lazy_static! {
    static ref SOA_RDATA: RData = {
        RData::SOA(SOA::new(
            Name::from_utf8("a.gtld-servers.net").unwrap(),
            Name::from_utf8("nstld.verisign-grs.com").unwrap(),
            1800,
            1800,
            900,
            604800,
            86400,
        ))
    };
}

/// Router implementation.
/// `'static + Send + Sync` is required for async usages.
/// `Display + Debug` is required for Error formatting implementation (It is intuitive for you to have your label readable).
/// `Eq + Clone + Hash` is required for internal design.
pub struct Router<L, M> {
    filter: Filter<L, M>,
    disable_ipv6: bool,
    upstreams: Upstreams<L>,
}

impl<L, M: Matcher<Label = L>> Router<L, M>
where
    L: 'static + Display + Debug + Eq + Hash + Send + Clone + Sync,
{
    /// Create a new `Router` from configuration and check the validity. `data` is the content of the configuration file.
    pub async fn new(
        upstreams: Vec<Upstream<L>>,
        disable_ipv6: bool,
        cache_size: usize,
        default_tag: L,
        rules: Vec<Rule<L>>,
    ) -> Result<L, Self> {
        let filter = Filter::new(default_tag, rules).await?;
        let router = Self {
            disable_ipv6,
            upstreams: Upstreams::new(upstreams, cache_size).await?,
            filter,
        };
        router.check()?;
        Ok(router)
    }

    /// Validate the internal rules defined. This is automatically performed by `new` method.
    pub fn check(&self) -> Result<L, bool> {
        self.upstreams.hybrid_check()?;
        for dst in self.filter.get_dsts() {
            self.upstreams.exists(dst)?;
        }
        self.upstreams.exists(&self.filter.default_tag())?;
        Ok(true)
    }

    /// Resolve the DNS query with routing rules defined.
    pub async fn resolve(&self, mut msg: Message) -> Result<L, Message> {
        let (id, op_code) = (msg.id(), msg.op_code());
        let tag = if msg.query_count() == 1 {
            let q = msg.queries().iter().next().unwrap(); // Safe unwrap here because query_count == 1
            if (q.query_type() == RecordType::AAAA) && (self.disable_ipv6) {
                // If `disable_ipv6` has been set, return immediately SOA.
                return Ok({
                    let r = Record::from_rdata(q.name().clone(), MAX_TTL, SOA_RDATA.clone());
                    // We can't add record to authority section but somehow it works
                    msg.add_additional(r);
                    msg
                });
            } else {
                self.filter.get_upstream(q.name().to_utf8().as_str())
            }
        } else {
            warn!("DNS message contains multiple queries, using default_tag to route. IPv6 disable functionality is NOT taking effect.");
            self.filter.default_tag()
        };
        Ok(match self.upstreams.resolve(tag, &msg).await {
            Ok(m) => m,
            Err(e) => {
                // Catch all server failure here and return server fail
                warn!("Upstream encountered error: {}, returning SERVFAIL", e);
                Message::error_msg(id, op_code, ResponseCode::ServFail)
            }
        })
    }
}
