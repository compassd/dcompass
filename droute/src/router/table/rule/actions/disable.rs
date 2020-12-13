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

use super::{
    super::super::{super::upstreams::Upstreams, State},
    Action, Result,
};
use crate::{Label, MAX_TTL};
use async_trait::async_trait;
use lazy_static::lazy_static;
use trust_dns_proto::rr::{rdata::soa::SOA, record_data::RData, resource::Record, Name};

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

/// An action that sends back the message that may refrain the sender to continue to query.
pub struct Disable;

impl Default for Disable {
    /// Create a default `Disable` action.
    fn default() -> Self {
        Self
    }
}

#[async_trait]
impl Action for Disable {
    async fn act(&self, state: &mut State, _: &Upstreams) -> Result<()> {
        // unwrap should be safe here cause router will ensure the number of the queries is larger than zero.
        let r = Record::from_rdata(
            state.query.queries().iter().next().unwrap().name().clone(),
            MAX_TTL,
            SOA_RDATA.clone(),
        );

        state.resp = state.query.clone();
        // We can't add record to authority section but somehow it works
        state.resp.add_additional(r);
        Ok(())
    }

    fn used_upstream(&self) -> Option<Label> {
        None
    }
}
