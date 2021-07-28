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

use std::str::FromStr;

use super::{
    super::super::{super::upstreams::Upstreams, State},
    Action, Result,
};
use crate::{Label, MAX_TTL};
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use domain::{
    base::{Dname, MessageBuilder},
    rdata::Soa,
};
use once_cell::sync::Lazy;

// Data from smartdns. https://github.com/pymumu/smartdns/blob/42b3e98b2a3ca90ea548f8cb5ed19a3da6011b74/src/dns_server.c#L651
static SOA_RDATA: Lazy<(Dname<Bytes>, u32, Soa<Dname<Bytes>>)> = Lazy::new(|| {
    (
        Dname::root_bytes(),
        MAX_TTL,
        Soa::new(
            Dname::from_str("a.gtld-servers.net").unwrap(),
            Dname::from_str("nstld.verisign-grs.com").unwrap(),
            1800.into(),
            1800,
            900,
            604800,
            86400,
        ),
    )
});

/// An action that sends back the message that may refrain the sender to continue to query.
pub struct Blackhole;

impl Default for Blackhole {
    /// Create a default `Disable` action.
    fn default() -> Self {
        Self
    }
}

#[async_trait]
impl Action for Blackhole {
    async fn act(&self, state: &mut State, _: &Upstreams) -> Result<()> {
        // Is 50 a good number?
        let mut builder = MessageBuilder::from_target(BytesMut::with_capacity(50))?.additional();

        builder.push(SOA_RDATA.clone())?;

        state.resp = builder.into_message();
        Ok(())
    }

    fn used_upstream(&self) -> Option<Label> {
        None
    }
}
