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

pub mod table;
pub mod upstreams;

#[cfg(feature = "serde-cfg")]
use self::{
    table::parsed::{ParActionTrait, ParMatcherTrait, ParRule},
    upstreams::parsed::{ParUpstream, ParUpstreamKind},
};
use self::{table::Table, upstreams::Upstreams};
use crate::{
    error::{DrouteError, Result},
    Label, Validatable,
};
use log::warn;
use std::collections::HashSet;
use trust_dns_client::op::{Message, ResponseCode};

/// Router implementation.
pub struct Router {
    table: Table,
    upstreams: Upstreams,
}

impl Validatable for Router {
    type Error = DrouteError;
    fn validate(&self, _: Option<&HashSet<Label>>) -> Result<()> {
        self.table.validate(None)?;
        self.upstreams.validate(Some(self.table.used_upstreams()))?;
        Ok(())
    }
}

impl Router {
    /// Create a new `Router` from raw
    pub fn new(table: Table, upstreams: Upstreams) -> Result<Self> {
        let router = Self { table, upstreams };
        router.validate(None)?;
        Ok(router)
    }

    /// Create a new `Router` from parsed configuration and check the validity. `data` is the content of the configuration file.
    #[cfg(feature = "serde-cfg")]
    pub async fn parse(
        cache_size: usize,
        rules: Vec<ParRule<impl ParMatcherTrait, impl ParActionTrait>>,
        upstreams: Vec<ParUpstream<impl ParUpstreamKind>>,
    ) -> Result<Self> {
        let table = Table::parse(rules).await?;
        let upstreams = Upstreams::parse(upstreams, cache_size).await?;
        Self::new(table, upstreams)
    }

    /// Validate the internal rules defined. This is automatically performed by `new` method.

    /// Resolve the DNS query with routing rules defined.
    pub async fn resolve(&self, msg: Message) -> Result<Message> {
        let (id, op_code) = (msg.id(), msg.op_code());
        // We have to ensure the number of queries is larger than 0 as it is a gurantee for actions/matchers.
        // Not using `query_count()` because it is manually set, and may not be correct.
        if !msg.queries().is_empty() {
            Ok(match self.table.route(msg, &self.upstreams).await {
                Ok(m) => m,
                Err(e) => {
                    // Catch all server failure here and return server fail
                    warn!("Upstream encountered error: {}, returning SERVFAIL", e);
                    Message::error_msg(id, op_code, ResponseCode::ServFail)
                }
            })
        } else {
            warn!("DNS message contains zero querie(s), doing nothing.");
            Ok(Message::error_msg(id, op_code, ResponseCode::ServFail))
        }
    }
}
