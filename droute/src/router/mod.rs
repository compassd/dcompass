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

use self::{
    table::{Table, TableError},
    upstreams::{error::UpstreamError, Upstreams},
};
use crate::{
    error::{DrouteError, Result},
    AsyncTryInto, Label, Validatable, MAX_LEN,
};
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use domain::base::{iana::rcode::Rcode, Message, MessageBuilder};
use log::warn;

/// Router implementation.
pub struct Router {
    table: Table,
    upstreams: Upstreams,
}

impl Validatable for Router {
    type Error = DrouteError;
    fn validate(&self, _: Option<&Vec<Label>>) -> Result<()> {
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

    /// Resolve the DNS query with routing rules defined.
    pub async fn resolve(&self, msg: Message<Bytes>) -> Result<Message<Bytes>> {
        // We have to ensure the number of queries is larger than 0 as it is a gurantee for actions/matchers.
        // Not using `query_count()` because it is manually set, and may not be correct.
        Ok(match msg.sole_question() {
            Ok(_) => {
                // Clone should be cheap here guaranteed by Bytes
                match self.table.route(msg.clone(), &self.upstreams).await {
                    Ok(m) => m,
                    Err(e) => {
                        // Catch all server failure here and return server fail
                        warn!("Upstream encountered error: {}, returning SERVFAIL", e);
                        MessageBuilder::from_target(BytesMut::with_capacity(MAX_LEN))?
                            .start_answer(&msg, Rcode::ServFail)?
                            .into_message()
                    }
                }
            }
            Err(e) => {
                warn!("DNS message parsing errored: {}.", e);
                MessageBuilder::from_target(BytesMut::with_capacity(MAX_LEN))?
                    .start_answer(&msg, Rcode::ServFail)?
                    .into_message()
            }
        })
    }
}

/// A Builder for Router.
pub struct RouterBuilder<T, U>
where
    T: AsyncTryInto<Table, Error = TableError>,
    U: AsyncTryInto<Upstreams, Error = UpstreamError>,
{
    table: T,
    upstreams: U,
}

impl<T, U> RouterBuilder<T, U>
where
    T: AsyncTryInto<Table, Error = TableError>,
    U: AsyncTryInto<Upstreams, Error = UpstreamError>,
{
    /// Create a RouteBuilder
    pub fn new(table: T, upstreams: U) -> Self {
        Self { table, upstreams }
    }
}

#[async_trait]
impl<T, U> AsyncTryInto<Router> for RouterBuilder<T, U>
where
    T: AsyncTryInto<Table, Error = TableError>,
    U: AsyncTryInto<Upstreams, Error = UpstreamError>,
{
    type Error = DrouteError;

    /// Build a new `Router` from configuration and check the validity. `data` is the content of the configuration file.
    async fn try_into(self) -> Result<Router> {
        let table = self.table.try_into().await?;
        let upstreams = self.upstreams.try_into().await?;
        Router::new(table, upstreams)
    }
}
