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

pub mod script;
pub mod upstreams;

use self::{
    script::{QueryContext, Script, ScriptBuilder},
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
    script: Script,
}

impl Validatable for Router {
    type Error = DrouteError;
    fn validate(&self, _: Option<&Vec<Label>>) -> Result<()> {
        self.script.validate(None)?;
        Ok(())
    }
}

impl Router {
    /// Create a new `Router` from raw
    pub fn new(script: Script) -> Result<Self> {
        let router = Self { script };
        router.validate(None)?;
        Ok(router)
    }

    /// Resolve the DNS query with routing rules defined.
    pub async fn resolve(
        &self,
        msg: Message<Bytes>,
        qctx: Option<QueryContext>,
    ) -> Result<Message<Bytes>> {
        // We have to ensure the number of queries is larger than 0 as it is a gurantee for actions/matchers.
        // Not using `query_count()` because it is manually set, and may not be correct.
        Ok(match msg.sole_question() {
            Ok(_) => {
                // Clone should be cheap here guaranteed by Bytes
                match self.script.route(msg.clone(), qctx) {
                    Ok(m) => m,
                    Err(e) => {
                        // Catch all server failure here and return server fail
                        warn!("upstream encountered error: {}, returning SERVFAIL", e);
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
pub struct RouterBuilder<U>
where
    U: AsyncTryInto<Upstreams, Error = UpstreamError>,
{
    script: ScriptBuilder,
    upstreams: U,
}

impl<U> RouterBuilder<U>
where
    U: AsyncTryInto<Upstreams, Error = UpstreamError>,
{
    /// Create a RouteBuilder
    pub fn new(script: ScriptBuilder, upstreams: U) -> Self {
        Self { script, upstreams }
    }
}

#[async_trait]
impl<U> AsyncTryInto<Router> for RouterBuilder<U>
where
    U: AsyncTryInto<Upstreams, Error = UpstreamError>,
{
    type Error = DrouteError;

    /// Build a new `Router` from configuration and check the validity. `data` is the content of the configuration file.
    async fn async_try_into(self) -> Result<Router> {
        let upstreams = self.upstreams.async_try_into().await?;
        Router::new(self.script.build(upstreams)?)
    }
}
