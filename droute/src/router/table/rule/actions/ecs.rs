// Copyright 2021 LEXUGE
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

use std::{net::IpAddr, num::NonZeroUsize, str::FromStr, sync::Arc};

use super::{Action, ActionError, Result};
use crate::{
    cache::{EcsCache, RecordStatus},
    router::table::State,
    AsyncTryInto, Label, QueryContext, Upstreams,
};
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use domain::base::{opt::ClientSubnet, Message, MessageBuilder};
use serde::{Deserialize, Serialize};

/// An action that add ECS record into OPT section
#[derive(Clone)]
pub struct Ecs {
    cache: Arc<EcsCache>,
    api: String,
}

impl Ecs {
    /// Create a `Query` action with its associated upstream tag.
    pub fn new(api: String) -> Result<Self> {
        Ok(Self {
            cache: Arc::new(EcsCache::new(NonZeroUsize::new(512).unwrap())?),
            api,
        })
    }
}

impl Ecs {
    async fn get_external_ip(&self, ip: IpAddr) -> Result<IpAddr> {
        // If we reuse the client, internal client pool will not be updated if network condition changes.
        let external_ip = reqwest::get(&self.api).await?.text().await?;
        log::info!("got external IP: {}", external_ip.trim());
        // The answer should be a valid IP address
        let external_ip = IpAddr::from_str(external_ip.trim()).unwrap();
        self.cache.put(ip, external_ip).await;
        Ok(external_ip)
    }
}

fn add_ecs_record(msg: &Message<Bytes>, ip: IpAddr) -> Result<Message<Bytes>> {
    let source_prefix_len = match ip {
        IpAddr::V4(_) => 24,
        IpAddr::V6(_) => 56,
    };
    let mut builder = MessageBuilder::from_target(BytesMut::from(msg.as_slice()))?;
    *builder.header_mut() = msg.header();
    let mut builder = builder.question();
    for item in msg.question().flatten() {
        builder.push(item)?;
    }
    let mut builder = builder.additional();
    builder.opt(|opt| ClientSubnet::push(opt, source_prefix_len, 0, ip))?;
    Ok(builder.into_message())
}

#[async_trait]
impl Action for Ecs {
    async fn act(&self, state: &mut State, _: &Upstreams) -> Result<()> {
        if let Some(QueryContext { ip }) = state.qctx {
            // Test if the origin has a global IP address
            // TODO: We should use ip.is_global() instead once stabalized
            let global = match ip {
                IpAddr::V4(ref ip) => {
                    !ip.is_private()
                        && !ip.is_broadcast()
                        && !ip.is_link_local()
                        && !ip.is_loopback()
                        && !ip.is_unspecified()
                }
                IpAddr::V6(ref ip) => ip.is_multicast() && (ip.segments()[0] & 0x000f == 14),
            };
            if global {
                log::debug!("appending global origin IP address ECS info to the OPT section");
                // If the query sender has external IP
                state.query = add_ecs_record(&state.query, ip)?;
            } else {
                log::debug!("trying to obtain external IP address for local query IP");
                match self.cache.get(&ip) {
                    Some(RecordStatus::Alive(r)) => {
                        // Alive external IP cache
                        // Immediately return back
                        state.query = add_ecs_record(&state.query, r)?;
                    }
                    Some(RecordStatus::Expired(r)) => {
                        // Expired record
                        let ecs = self.clone();
                        state.query = add_ecs_record(&state.query, r)?;
                        tokio::spawn(async move {
                            // We have to update the cache though
                            // We don't care about failures here.
                            // Get external_ip will update cache automatically.
                            let _ = ecs.get_external_ip(ip).await;
                        });
                    }
                    None => {
                        // No cache
                        state.query =
                            add_ecs_record(&state.query, self.get_external_ip(ip).await?)?;
                    }
                }
            };
        } else {
            // Do nothing if there is no origin IP.
            log::warn!("no origin IP address found to append ECS record");
        }
        Ok(())
    }

    fn used_upstream(&self) -> Option<Label> {
        None
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct EcsBuilder {
    api: String,
}

#[async_trait]
impl AsyncTryInto<Ecs> for EcsBuilder {
    type Error = ActionError;

    async fn try_into(self) -> Result<Ecs> {
        Ecs::new(self.api)
    }
}
