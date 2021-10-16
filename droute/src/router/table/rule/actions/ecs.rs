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

use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
    time::Duration,
};

use super::{Action, ActionError, Result};
use crate::{
    cache::{EcsCache, RecordStatus},
    router::table::State,
    AsyncTryInto, Label, Upstreams,
};
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use domain::{
    base::{
        opt::{AllOptData, ClientSubnet},
        Message, MessageBuilder, ShortBuf,
    },
    rdata::AllRecordData,
};
use reqwest::{Client, Proxy, Url};
use serde::{Deserialize, Serialize};

/// An action that add ECS record into additional section
#[derive(Clone)]
pub enum Ecs {
    // inner arc
    /// Dynamically update and fetch external IP
    Dynamic {
        /// The EcsCache
        cache: EcsCache,
        /// Inner Client
        client: Client,
        /// Internal API
        api: String,
    },
    /// Statically assign an external IP to use
    Static(IpAddr),
}

impl Ecs {
    /// Create a new dynamic API
    pub fn new_dynamic(api: String, addr: Option<IpAddr>, proxy: Option<String>) -> Result<Self> {
        let client = Client::builder()
            .https_only(true)
            .connect_timeout(Duration::from_secs(3));

        let client = if let Some(addr) = addr {
            // The port in socket addr doesn't take effect here per documentation
            client.resolve(
                Url::from_str(&api)
                    .map_err(|_| ActionError::InvalidUrl(api.clone()))?
                    .domain()
                    .ok_or_else(|| ActionError::InvalidUrl(api.clone()))?,
                SocketAddr::new(addr, 0),
            )
        } else {
            client
        };

        let client = if let Some(proxy) = proxy {
            client.proxy(Proxy::all(proxy)?)
        } else {
            client
        }
        .build()?;

        Ok(Self::Dynamic {
            api,
            client,
            cache: EcsCache::new(),
        })
    }

    // Update the external IP and cache; return the IP address
    async fn get_and_update_external_ip(&self) -> Result<IpAddr> {
        match self {
            Self::Dynamic { cache, client, api } => {
                let external_ip = client.get(api).send().await?.text().await?;
                log::info!("got external IP: {}", external_ip.trim());
                // The answer should be a valid IP address
                let external_ip = IpAddr::from_str(external_ip.trim()).unwrap();
                cache.put(external_ip).await;
                Ok(external_ip)
            }
            _ => unreachable!(),
        }
    }
}

// TODO: We should test this function thoroughly
fn add_ecs_record(msg: &Message<Bytes>, ip: IpAddr) -> Result<Message<Bytes>> {
    let source_prefix_len = match ip {
        IpAddr::V4(_) => 24,
        IpAddr::V6(_) => 56,
    };
    // Copy all the questions and headers here.
    let mut builder = MessageBuilder::from_target(BytesMut::from(msg.as_slice()))?;
    *builder.header_mut() = msg.header();
    let mut builder = builder.question();
    for item in msg.question().flatten() {
        builder.push(item)?;
    }
    let mut builder = builder.additional();
    // Per RFC 6891
    // The OPT RR MAY be placed anywhere within the additional data section.
    // When an OPT RR is included within any DNS message, it MUST be the
    // only OPT RR in that message.

    // Whether we have already seen an OPT record.
    let mut flag = false;
    for item in msg.additional()? {
        if let Some(record) = item?.into_record::<AllRecordData<_, _>>()? {
            // If this is an OPT record
            match (record.data(), flag) {
                (AllRecordData::Opt(opt), false) => {
                    builder.opt(|builder| {
                        // Iterate on all the options
                        for option in opt.iter() {
                            let option = option.map_err(|_| ShortBuf)?;
                            if let AllOptData::ClientSubnet(_) = option {
                                // If this is an ECS option, we should not add it
                            } else {
                                // Otherwise we copy the option
                                builder.push(&option)?
                            }
                        }
                        // Finally we add our own ECS option
                        ClientSubnet::push(builder, source_prefix_len, 0, ip)?;
                        Ok(())
                    })?;
                    flag = true
                }
                (AllRecordData::Opt(_), true) => {} // We have already encountered an OPT record, DON'T copy it
                (_, _) => {
                    builder.push(record)?;
                }
            }
        }
    }
    Ok(builder.into_message())
}

#[async_trait]
impl Action for Ecs {
    async fn act(&self, state: &mut State, _: &Upstreams) -> Result<()> {
        if let Some(ip) = state.origin_ip() {
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

            // Obtain the external IP
            let external_ip = if global {
                log::debug!("appending global IP {} to the ECS info", ip);
                // If the query sender has external IP
                ip
            } else {
                log::debug!("trying to obtain external IP address for local query IP");
                match self {
                    Self::Dynamic { cache, .. } => match cache.get(&ip) {
                        Some(RecordStatus::Alive(r)) => {
                            // Alive external IP cache
                            // Immediately return back
                            r
                        }
                        Some(RecordStatus::Expired(r)) => {
                            // Expired record
                            let ecs = self.clone();
                            tokio::spawn(async move {
                                // We have to update the cache though
                                // We don't care about failures here.
                                // Get external_ip will update cache automatically.
                                let _ = ecs.get_and_update_external_ip().await;
                            });
                            r
                        }
                        None => {
                            // No cache
                            self.get_and_update_external_ip().await?
                        }
                    },
                    Self::Static(ip) => {
                        log::debug!("got manually defined IP address: {}", ip);
                        *ip
                    }
                }
            };

            // Append the record
            state.query = add_ecs_record(&state.query, external_ip)?;
        } else {
            // Do nothing if there is no origin IP.
            log::warn!("no origin IP address found to generate ECS record");
        }
        Ok(())
    }

    fn used_upstream(&self) -> Option<Label> {
        None
    }
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
/// Build ECS with two modes
pub enum EcsBuilder {
    /// Automatically obtain and manage the external IP using an API
    Auto {
        /// The API address to obtain your external IP. e.g. https://ifconfig.me
        api: String,
        /// An optional IP addr to use if you want to bootstrap this plugin
        addr: Option<IpAddr>,
        /// An optional SOCKS5 proxy
        proxy: Option<String>,
    },
    /// Manually assign an external IP
    Manual(IpAddr),
}

#[async_trait]
impl AsyncTryInto<Ecs> for EcsBuilder {
    type Error = ActionError;

    async fn try_into(self) -> Result<Ecs> {
        Ok(match self {
            EcsBuilder::Auto { api, addr, proxy } => Ecs::new_dynamic(api, addr, proxy)?,
            EcsBuilder::Manual(ip) => Ecs::Static(ip),
        })
    }
}

#[cfg(test)]
mod tests {
    use bytes::{Bytes, BytesMut};
    use domain::base::{
        octets::ParseError,
        opt::{AllOptData, ClientSubnet, Cookie},
        MessageBuilder,
    };

    use super::add_ecs_record;

    #[test]
    fn overwrite_ecs() {
        // First of all, we should overwrite all ECS option. i.e. Remove all ECS options and add our own.
        // Second of all, we should only push back one OPT record.
        let mut builder = MessageBuilder::<BytesMut>::new_bytes().additional();
        builder
            .opt(|opt| {
                ClientSubnet::push(opt, 32, 0, "1.1.1.1".parse().unwrap())?;
                opt.push(&AllOptData::<Bytes>::Cookie(Cookie::new([7; 8])))?;
                Ok(())
            })
            .unwrap();
        builder
            .opt(|opt| ClientSubnet::push(opt, 24, 0, "1.1.1.1".parse().unwrap()))
            .unwrap();
        let msg = builder.into_message();

        let v = add_ecs_record(&msg, "9.9.9.9".parse().unwrap())
            .unwrap()
            .opt()
            .unwrap()
            .as_opt()
            .iter::<AllOptData<Bytes>>()
            .collect::<Result<Vec<AllOptData<Bytes>>, ParseError>>()
            .unwrap();
        assert_eq!(v.len(), 2);
        // AllOptData doesn't implement debug
        // Cookie
        match v[0] {
            AllOptData::Cookie(cookie) => {
                assert_eq!(cookie.cookie(), [7; 8]);
            }
            _ => unreachable!(),
        };

        match v[1] {
            AllOptData::ClientSubnet(cs) => {
                assert_eq!(cs.source_prefix_len(), 24);
                assert_eq!(cs.scope_prefix_len(), 0);
                assert_eq!(cs.addr(), "9.9.9.0".parse::<std::net::IpAddr>().unwrap());
            }
            _ => unreachable!(),
        };
    }

    #[test]
    fn add_ecs_opt() {
        // First of all, we should overwrite all ECS option. i.e. Remove all ECS options and add our own.
        // Second of all, we should only push back one OPT record.
        // Third of all, even if there is no ECS option already, we should add one.
        let mut builder = MessageBuilder::<BytesMut>::new_bytes().additional();
        builder
            .opt(|opt| opt.push(&AllOptData::<Bytes>::Cookie(Cookie::new([7; 8]))))
            .unwrap();
        let msg = builder.into_message();

        let v = add_ecs_record(&msg, "9.9.9.9".parse().unwrap())
            .unwrap()
            .opt()
            .unwrap()
            .as_opt()
            .iter::<AllOptData<Bytes>>()
            .collect::<Result<Vec<AllOptData<Bytes>>, ParseError>>()
            .unwrap();
        assert_eq!(v.len(), 2);
        // AllOptData doesn't implement debug
        // Cookie
        match v[0] {
            AllOptData::Cookie(cookie) => {
                assert_eq!(cookie.cookie(), [7; 8]);
            }
            _ => unreachable!(),
        };

        match v[1] {
            AllOptData::ClientSubnet(cs) => {
                assert_eq!(cs.source_prefix_len(), 24);
                assert_eq!(cs.scope_prefix_len(), 0);
                assert_eq!(cs.addr(), "9.9.9.0".parse::<std::net::IpAddr>().unwrap());
            }
            _ => unreachable!(),
        };
    }
}
