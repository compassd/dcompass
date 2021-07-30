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

use super::{QHandle, QHandleError, Result};
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use domain::base::Message;
use reqwest::{Client, Proxy, Url};
use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
    time::Duration,
};
use tokio::time::timeout;

/// Client instance for UDP connections
#[derive(Clone)]
pub struct Https {
    client: Client,
    uri: Url,
    timeout: Duration,
}

static APP_USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"),);

impl Https {
    /// Create a new HTTPS client creator instance. with the given remote server address.
    pub async fn new(
        uri: String,
        addr: IpAddr,
        proxy: Option<String>,
        timeout: Duration,
    ) -> Result<Self> {
        let uri = Url::from_str(&uri).map_err(|_| QHandleError::InvalidUri(uri))?;
        let domain = uri
            .domain()
            .ok_or_else(|| QHandleError::InvalidDomain(uri.clone()))?;

        let client = Client::builder()
            // The port in socket addr doesn't take effect here per documentation
            .resolve(domain, SocketAddr::new(addr, 0))
            .https_only(true)
            .user_agent(APP_USER_AGENT)
            .connect_timeout(Duration::from_secs(3))
            .pool_max_idle_per_host(32);

        let client = if let Some(proxy) = proxy {
            client.proxy(Proxy::all(proxy)?)
        } else {
            client
        };
        Ok(Self {
            client: client.build()?,
            uri,
            timeout,
        })
    }
}

#[async_trait]
impl QHandle for Https {
    async fn query(&self, msg: &Message<Bytes>) -> Result<Message<Bytes>> {
        // Per RFC, the message ID should be set to 0 to better facilitate HTTPS caching.
        let mut msg = Message::from_octets(BytesMut::from(msg.as_slice()))?;
        msg.header_mut().set_id(0);

        let body: reqwest::Body = msg.into_octets().freeze().into();
        let res = self
            .client
            .post(self.uri.clone())
            .header("content-type", "application/dns-message")
            .body(body)
            .send()
            .await?;

        timeout(self.timeout, async {
            if res.status().is_success() {
                let res = res.bytes().await?;
                let answer = Message::from_octets(res)?;
                Ok(answer)
            } else {
                Err(QHandleError::FailedHttp(res.status()))
            }
        })
        .await?
    }
}
