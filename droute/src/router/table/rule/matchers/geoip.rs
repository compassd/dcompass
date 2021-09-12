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

use super::{super::super::State, get_ip_addr, MatchError, Matcher, Result};
use crate::AsyncTryInto;
use async_trait::async_trait;
use log::info;
use maxminddb::{geoip2::Country, Reader};
use serde::Deserialize;
use std::{collections::HashSet, path::PathBuf, str::FromStr};

/// A matcher that matches if IP address in the record of the first A/AAAA response is in the list of countries.
pub struct GeoIp {
    db: Reader<Vec<u8>>,
    list: HashSet<String>,
}

impl GeoIp {
    /// Create a new `Geoip` matcher from a set of ISO country codes like `CN`, `AU`.
    pub fn new(list: HashSet<String>, buf: Vec<u8>) -> Result<Self> {
        Ok(Self {
            list,
            db: Reader::from_source(buf)?,
        })
    }
}

impl Matcher for GeoIp {
    fn matches(&self, state: &State) -> bool {
        if let Ok(Some(ip)) = get_ip_addr(&state.resp) {
            let r = if let Ok(r) = self.db.lookup::<Country>(ip) {
                r
            } else {
                return false;
            };

            r.country
                .and_then(|c| {
                    c.iso_code.map(|n| {
                        info!("IP `{}` has ISO country code `{}`", ip, n);
                        self.list.contains(n)
                    })
                })
                .unwrap_or(false)
        } else {
            false
        }
    }
}

#[derive(Deserialize, Clone, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
/// Arguments of the GeoIp.
pub struct GeoIpBuilder {
    /// Country codes to match on
    codes: HashSet<String>,
    /// Buf
    buf: Vec<u8>,
}

impl GeoIpBuilder {
    pub async fn from_path(path: impl AsRef<str>) -> Result<Self> {
        // Per std documentation, this is infallible
        let buf: Vec<u8> = tokio::fs::read(PathBuf::from_str(path.as_ref()).unwrap()).await?;
        Ok(Self {
            codes: HashSet::new(),
            buf,
        })
    }

    pub fn from_buf(buf: Vec<u8>) -> Self {
        Self {
            codes: HashSet::new(),
            buf,
        }
    }

    pub fn add_code(mut self, code: impl ToString) -> Self {
        self.codes.insert(code.to_string());
        self
    }
}

#[async_trait]
impl AsyncTryInto<GeoIp> for GeoIpBuilder {
    async fn try_into(self) -> Result<GeoIp> {
        // By default, we don't provide any builtin database.
        Ok(GeoIp::new(self.codes, self.buf)?)
    }

    type Error = MatchError;
}

#[cfg(test)]
mod tests {
    use super::{super::Matcher, GeoIpBuilder, State};
    use crate::{AsyncTryInto, MAX_LEN};
    use bytes::{Bytes, BytesMut};
    use domain::{
        base::{Dname, Message, MessageBuilder},
        rdata::A,
    };
    use once_cell::sync::Lazy;
    use std::str::FromStr;

    // Starting from droute's crate root
    static PATH: Lazy<Vec<u8>> =
        Lazy::new(|| include_bytes!("../../../../../../data/full.mmdb").to_vec());
    static MESSAGE_NOT_CHINA: Lazy<Message<Bytes>> = Lazy::new(|| {
        let name = Dname::<Bytes>::from_str("cloudflare-dns.com").unwrap();
        let mut builder = MessageBuilder::from_target(BytesMut::with_capacity(MAX_LEN))
            .unwrap()
            .answer();
        builder
            .push((&name, 10, A::from_octets(1, 1, 1, 1)))
            .unwrap();
        builder.into_message()
    });
    static MESSAGE_CHINA: Lazy<Message<Bytes>> = Lazy::new(|| {
        let name = Dname::<Bytes>::from_str("baidu.com").unwrap();
        let mut builder = MessageBuilder::from_target(BytesMut::with_capacity(MAX_LEN))
            .unwrap()
            .answer();
        // This makes sure that even with non-chinese records blended, GeoIP still works fine.
        // But GeoIP only looks at the first A/AAAA record.
        builder
            .push((&name, 10, A::from_octets(180, 101, 49, 12)))
            .unwrap();
        builder
            .push((&Dname::root_bytes(), 10, A::from_octets(1, 1, 1, 1)))
            .unwrap();
        builder.into_message()
    });

    fn create_state(m: Message<Bytes>) -> State {
        State {
            resp: m.clone(),
            query: m,
        }
    }

    #[tokio::test]
    async fn builtin_db_not_china() {
        assert_eq!(
            GeoIpBuilder::from_buf(PATH.clone())
                .add_code("CN")
                .try_into()
                .await
                .unwrap()
                .matches(&create_state(MESSAGE_NOT_CHINA.clone())),
            false
        )
    }

    #[tokio::test]
    async fn not_china() {
        assert_eq!(
            GeoIpBuilder::from_buf(PATH.clone())
                .add_code("CN")
                .try_into()
                .await
                .unwrap()
                .matches(&create_state(MESSAGE_NOT_CHINA.clone())),
            false
        )
    }

    #[tokio::test]
    async fn mixed() {
        let geoip = GeoIpBuilder::from_buf(PATH.clone())
            .add_code("CN")
            .add_code("AU")
            .try_into()
            .await
            .unwrap();
        assert_eq!(geoip.matches(&create_state(MESSAGE_CHINA.clone())), true);
        assert_eq!(
            geoip.matches(&create_state(MESSAGE_NOT_CHINA.clone())),
            true
        )
    }

    #[tokio::test]
    async fn empty_records() {
        assert_eq!(
            GeoIpBuilder::from_buf(PATH.clone())
                .add_code("CN")
                .try_into()
                .await
                .unwrap()
                .matches(&create_state(
                    Message::from_octets(Bytes::from_static(&[0_u8; 55])).unwrap()
                )),
            false,
        )
    }

    #[tokio::test]
    async fn is_china() {
        assert_eq!(
            GeoIpBuilder::from_buf(PATH.clone())
                .add_code("CN")
                .try_into()
                .await
                .unwrap()
                .matches(&create_state(MESSAGE_CHINA.clone())),
            true
        )
    }
}
