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

use super::{super::super::State, MatchError, Matcher, Result};
use crate::AsyncTryInto;
use async_trait::async_trait;
use log::info;
use maxminddb::{geoip2::Country, Reader};
use serde::Deserialize;
use std::{collections::HashSet, net::IpAddr, path::PathBuf, str::FromStr};
use trust_dns_proto::rr::record_data::RData::{A, AAAA};

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
        if let Some(ip) = state
            .resp
            .answers()
            .iter()
            .find(|&r| matches!(r.rdata(), A(_) | AAAA(_)))
            .map(|r| match *r.rdata() {
                A(addr) => IpAddr::V4(addr),
                AAAA(addr) => IpAddr::V6(addr),
                _ => unreachable!(),
            })
        {
            let r = if let Ok(r) = self.db.lookup::<Country>(ip) {
                r
            } else {
                return false;
            };

            r.country
                .and_then(|c| {
                    c.iso_code.map(|n| {
                        info!("The IP `{}` has ISO country code `{}`", ip, n);
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
    use crate::AsyncTryInto;
    use once_cell::sync::Lazy;
    use std::str::FromStr;
    use trust_dns_proto::{
        op::Message,
        rr::{resource::Record, Name, RData},
    };

    // Starting from droute's crate root
    static PATH: Lazy<Vec<u8>> =
        Lazy::new(|| include_bytes!("../../../../../../data/full.mmdb").to_vec());
    static RECORD_NOT_CHINA: Lazy<Record> = Lazy::new(|| {
        Record::from_rdata(
            Name::from_str("apple.com").unwrap(),
            10,
            RData::A("1.1.1.1".parse().unwrap()),
        )
    });
    static RECORD_CHINA: Lazy<Record> = Lazy::new(|| {
        Record::from_rdata(
            Name::from_str("baidu.com").unwrap(),
            10,
            RData::A("36.152.44.95".parse().unwrap()),
        )
    });

    fn create_state(v: Vec<Record>, m: &Message) -> State<'_> {
        State {
            resp: {
                let mut m = Message::new();
                m.insert_answers(v);
                m
            },
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
                .matches(&create_state(
                    vec![(RECORD_NOT_CHINA).clone()],
                    &Message::new()
                )),
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
                .matches(&create_state(
                    vec![(RECORD_NOT_CHINA).clone()],
                    &Message::new()
                )),
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
        assert_eq!(
            geoip.matches(&create_state(vec![(RECORD_CHINA).clone()], &Message::new())),
            true
        );
        assert_eq!(
            geoip.matches(&create_state(
                vec![(RECORD_NOT_CHINA).clone()],
                &Message::new()
            )),
            true
        )
    }

    #[tokio::test]
    async fn empty_records() {
        let em = Message::default();
        assert_eq!(
            GeoIpBuilder::from_buf(PATH.clone())
                .add_code("CN")
                .try_into()
                .await
                .unwrap()
                .matches(&State {
                    resp: Message::default(),
                    query: &em,
                }),
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
                .matches(&create_state(vec![(RECORD_CHINA).clone()], &Message::new())),
            true
        )
    }

    #[tokio::test]
    async fn unordered_is_china() {
        assert_eq!(
            GeoIpBuilder::from_buf(PATH.clone())
                .add_code("CN")
                .try_into()
                .await
                .unwrap()
                .matches(&create_state(
                    vec![
                        (RECORD_CHINA).clone(),
                        (RECORD_NOT_CHINA).clone(),
                        Record::from_rdata(
                            Name::from_str("baidu.com").unwrap(),
                            10,
                            RData::NS(Name::from_str("baidu.com").unwrap()),
                        ),
                    ],
                    &Message::new()
                )),
            true
        )
    }
}
