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

use super::{super::super::State, Matcher, Result};
use hashbrown::HashSet;
use log::info;
use maxminddb::{geoip2::Country, Reader};
#[cfg(feature = "serde-cfg")]
use serde::Deserialize;
use std::net::IpAddr;
use trust_dns_proto::rr::record_data::RData::{A, AAAA};

#[cfg_attr(feature = "serde-cfg", derive(Deserialize))]
#[cfg_attr(feature = "serde-cfg", serde(rename_all = "lowercase"))]
#[derive(Clone, Eq, PartialEq)]
/// Target for GeoIP to match on
pub enum GeoIpTarget {
    /// Match on the IP of the query sender.
    Src,
    /// Match on the response.
    Resp,
}

/// A matcher that matches if IP address in the record of the first A/AAAA response is in the list of countries.
pub struct Geoip {
    db: Reader<Vec<u8>>,
    list: HashSet<String>,
    on: GeoIpTarget,
}

impl Geoip {
    /// Create a new `Geoip` matcher from a set of ISO country codes like `CN`, `AU`.
    pub fn new(on: GeoIpTarget, list: HashSet<String>) -> Result<Self> {
        Ok(Self {
            on,
            list,
            db: Reader::from_source(
                include_bytes!("../../../../../../data/Country.mmdb").to_vec(),
            )?,
        })
    }
}

impl Matcher for Geoip {
    fn matches(&self, state: &State) -> bool {
        if let Some(ip) = match self.on {
            GeoIpTarget::Src => state.src.map(|i| i.ip()),
            GeoIpTarget::Resp => state
                .resp
                .answers()
                .iter()
                .find(|&r| matches!(r.rdata(), A(_) | AAAA(_)))
                .map(|r| match *r.rdata() {
                    A(addr) => IpAddr::V4(addr),
                    AAAA(addr) => IpAddr::V6(addr),
                    _ => unreachable!(),
                }),
        } {
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

#[cfg(test)]
mod tests {
    use super::{super::Matcher, GeoIpTarget::*, Geoip, State};
    use std::str::FromStr;
    use trust_dns_proto::{
        op::Message,
        rr::{resource::Record, Name, RData},
    };

    #[test]
    fn src_is_china() {
        assert_eq!(
            Geoip::new(Src, vec!["CN".to_string()].into_iter().collect())
                .unwrap()
                .matches(&State {
                    // Port if not important here.
                    src: Some("36.152.44.95:1".parse().unwrap()),
                    ..Default::default()
                }),
            true
        )
    }

    #[test]
    fn src_is_not_china() {
        assert_eq!(
            Geoip::new(Src, vec!["CN".to_string()].into_iter().collect())
                .unwrap()
                .matches(&State {
                    src: Some("1.1.1.1:1".parse().unwrap()),
                    ..Default::default()
                }),
            false
        )
    }

    #[test]
    fn empty_src() {
        assert_eq!(
            Geoip::new(Src, vec!["CN".to_string()].into_iter().collect())
                .unwrap()
                .matches(&State::default()),
            false
        )
    }

    #[test]
    fn not_china() {
        assert_eq!(
            Geoip::new(Resp, vec!["CN".to_string()].into_iter().collect())
                .unwrap()
                .matches(&State {
                    resp: {
                        let mut m = Message::new();
                        m.insert_answers(
                            [Record::from_rdata(
                                Name::from_str("apple.com").unwrap(),
                                10,
                                RData::A("1.1.1.1".parse().unwrap()),
                            )]
                            .to_vec(),
                        );
                        m
                    },
                    ..Default::default()
                }),
            false
        )
    }

    #[test]
    fn mixed() {
        let geoip = Geoip::new(
            Resp,
            vec!["CN".to_string(), "AU".to_string()]
                .into_iter()
                .collect(),
        )
        .unwrap();
        assert_eq!(
            geoip.matches(&State {
                resp: {
                    let mut m = Message::new();
                    m.insert_answers(
                        [Record::from_rdata(
                            Name::from_str("apple.com").unwrap(),
                            10,
                            RData::A("1.1.1.1".parse().unwrap()),
                        )]
                        .to_vec(),
                    );
                    m
                },
                ..Default::default()
            }),
            true
        );
        assert_eq!(
            geoip.matches(&State {
                resp: {
                    let mut m = Message::new();
                    m.insert_answers(
                        [Record::from_rdata(
                            Name::from_str("baidu.com").unwrap(),
                            10,
                            RData::A("36.152.44.95".parse().unwrap()),
                        )]
                        .to_vec(),
                    );
                    m
                },
                ..Default::default()
            }),
            true
        )
    }

    #[test]
    fn empty_records() {
        assert_eq!(
            Geoip::new(Resp, vec!["CN".to_string()].into_iter().collect())
                .unwrap()
                .matches(&State::default()),
            false,
        )
    }

    #[test]
    fn is_china() {
        assert_eq!(
            Geoip::new(Resp, vec!["CN".to_string()].into_iter().collect())
                .unwrap()
                .matches(&State {
                    resp: {
                        let mut m = Message::new();
                        m.insert_answers(
                            [Record::from_rdata(
                                Name::from_str("baidu.com").unwrap(),
                                10,
                                RData::A("36.152.44.95".parse().unwrap()),
                            )]
                            .to_vec(),
                        );
                        m
                    },
                    ..Default::default()
                }),
            true
        )
    }

    #[test]
    fn unordered_is_china() {
        assert_eq!(
            Geoip::new(Resp, vec!["CN".to_string()].into_iter().collect())
                .unwrap()
                .matches(&State {
                    resp: {
                        let mut m = Message::new();
                        m.insert_answers(
                            [
                                Record::from_rdata(
                                    Name::from_str("baidu.com").unwrap(),
                                    10,
                                    RData::CNAME(Name::from_str("baidu.com").unwrap()),
                                ),
                                Record::from_rdata(
                                    Name::from_str("baidu.com").unwrap(),
                                    10,
                                    RData::A("36.152.44.95".parse().unwrap()),
                                ),
                                Record::from_rdata(
                                    Name::from_str("baidu.com").unwrap(),
                                    10,
                                    RData::NS(Name::from_str("baidu.com").unwrap()),
                                ),
                            ]
                            .to_vec(),
                        );
                        m
                    },
                    ..Default::default()
                }),
            true
        )
    }
}
