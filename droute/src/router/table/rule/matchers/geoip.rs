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
use std::net::IpAddr;
use trust_dns_proto::rr::record_data::RData::{A, AAAA};

/// A matcher that matches if IP address in the record of the first A/AAAA response is in the list of countries.
pub struct Geoip {
    db: Reader<Vec<u8>>,
    list: HashSet<String>,
}

impl Geoip {
    /// Create a new `Geoip` matcher from a set of ISO country codes like `CN`, `AU`.
    pub fn new(list: HashSet<String>) -> Result<Self> {
        Ok(Self {
            list,
            db: Reader::from_source(
                include_bytes!("../../../../../../data/Country.mmdb").to_vec(),
            )?,
        })
    }
}

impl Matcher for Geoip {
    fn matches(&self, state: &State) -> bool {
        if let Some(record) = state
            .resp
            .answers()
            .iter()
            .find(|&record| matches!(record.rdata(), A(_) | AAAA(_)))
        {
            let r = if let Ok(r) = self.db.lookup::<Country>(match *record.rdata() {
                A(addr) => IpAddr::V4(addr),
                AAAA(addr) => IpAddr::V6(addr),
                _ => return false,
            }) {
                r
            } else {
                return false;
            };

            r.country
                .and_then(|c| {
                    c.iso_code.map(|n| {
                        info!(
                            "The record `{:?}` has ISO country code `{}`",
                            record.rdata(),
                            n
                        );
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
    use super::{super::Matcher, Geoip, State};
    use std::str::FromStr;
    use trust_dns_client::rr::RData;
    use trust_dns_proto::{
        op::Message,
        rr::{resource::Record, Name},
    };

    #[test]
    fn not_china() {
        assert_eq!(
            Geoip::new(vec!["CN".to_string()].into_iter().collect())
                .unwrap()
                .matches(&State {
                    query: Message::new(),
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
                }),
            false
        )
    }

    #[test]
    fn mixed() {
        let geoip = Geoip::new(
            vec!["CN".to_string(), "AU".to_string()]
                .into_iter()
                .collect(),
        )
        .unwrap();
        assert_eq!(
            geoip.matches(&State {
                query: Message::new(),
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
            }),
            true
        );
        assert_eq!(
            geoip.matches(&State {
                query: Message::new(),
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
            }),
            true
        )
    }

    #[test]
    fn empty_records() {
        assert_eq!(
            Geoip::new(vec!["CN".to_string()].into_iter().collect())
                .unwrap()
                .matches(&State {
                    query: Message::new(),
                    resp: Message::new()
                }),
            false,
        )
    }

    #[test]
    fn is_china() {
        assert_eq!(
            Geoip::new(vec!["CN".to_string()].into_iter().collect())
                .unwrap()
                .matches(&State {
                    query: Message::new(),
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
                }),
            true
        )
    }

    #[test]
    fn unordered_is_china() {
        assert_eq!(
            Geoip::new(vec!["CN".to_string()].into_iter().collect())
                .unwrap()
                .matches(&State {
                    query: Message::new(),
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
                }),
            true
        )
    }
}
