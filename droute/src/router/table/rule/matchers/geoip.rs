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

use super::{Matcher, Result};
use hashbrown::HashSet;
use maxminddb::{geoip2::Country, Reader};
use std::net::IpAddr;
use trust_dns_proto::{
    op::query::Query,
    rr::{
        record_data::RData::{A, AAAA},
        resource::Record,
    },
};

/// A matcher that matches if IP address in the record of the first response is in the list of countries.
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
    fn matches(&self, _: &[Query], records: &[Record]) -> bool {
        match *records[0].rdata() {
            A(addr) => {
                if let Some(name) = if let Some(c) =
                    if let Ok(r) = self.db.lookup::<Country>(IpAddr::V4(addr)) {
                        r
                    } else {
                        return false;
                    }
                    .country
                {
                    c
                } else {
                    return false;
                }
                .iso_code
                {
                    self.list.contains(name)
                } else {
                    false
                }
            }
            AAAA(addr) => {
                if let Some(name) = if let Some(c) =
                    if let Ok(r) = self.db.lookup::<Country>(IpAddr::V6(addr)) {
                        r
                    } else {
                        return false;
                    }
                    .country
                {
                    c
                } else {
                    return false;
                }
                .iso_code
                {
                    self.list.contains(name)
                } else {
                    false
                }
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{super::Matcher, Geoip};
    use std::str::FromStr;
    use trust_dns_client::rr::RData;
    use trust_dns_proto::rr::{resource::Record, Name};

    #[test]
    fn not_china() {
        assert_eq!(
            Geoip::new(vec!["CN".to_string()].into_iter().collect())
                .unwrap()
                .matches(
                    &[],
                    &[Record::from_rdata(
                        Name::from_str("apple.com").unwrap(),
                        10,
                        RData::A("1.1.1.1".parse().unwrap()),
                    )],
                ),
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
            geoip.matches(
                &[],
                &[Record::from_rdata(
                    Name::from_str("apple.com").unwrap(),
                    10,
                    RData::A("1.1.1.1".parse().unwrap()),
                )],
            ),
            true
        );
        assert_eq!(
            geoip.matches(
                &[],
                &[Record::from_rdata(
                    Name::from_str("baidu.com").unwrap(),
                    10,
                    RData::A("36.152.44.95".parse().unwrap()),
                )],
            ),
            true
        )
    }

    #[test]
    fn is_china() {
        assert_eq!(
            Geoip::new(vec!["CN".to_string()].into_iter().collect())
                .unwrap()
                .matches(
                    &[],
                    &[Record::from_rdata(
                        Name::from_str("baidu.com").unwrap(),
                        10,
                        RData::A("36.152.44.95".parse().unwrap()),
                    )],
                ),
            true
        )
    }
}
