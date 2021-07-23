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
use cidr_utils::{
    cidr::{IpCidr as Cidr, IpCidrError},
    utils::IpCidrCombiner as CidrCombiner,
};
use serde::Deserialize;
use std::net::IpAddr;
use trust_dns_proto::rr::record_data::RData::{A, AAAA};

/// A matcher that matches the IP on dst.
pub struct IpCidr {
    matcher: CidrCombiner,
}

impl IpCidr {
    /// Create a new `IpCidr` matcher from a list of files where each IP CIDR is seperated from one another by `\n`.
    pub async fn new(path: Vec<String>) -> Result<Self> {
        Ok({
            let mut matcher = CidrCombiner::new();
            for r in path {
                let (mut file, _) = niffler::from_path(r)?;
                let mut data = String::new();
                file.read_to_string(&mut data)?;
                // This gets rid of empty substrings for stability reasons. See also https://github.com/LEXUGE/dcompass/issues/33.
                data.split('\n').filter(|&x| !x.is_empty()).try_for_each(
                    |x| -> std::result::Result<(), IpCidrError> {
                        matcher.push(Cidr::from_str(x)?);
                        Ok(())
                    },
                )?;
            }
            Self { matcher }
        })
    }
}

impl Matcher for IpCidr {
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
            self.matcher.contains(ip)
        } else {
            false
        }
    }
}

/// A builder for IpCidr matcher plugin
#[derive(Deserialize, Clone)]
pub struct IpCidrBuilder(Vec<String>);

impl Default for IpCidrBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl IpCidrBuilder {
    /// Create an empty builder
    pub fn new() -> Self {
        IpCidrBuilder(Vec::new())
    }

    /// Add a file of IP CIDR addresses to the matcher builder
    pub fn add_file(mut self, s: impl ToString) -> Self {
        self.0.push(s.to_string());
        self
    }
}

#[async_trait]
impl AsyncTryInto<IpCidr> for IpCidrBuilder {
    type Error = MatchError;

    async fn try_into(self) -> Result<IpCidr> {
        IpCidr::new(self.0).await
    }
}

#[cfg(test)]
mod tests {
    use crate::AsyncTryInto;

    use super::{
        super::{Matcher, State},
        IpCidrBuilder,
    };
    use once_cell::sync::Lazy;
    use std::str::FromStr;
    use trust_dns_proto::{
        op::Message,
        rr::{resource::Record, Name, RData},
    };

    static RECORD_NOT_CHINA: Lazy<Record> = Lazy::new(|| {
        Record::from_rdata(
            Name::from_str("cloudflare-dns.com").unwrap(),
            10,
            RData::A("1.1.1.1".parse().unwrap()),
        )
    });
    static RECORD_CHINA: Lazy<Record> = Lazy::new(|| {
        Record::from_rdata(
            Name::from_str("baidu.com").unwrap(),
            10,
            RData::A("180.101.49.12".parse().unwrap()),
        )
    });

    fn create_state(v: Vec<Record>) -> State {
        State {
            resp: {
                let mut m = Message::new();
                m.insert_answers(v);
                m
            },
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn newline_terminator_test() {
        // https://github.com/LEXUGE/dcompass/issues/33
        IpCidrBuilder::new()
            .add_file("../data/ipcidr-test.txt")
            .try_into()
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test() {
        let matcher = IpCidrBuilder::new()
            .add_file("../data/ipcn.txt")
            .try_into()
            .await
            .unwrap();
        assert_eq!(
            matcher.matches(&create_state(vec![(*RECORD_CHINA).clone()])),
            true
        );
        assert_eq!(
            matcher.matches(&create_state(vec![(*RECORD_NOT_CHINA).clone()])),
            false
        )
    }
}
