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

use super::{super::super::State, IpTarget, Matcher, Result};
use cidr_utils::{
    cidr::{IpCidr as Cidr, IpCidrError},
    utils::IpCidrCombiner as CidrCombiner,
};
use std::net::IpAddr;
use tokio::{fs::File, io::AsyncReadExt};
use trust_dns_proto::rr::record_data::RData::{A, AAAA};

/// A matcher that matches the IP on src or dst as specified.
pub struct IpCidr {
    matcher: CidrCombiner,
    on: IpTarget,
}

impl IpCidr {
    /// Create a new `IpCidr` matcher from a list of files where each IP CIDR is seperated from one another by `\n`.
    pub async fn new(on: IpTarget, p: Vec<String>) -> Result<Self> {
        Ok({
            let mut matcher = CidrCombiner::new();
            for r in p {
                let mut file = File::open(r).await?;
                let mut data = String::new();
                file.read_to_string(&mut data).await?;
                data.split('\n')
                    .try_for_each(|x| -> std::result::Result<(), IpCidrError> {
                        matcher.push(Cidr::from_str(x)?);
                        Ok(())
                    })?;
            }
            Self { matcher, on }
        })
    }
}

impl Matcher for IpCidr {
    fn matches(&self, state: &State) -> bool {
        if let Some(ip) = match self.on {
            IpTarget::Src => state.src.map(|i| i.ip()),
            IpTarget::Resp => state
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
            self.matcher.contains(ip)
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        super::{IpTarget::*, Matcher, State},
        IpCidr,
    };
    use once_cell::sync::Lazy;
    use std::str::FromStr;
    use trust_dns_proto::{
        op::Message,
        rr::{resource::Record, Name, RData},
    };

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
    async fn test() {
        let matcher = IpCidr::new(
            Resp,
            vec!["../data/ipcn.txt".to_string()].into_iter().collect(),
        )
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
