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
use cidr_utils::{
    cidr::{IpCidr as Cidr, IpCidrError},
    utils::IpCidrCombiner as CidrCombiner,
};
use serde::Deserialize;

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
        if let Ok(Some(ip)) = get_ip_addr(&state.resp) {
            self.matcher.contains(ip)
        } else {
            false
        }
    }
}

/// A builder for IpCidr matcher plugin
#[derive(Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(transparent)]
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
    use crate::{AsyncTryInto, MAX_LEN};

    use super::{
        super::{Matcher, State},
        IpCidrBuilder,
    };
    use bytes::{Bytes, BytesMut};
    use domain::{
        base::{Dname, Message, MessageBuilder},
        rdata::A,
    };
    use once_cell::sync::Lazy;
    use std::str::FromStr;

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
        let name = Dname::<Bytes>::from_str("cloudflare-dns.com").unwrap();
        let mut builder = MessageBuilder::from_target(BytesMut::with_capacity(MAX_LEN))
            .unwrap()
            .answer();
        builder
            .push((&name, 10, A::from_octets(180, 101, 49, 12)))
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
            matcher.matches(&create_state((*MESSAGE_CHINA).clone())),
            true
        );
        assert_eq!(
            matcher.matches(&create_state((*MESSAGE_NOT_CHINA).clone())),
            false
        )
    }
}
