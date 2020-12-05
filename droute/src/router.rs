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

//! Router is the core concept of `droute`.

pub(crate) mod table;
pub mod upstreams;

use self::{
    table::{parsed::ParsedRule, Table},
    upstreams::{Upstream, Upstreams},
};
use crate::error::Result;
use log::warn;
use trust_dns_client::op::{Message, ResponseCode};

/// Router implementation.
pub struct Router {
    table: Table,
    upstreams: Upstreams,
}

impl Router {
    /// Create a new `Router` from configuration and check the validity. `data` is the content of the configuration file.
    pub async fn new(
        cache_size: usize,
        rules: Vec<ParsedRule>,
        upstreams: Vec<Upstream>,
    ) -> Result<Self> {
        let table = Table::new(rules).await?;
        let upstreams = Upstreams::new(upstreams, cache_size).await?;
        let router = Self { upstreams, table };
        router.check()?;
        Ok(router)
    }

    /// Validate the internal rules defined. This is automatically performed by `new` method.
    pub fn check(&self) -> Result<bool> {
        self.upstreams.check()?;
        for dst in self.table.used() {
            self.upstreams.exists(dst)?;
        }
        Ok(true)
    }

    /// Resolve the DNS query with routing rules defined.
    pub async fn resolve(&self, msg: Message) -> Result<Message> {
        let (id, op_code) = (msg.id(), msg.op_code());
        // We have to ensure the number of queries is larger than 0 as it is a gurantee for actions/matchers.
        // Not using `query_count()` because it is manually set, and may not be correct.
        if !msg.queries().is_empty() {
            Ok(match self.table.route(msg, &self.upstreams).await {
                Ok(m) => m,
                Err(e) => {
                    // Catch all server failure here and return server fail
                    warn!("Upstream encountered error: {}, returning SERVFAIL", e);
                    Message::error_msg(id, op_code, ResponseCode::ServFail)
                }
            })
        } else {
            warn!("DNS message contains zero querie(s), doing nothing.");
            Ok(Message::error_msg(id, op_code, ResponseCode::ServFail))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        table::parsed::{
            ParsedAction::{Query as ActQuery, Skip},
            ParsedMatcher, ParsedRule,
        },
        upstreams::{Upstream, UpstreamKind::Udp},
        Router,
    };
    use lazy_static::lazy_static;
    use std::net::SocketAddr;
    use tokio::net::UdpSocket;
    use trust_dns_client::op::Message;
    use trust_dns_proto::{
        op::{header::MessageType, query::Query},
        rr::{record_data::RData, record_type::RecordType, resource::Record, Name},
    };

    lazy_static! {
        static ref DUMMY_MSG: Message = {
            let mut msg = Message::new();
            msg.add_answer(Record::from_rdata(
                Name::from_utf8("www.apple.com").unwrap(),
                32,
                RData::A("1.1.1.1".parse().unwrap()),
            ));
            msg.set_message_type(MessageType::Response);
            msg
        };
        static ref QUERY: Message = {
            let mut msg = Message::new();
            msg.add_query(Query::query(
                Name::from_utf8("www.apple.com").unwrap(),
                RecordType::A,
            ));
            msg.set_message_type(MessageType::Query);
            msg
        };
    }

    struct Server {
        socket: UdpSocket,
        buf: Vec<u8>,
        to_send: Option<SocketAddr>,
    }

    impl Server {
        async fn run(self) -> Result<(), std::io::Error> {
            let Server {
                socket,
                mut buf,
                mut to_send,
            } = self;

            loop {
                // First we check to see if there's a message we need to echo back.
                // If so then we try to send it back to the original source, waiting
                // until it's writable and we're able to do so.
                if let Some(peer) = to_send {
                    // ID is required to match for trust-dns-client to accept response
                    let id = Message::from_vec(&buf).unwrap().id();
                    socket
                        .send_to(&DUMMY_MSG.clone().set_id(id).to_vec().unwrap(), &peer)
                        .await?;
                }

                // If we're here then `to_send` is `None`, so we take a look for the
                // next message we're going to echo back.
                to_send = Some(socket.recv_from(&mut buf).await?.1);
            }
        }
    }

    #[tokio::test]
    async fn test_resolve() {
        let socket = UdpSocket::bind(&"127.0.0.1:53533").await.unwrap();
        let server = Server {
            socket,
            buf: vec![0; 1024],
            to_send: None,
        };
        tokio::spawn(server.run());

        let router = Router::new(
            0,
            vec![ParsedRule {
                tag: "start".into(),
                matcher: ParsedMatcher::Any,
                on_match: (ActQuery("mock".into()), "end".into()),
                no_match: (Skip, "end".into()),
            }],
            vec![Upstream {
                timeout: 10,
                method: Udp("127.0.0.1:53533".parse().unwrap()),
                tag: "mock".into(),
            }],
        )
        .await
        .unwrap();

        assert_eq!(
            router.resolve(QUERY.clone()).await.unwrap().answers(),
            DUMMY_MSG.answers()
        );
    }
}
