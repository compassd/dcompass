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

pub mod table;
pub mod upstreams;

#[cfg(feature = "serde-cfg")]
use self::{table::parsed::ParsedRule, upstreams::parsed::ParsedUpstream};
use self::{table::Table, upstreams::Upstreams};
use crate::error::Result;
use log::warn;
use std::net::SocketAddr;
use trust_dns_client::op::{Message, ResponseCode};

/// Router implementation.
pub struct Router {
    table: Table,
    upstreams: Upstreams,
}

impl Router {
    /// Create a new `Router` from raw
    pub fn new(table: Table, upstreams: Upstreams) -> Result<Self> {
        let router = Self { table, upstreams };
        router.check()?;
        Ok(router)
    }

    /// Create a new `Router` from parsed configuration and check the validity. `data` is the content of the configuration file.
    #[cfg(feature = "serde-cfg")]
    pub async fn with_parsed(
        cache_size: usize,
        rules: Vec<ParsedRule>,
        upstreams: Vec<ParsedUpstream>,
    ) -> Result<Self> {
        let table = Table::with_parsed(rules).await?;
        let upstreams = Upstreams::with_parsed(upstreams, cache_size).await?;
        Self::new(table, upstreams)
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
    pub async fn resolve(&self, src: Option<SocketAddr>, msg: Message) -> Result<Message> {
        let (id, op_code) = (msg.id(), msg.op_code());
        // We have to ensure the number of queries is larger than 0 as it is a gurantee for actions/matchers.
        // Not using `query_count()` because it is manually set, and may not be correct.
        if !msg.queries().is_empty() {
            Ok(match self.table.route(src, msg, &self.upstreams).await {
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
        table::{
            rule::{
                actions::{Query as ActQuery, Skip},
                matchers::Any,
                Rule,
            },
            Table,
        },
        upstreams::{client_pool::Udp, Upstream, UpstreamKind, Upstreams},
        Router,
    };
    use lazy_static::lazy_static;
    use std::net::SocketAddr;
    use tokio::net::UdpSocket;
    use trust_dns_client::op::Message;
    use trust_dns_proto::{
        op::{header::MessageType, query::Query, OpCode, ResponseCode},
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
            Table::new(vec![Rule::new(
                "start".into(),
                Box::new(Any::default()),
                (Box::new(ActQuery::new("mock".into())), "end".into()),
                (Box::new(Skip::default()), "end".into()),
            )])
            .unwrap(),
            Upstreams::new(vec![(
                "mock".into(),
                Upstream::new(
                    UpstreamKind::Client {
                        pool: Box::new(
                            Udp::new(&"127.0.0.1:53533".parse().unwrap()).await.unwrap(),
                        ),
                        timeout: 1,
                    },
                    10,
                ),
            )])
            .unwrap(),
        )
        .unwrap();

        assert_eq!(
            router.resolve(None, QUERY.clone()).await.unwrap().answers(),
            DUMMY_MSG.answers()
        );

        // Shall not accept messages with no queries.
        assert_eq!(
            router.resolve(None, Message::new()).await.unwrap(),
            Message::error_msg(0, OpCode::Query, ResponseCode::ServFail)
        );
    }
}
