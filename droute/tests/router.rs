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

use droute::{
    actions::Query as ActQuery,
    client_pool::{DefClientPool, Udp},
    matchers::Any,
    mock::Server,
    Router, Rule, Table, Upstream, UpstreamKind, Upstreams,
};
use lazy_static::lazy_static;
use std::time::Duration;
use tokio::net::UdpSocket;
use trust_dns_proto::{
    op::{header::MessageType, query::Query, Message, OpCode, ResponseCode},
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

#[tokio::test]
async fn test_resolve() {
    let socket = UdpSocket::bind(&"127.0.0.1:53533").await.unwrap();
    let server = Server::new(socket, vec![0; 1024], None);
    tokio::spawn(server.run(DUMMY_MSG.clone()));

    let router = Router::new(
        Table::new(vec![Rule::new(
            "start".into(),
            Box::new(Any::default()),
            (vec![Box::new(ActQuery::new("mock".into()))], "end".into()),
            (vec![], "end".into()),
        )])
        .unwrap(),
        Upstreams::new(vec![(
            "mock".into(),
            Upstream::new(
                UpstreamKind::Client {
                    pool: Box::new(DefClientPool::new(Udp::new(
                        "127.0.0.1:53533".parse().unwrap(),
                    ))),
                    timeout: Duration::from_secs(1),
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
