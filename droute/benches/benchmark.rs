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

use criterion::{criterion_group, criterion_main, Criterion};
use droute::{actions::CacheMode, builders::*, mock::Server, Router};
use once_cell::sync::Lazy;
use tokio::net::UdpSocket;
use trust_dns_client::op::Message;
use trust_dns_proto::{
    op::{header::MessageType, query::Query},
    rr::{record_data::RData, record_type::RecordType, resource::Record, Name},
};

static DUMMY_MSG: Lazy<Message> = Lazy::new(|| {
    let mut msg = Message::new();
    msg.add_answer(Record::from_rdata(
        Name::from_utf8("www.apple.com").unwrap(),
        32,
        RData::A("1.1.1.1".parse().unwrap()),
    ));
    msg.set_message_type(MessageType::Response);
    msg
});
static QUERY: Lazy<Message> = Lazy::new(|| {
    let mut msg = Message::new();
    msg.add_query(Query::query(
        Name::from_utf8("www.apple.com").unwrap(),
        RecordType::A,
    ));
    msg
});

async fn create_router(c: usize) -> Router {
    RouterBuilder::new(
        TableBuilder::new(
            vec![(
                "start",
                RuleBuilder::new(
                    BuiltinMatcherBuilder::Any,
                    BranchBuilder::new(
                        vec![BuiltinActionBuilder::Query(
                            "mock".into(),
                            CacheMode::default(),
                        )],
                        "end",
                    ),
                    BranchBuilder::default(),
                ),
            )]
            .into_iter()
            .collect(),
        ),
        UpstreamsBuilder::new(
            vec![(
                "mock",
                UpstreamBuilder::Udp {
                    addr: "127.0.0.1:53533".parse().unwrap(),
                    dnssec: false,
                    cache_size: c,
                    timeout: 1,
                },
            )]
            .into_iter()
            .collect(),
        ),
    )
    .build()
    .await
    .unwrap()
}

fn bench_resolve(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let socket = rt.block_on(UdpSocket::bind(&"127.0.0.1:53533")).unwrap();
    let server = Server::new(socket, vec![0; 1024], None);
    rt.spawn(server.run(DUMMY_MSG.clone()));

    let router = rt.block_on(create_router(0));
    let cached_router = rt.block_on(create_router(4096));

    c.bench_function("non_cache_resolve", |b| {
        b.to_async(&rt).iter(|| async {
            assert_eq!(
                router.resolve(QUERY.clone()).await.unwrap().answers(),
                DUMMY_MSG.answers()
            );
        })
    });

    c.bench_function("cached_resolve", |b| {
        b.to_async(&rt).iter(|| async {
            assert_eq!(
                cached_router
                    .resolve(QUERY.clone())
                    .await
                    .unwrap()
                    .answers(),
                DUMMY_MSG.answers()
            );
        })
    });
}

criterion_group!(benches, bench_resolve);
criterion_main!(benches);
