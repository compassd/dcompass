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

use bytes::{Bytes, BytesMut};
use criterion::{criterion_group, criterion_main, Criterion};
use domain::{
    base::{Dname, Message, MessageBuilder, Rtype},
    rdata::A,
};
use droute::{actions::CacheMode, builders::*, mock::Server, AsyncTryInto, Router};
use once_cell::sync::Lazy;
use std::str::FromStr;
use tokio::net::UdpSocket;

// It is fine for us to have the same ID, because each query is sent from different source addr, meaning there is no collision on that
static DUMMY_MSG: Lazy<Message<BytesMut>> = Lazy::new(|| {
    let name = Dname::<Bytes>::from_str("cloudflare-dns.com").unwrap();
    let mut builder = MessageBuilder::from_target(BytesMut::with_capacity(1232)).unwrap();
    let header = builder.header_mut();
    header.set_id(0);
    header.set_qr(true);
    let mut builder = builder.question();
    builder.push((&name, Rtype::A)).unwrap();
    let mut builder = builder.answer();
    builder
        .push((&name, 10, A::from_octets(1, 1, 1, 1)))
        .unwrap();
    Message::from_octets(BytesMut::from(builder.as_slice())).unwrap()
});

static QUERY: Lazy<Message<Bytes>> = Lazy::new(|| {
    let name = Dname::<Bytes>::from_str("cloudflare-dns.com").unwrap();
    let mut builder = MessageBuilder::from_target(BytesMut::with_capacity(1232)).unwrap();
    builder.header_mut().set_id(0);
    let mut builder = builder.question();
    builder.push((&name, Rtype::A)).unwrap();
    builder.into_message()
});

async fn create_router(c: usize) -> Router {
    RouterBuilder::new(
        TableBuilder::new().add_rule(
            "start",
            RuleBuilders::<BuiltinMatcherBuilders, _>::SeqBlock(
                BranchBuilder::new("end").add_action(BuiltinActionBuilders::Query(
                    QueryBuilder::new(
                        "mock",
                        if c != 1 {
                            CacheMode::default()
                        } else {
                            CacheMode::Disabled
                        },
                    ),
                )),
            ),
        ),
        UpstreamsBuilder::new(c).unwrap().add_upstream(
            "mock",
            UpstreamBuilder::Udp(UdpBuilder {
                addr: "127.0.0.1:53533".parse().unwrap(),
                timeout: 1,
            }),
        ),
    )
    .try_into()
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

    let router = rt.block_on(create_router(1));
    let cached_router = rt.block_on(create_router(4096));

    c.bench_function("non_cache_resolve", |b| {
        b.to_async(&rt).iter(|| async {
            assert_eq!(
                router
                    .resolve(QUERY.clone(), None)
                    .await
                    .unwrap()
                    .into_octets(),
                DUMMY_MSG.clone().into_octets()
            );
        })
    });

    c.bench_function("cached_resolve", |b| {
        b.to_async(&rt).iter(|| async {
            assert_eq!(
                cached_router
                    .resolve(QUERY.clone(), None)
                    .await
                    .unwrap()
                    .into_octets(),
                DUMMY_MSG.clone().into_octets()
            );
        })
    });
}

criterion_group!(benches, bench_resolve);
criterion_main!(benches);
