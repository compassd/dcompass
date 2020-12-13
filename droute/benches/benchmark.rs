// TODO: Currently, criterion doesn't support async benchmark, which unables us to make actual connection.
// Tracking issue: https://github.com/bheisler/criterion.rs/issues/403
use criterion::{criterion_group, criterion_main, Criterion};
use droute::{
    actions::{Query as ActQuery, Skip},
    matchers::Any,
    Router, Rule, Table, Upstream,
    UpstreamKind::Udp,
    Upstreams,
};
use lazy_static::lazy_static;
use std::{net::SocketAddr, thread};
use tokio::net::UdpSocket;
use tokio_test::{assert_ok, block_on};
use trust_dns_client::op::Message;
use trust_dns_proto::{
    op::query::Query,
    rr::{record_type::RecordType, Name},
};

const BUILD: fn(usize) -> Router = |c| {
    Router::new(
        Table::new(vec![Rule::new(
            "start".into(),
            Box::new(Any::default()),
            (Box::new(ActQuery::new("mock".into())), "end".into()),
            (Box::new(Skip::default()), "end".into()),
        )])
        .unwrap(),
        block_on(Upstreams::new(
            vec![Upstream {
                timeout: 10,
                method: Udp("127.0.0.1:53533".parse().unwrap()),
                tag: "mock".into(),
            }],
            c,
        ))
        .unwrap(),
    )
    .unwrap()
};

lazy_static! {
    static ref DUMMY_MSG: Vec<u8> = Message::new().to_vec().unwrap();
    static ref QUERY: Message = {
        let mut msg = Message::new();
        msg.add_query(Query::query(
            Name::from_utf8("www.apple.com").unwrap(),
            RecordType::A,
        ));
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
                socket.send_to(&DUMMY_MSG, &peer).await?;
            }

            // If we're here then `to_send` is `None`, so we take a look for the
            // next message we're going to echo back.
            to_send = Some(socket.recv_from(&mut buf).await?.1);
        }
    }
}

fn bench_resolve(c: &mut Criterion) {
    let socket = block_on(UdpSocket::bind(&"127.0.0.1:53533")).unwrap();
    let server = Server {
        socket,
        buf: vec![0; 1024],
        to_send: None,
    };
    thread::spawn(|| block_on(server.run()));

    let router = BUILD(0);

    let cached_router = BUILD(4096);

    c.bench_function("non_cache_resolve", |b| {
        b.iter(|| assert_ok!(block_on(router.resolve(None, QUERY.clone()))))
    });

    c.bench_function("cached_resolve", |b| {
        b.iter(|| assert_ok!(block_on(cached_router.resolve(None, QUERY.clone()))))
    });
}

criterion_group!(benches, bench_resolve);
criterion_main!(benches);
