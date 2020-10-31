use dmatcher::Dmatcher;
use log::*;
use simple_logger::SimpleLogger;

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, mpsc::Sender};
use trust_dns_proto::op::Message;
use trust_dns_proto::rr::{Record, RecordType};
use trust_dns_proto::xfer::dns_request::DnsRequestOptions;
use trust_dns_resolver::config::*;
use trust_dns_resolver::error::ResolveResult;

use trust_dns_resolver::TokioAsyncResolver;

async fn resolve(
    dns_name: String,
    qtype: RecordType,
    resolver: &TokioAsyncResolver,
) -> ResolveResult<Vec<Record>> {
    Ok(resolver
        .lookup(
            dns_name,
            qtype,
            DnsRequestOptions {
                expects_multiple_responses: false,
            },
        )
        .await?
        .record_iter()
        .cloned()
        .collect())
}

/// Handle a single incoming packet
async fn handle_query(
    src: SocketAddr,
    buf: [u8; 512],
    resolvers: Arc<Vec<TokioAsyncResolver>>,
    matcher: Arc<Dmatcher<'_>>,
    mut tx: Sender<(Vec<u8>, SocketAddr)>,
) -> ResolveResult<()> {
    let request = Message::from_vec(&buf)?;

    for q in request.queries() {
        info!("Received query: {:?}", q);
        let mut response = request.clone();
        if matcher.matches(&q.name().to_utf8()) {
            info!("Route via 1");
            response.add_answers(resolve(q.name().to_utf8(), q.query_type(), &resolvers[1]).await?);
        } else {
            info!("Route via 0");
            response.add_answers(resolve(q.name().to_utf8(), q.query_type(), &resolvers[0]).await?);
        }
        tx.send((response.to_vec()?, src)).await.unwrap();
        info!("Response completed");
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Bind an UDP socket on port 2053
    let (mut server_rx, mut server_tx) = UdpSocket::bind(("0.0.0.0", 2053)).await?.split();
    let (tx, mut rx): (
        Sender<(Vec<u8>, SocketAddr)>,
        tokio::sync::mpsc::Receiver<(Vec<u8>, SocketAddr)>,
    ) = mpsc::channel(32);

    SimpleLogger::new()
        .with_level(LevelFilter::Info)
        .init()
        .unwrap();

    let mut matcher = Dmatcher::new();
    matcher.insert_lines(include_str!("accelerated-domains.china.raw.txt"));
    let matcher = Arc::new(matcher);

    // Response loop
    tokio::spawn(async move {
        loop {
            info!("loop!");
            if let Some((msg, src)) = rx.recv().await {
                server_tx.send_to(&msg.to_vec(), &src).await.unwrap();
                info!("Send successfully");
            }
        }
    });

    let mut opts = ResolverOpts::default();
    opts.cache_size = 4096;

    let cloudflare = TokioAsyncResolver::tokio(ResolverConfig::cloudflare_tls(), opts)
        .await
        .unwrap();
    let dns114 = TokioAsyncResolver::tokio(
        ResolverConfig::from_parts(
            None,
            vec![],
            NameServerConfigGroup::from_ips_clear(&["114.114.114.114".parse().unwrap()], 53),
        ),
        opts,
    )
    .await
    .unwrap();

    let resolvers = Arc::new(vec![cloudflare, dns114]);

    // Enter an event loop
    loop {
        info!("another round!");
        let mut buf = [0; 512];
        let (_, src) = server_rx.recv_from(&mut buf).await.unwrap();

        let matcher = matcher.clone();
        let tx = tx.clone();
        tokio::spawn(handle_query(src, buf, resolvers.clone(), matcher, tx));
    }
}
