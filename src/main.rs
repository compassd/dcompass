use dmatcher::Dmatcher;
use log::*;
use simple_logger::SimpleLogger;
use std::net::UdpSocket;
use trust_dns_proto::op::Message;
use trust_dns_proto::rr::{Record, RecordType};
use trust_dns_resolver::config::*;
use trust_dns_resolver::error::ResolveResult;
use trust_dns_resolver::Resolver;

fn resolve(dns_name: &str, qtype: RecordType, resolver: &Resolver) -> ResolveResult<Vec<Record>> {
    Ok(resolver
        .lookup(dns_name, qtype)?
        .record_iter()
        .cloned()
        .collect())
}

/// Handle a single incoming packet
fn handle_query(
    socket: &UdpSocket,
    resolvers: Vec<&Resolver>,
    matcher: &Dmatcher,
) -> ResolveResult<()> {
    // let mut buf: Vec<u8> = Vec::new();
    let mut buf = [0; 512];
    let (_, src) = socket.recv_from(&mut buf).unwrap();

    let request = Message::from_vec(&buf)?;

    for q in request.queries() {
        info!("Received query: {:?}", q);
        let mut response = request.clone();
        if matcher.matches(&q.name().to_utf8()) {
            info!("Route via 1");
            response.add_answers(resolve(&q.name().to_utf8(), q.query_type(), resolvers[1])?);
        } else {
            info!("Route via 0");
            response.add_answers(resolve(&q.name().to_utf8(), q.query_type(), resolvers[0])?);
        }
        socket.send_to(&response.to_vec()?, src)?;
        info!("Response completed");
    }

    Ok(())
}

fn main() -> ResolveResult<()> {
    // Bind an UDP socket on port 2053
    let socket = UdpSocket::bind(("0.0.0.0", 2053))?;

    SimpleLogger::new().init().unwrap();

    let mut matcher = Dmatcher::new();
    matcher.insert_lines(include_str!("accelerated-domains.china.raw.txt"));

    // For now, queries are handled sequentially, so an infinite loop for servicing
    // requests is initiated.
    loop {
        let cloudflare =
            Resolver::new(ResolverConfig::cloudflare_tls(), ResolverOpts::default()).unwrap();
        let dns114 = Resolver::new(ResolverConfig::cloudflare(), ResolverOpts::default()).unwrap();

        match handle_query(&socket, vec![&cloudflare, &dns114], &matcher) {
            Ok(_) => {}
            Err(e) => error!("An error occured: {}", e),
        }
    }
}
