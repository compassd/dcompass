mod filter;
mod parser;
mod upstream;

use crate::filter::Filter;
use log::*;
use simple_logger::SimpleLogger;
use std::{net::SocketAddr, sync::Arc};
use tokio::{
    net::UdpSocket,
    sync::{mpsc, mpsc::Sender},
};
use trust_dns_proto::op::Message;
use trust_dns_resolver::error::ResolveResult;

/// Handle a single incoming packet
async fn handle_query(
    src: SocketAddr,
    buf: [u8; 512],
    filter: Arc<Filter>,
    mut tx: Sender<(Vec<u8>, SocketAddr)>,
) -> ResolveResult<()> {
    let request = Message::from_vec(&buf)?;

    for q in request.queries() {
        info!("Received query: {:?}", q);
        let mut response = request.clone();
        response.add_answers(filter.resolve(q.name().to_utf8(), q.query_type()).await?);
        info!("Get response: {:?}", response);
        tx.send((response.to_vec()?, src)).await.unwrap();
        info!("Response completed");
    }

    Ok(())
}

#[tokio::main(core_threads = 10)]
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

    let filter = Arc::new(Filter::from_json(include_str!("./config.json")).await);

    // Response loop
    tokio::spawn(async move {
        loop {
            if let Some((msg, src)) = rx.recv().await {
                server_tx.send_to(&msg.to_vec(), &src).await.unwrap();
                info!("Send successfully");
            }
        }
    });

    // Enter an event loop
    loop {
        info!("another round!");
        let mut buf = [0; 512];
        let (_, src) = server_rx.recv_from(&mut buf).await.unwrap();

        let tx = tx.clone();
        tokio::spawn(handle_query(src, buf, filter.clone(), tx));
    }
}
