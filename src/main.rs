mod filter;
mod parser;
mod upstream;

use crate::filter::Filter;
use anyhow::Result;
use log::*;
use simple_logger::SimpleLogger;
use std::{net::SocketAddr, sync::Arc};
use tokio::fs::File;
use tokio::prelude::*;
use tokio::{
    net::UdpSocket,
    sync::{mpsc, mpsc::Sender},
};
use trust_dns_proto::op::response_code::ResponseCode;
use trust_dns_proto::op::Message;

/// Handle a single incoming packet
async fn handle_query(
    src: SocketAddr,
    buf: [u8; 512],
    filter: Arc<Filter>,
    mut tx: Sender<(Vec<u8>, SocketAddr)>,
) -> Result<()> {
    let request = Message::from_vec(&buf)?;

    for q in request.queries() {
        info!("Received query: {:?}", q);

        match filter.resolve(q.name().to_utf8(), q.query_type()).await {
            Err(e) => {
                tx.send((
                    Message::error_msg(request.id(), request.op_code(), ResponseCode::NXDomain)
                        .to_vec()?,
                    src,
                ))
                .await?;
                // Give back the error
                return Err(e);
            }
            Ok(r) => {
                tx.send((request.clone().add_answers(r).to_vec()?, src))
                    .await?;
                info!("Response completed");
            }
        };
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    use clap::{load_yaml, App};
    type ChannelPair = (
        Sender<(Vec<u8>, SocketAddr)>,
        tokio::sync::mpsc::Receiver<(Vec<u8>, SocketAddr)>,
    );

    SimpleLogger::new().with_level(LevelFilter::Info).init()?;

    let yaml = load_yaml!("args.yaml");
    let m = App::from(yaml).get_matches();

    let (filter, addr) = match m.value_of("config") {
        Some(c) => {
            let mut file = File::open(c).await?;
            let mut config = String::new();
            file.read_to_string(&mut config).await?;
            Filter::from_json(&config).await?
        }
        None => Filter::from_json(include_str!("./config.json")).await?,
    };

    let filter = Arc::new(filter);
    // Bind an UDP socket
    let (mut server_rx, mut server_tx) = UdpSocket::bind(addr).await?.split();
    // Create channel
    let (tx, mut rx): ChannelPair = mpsc::channel(32);

    // Response loop
    tokio::spawn(async move {
        loop {
            if let Some((msg, src)) = rx.recv().await {
                match server_tx.send_to(&msg.to_vec(), &src).await {
                    Err(e) => error!("Sending response back failed: {}", e),
                    Ok(_) => info!("Sent response back successfully to {}", src),
                }
            }
        }
    });

    // Enter an event loop
    loop {
        let mut buf = [0; 512];
        let (_, src) = server_rx.recv_from(&mut buf).await?;

        let tx = tx.clone();
        let filter = filter.clone();
        tokio::spawn(async move {
            match handle_query(src, buf, filter, tx).await {
                Ok(_) => (),
                Err(e) => warn!("Handling query failed: {}", e),
            }
        });
    }
}
