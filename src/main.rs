mod filter;
mod parser;
mod upstream;

use crate::filter::Filter;
use anyhow::Result;
use futures::future::join_all;
use log::*;
use simple_logger::SimpleLogger;
use std::sync::Arc;
use tokio::fs::File;
use tokio::net::UdpSocket;
use tokio::prelude::*;
use trust_dns_proto::op::response_code::ResponseCode;
use trust_dns_proto::op::Message;

/// Handle a single incoming packet
async fn worker(filter: Arc<Filter>, socket: Arc<UdpSocket>) -> Result<()> {
    let mut buf = [0; 512];
    let (_, src) = socket.recv_from(&mut buf).await?;

    let request = Message::from_vec(&buf)?;

    for q in request.queries() {
        info!("Received query: {:?}", q);

        match filter.resolve(q.name().to_utf8(), q.query_type()).await {
            Err(e) => {
                socket
                    .send_to(
                        &Message::error_msg(
                            request.id(),
                            request.op_code(),
                            ResponseCode::NXDomain,
                        )
                        .to_vec()?,
                        src,
                    )
                    .await?;
                // Give back the error
                return Err(e);
            }
            Ok(r) => {
                socket
                    .send_to(&request.clone().add_answers(r).to_vec()?, src)
                    .await?;
                info!("Response completed. Sent back to {} successfully.", src);
            }
        };
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    use clap::{load_yaml, App};

    let yaml = load_yaml!("args.yaml");
    let m = App::from(yaml).get_matches();

    SimpleLogger::new()
        .with_level(match m.occurrences_of("verbose") {
            0 => LevelFilter::Warn,
            1 => LevelFilter::Info,
            2 => LevelFilter::Debug,
            _ => LevelFilter::Trace,
        })
        .init()?;

    let (filter, addr, num) = match m.value_of("config") {
        Some(c) => {
            let mut file = File::open(c).await?;
            let mut config = String::new();
            file.read_to_string(&mut config).await?;
            Filter::from_json(&config).await?
        }
        None => {
            warn!("No config file provided, using built-in config.");
            Filter::from_json(include_str!("./config.json")).await?
        }
    };

    let filter = Arc::new(filter);
    // Bind an UDP socket
    let socket = Arc::new(UdpSocket::bind(addr).await?);

    let mut handles = vec![];

    for i in 1..=num {
        let socket = socket.clone();
        let filter = filter.clone();

        handles.push(tokio::spawn(async move {
            loop {
                let socket = socket.clone();
                let filter = filter.clone();

                match worker(filter, socket).await {
                    Ok(_) => (),
                    Err(e) => warn!("Handling query failed: {}", e),
                }
            }
        }));
        info!("Worker {} started.", i);
    }

    join_all(handles).await;

    Ok(())
}
