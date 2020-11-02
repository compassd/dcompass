mod filter;
mod parser;
mod worker;

use crate::filter::Filter;
use crate::worker::worker;
use anyhow::Result;
use futures::future::join_all;
use log::*;
use simple_logger::SimpleLogger;
use std::sync::Arc;
use tokio::fs::File;
use tokio::net::UdpSocket;
use tokio::prelude::*;

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

                match worker(filter, socket, i).await {
                    Ok(_) => (),
                    Err(e) => warn!("Handling query failed: {}", e),
                }
            }
        }));
    }

    join_all(handles).await;

    Ok(())
}
