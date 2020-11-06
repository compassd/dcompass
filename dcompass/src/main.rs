mod worker;

use crate::worker::worker;
use anyhow::Result;
use droute::router::Router;
use log::*;
use simple_logger::SimpleLogger;
use std::sync::Arc;
use tokio::fs::File;
use tokio::net::UdpSocket;
use tokio::prelude::*;
use tokio_compat_02::FutureExt;

#[tokio::main]
async fn main() -> Result<()> {
    use clap::{load_yaml, App};

    let yaml = load_yaml!("args.yaml");
    let m = App::from(yaml).get_matches();

    let router = match m.value_of("config") {
        Some(c) => {
            let mut file = File::open(c).await?;
            let mut config = String::new();
            file.read_to_string(&mut config).await?;
            Router::new(&config).compat().await?
        }
        None => {
            Router::new(include_str!("../../configs/default.json"))
                .compat()
                .await?
        }
    };

    let (addr, verbosity) = (router.addr(), router.verbosity());

    SimpleLogger::new().with_level(verbosity).init()?;

    let router = Arc::new(router);
    // Bind an UDP socket
    let socket = Arc::new(UdpSocket::bind(addr).await?);

    loop {
        let mut buf = [0; 512];
        let (_, src) = socket.recv_from(&mut buf).await?;

        let router = router.clone();
        let socket = socket.clone();
        tokio::spawn(async move {
            match worker(router, socket, &buf, src).await {
                Ok(_) => (),
                Err(e) => warn!("Handling query failed: {}", e),
            }
        });
    }
}
