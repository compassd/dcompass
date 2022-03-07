// Copyright 2020, 2021 LEXUGE
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

// #[cfg(all(any(target_env = "gnu", target_env = ""), not(target_os = "windows")))]
// use tikv_jemallocator::Jemalloc;
//
// #[cfg(all(any(target_env = "gnu", target_env = ""), not(target_os = "windows")))]
// #[global_allocator]
// static GLOBAL: Jemalloc = Jemalloc;

mod parser;
#[cfg(test)]
mod tests;
mod worker;

use self::{parser::Parsed, worker::worker};
use anyhow::{Context, Result};
use bytes::BytesMut;
use droute::{
    builders::{RouterBuilder, UpstreamsBuilder},
    error::DrouteError,
    AsyncTryInto, Router,
};
#[cfg(target_pointer_width = "64")]
use governor::{Quota, RateLimiter};
use log::*;
use simple_logger::SimpleLogger;
use std::{
    net::SocketAddr, num::NonZeroU32, path::PathBuf, result::Result as StdResult, sync::Arc,
    time::Duration,
};
use structopt::StructOpt;
use tokio::{
    fs::File,
    io::AsyncReadExt,
    net::UdpSocket,
    signal,
    sync::broadcast::{self, Sender},
    time::sleep,
};

#[derive(Debug, StructOpt)]
#[structopt(
    name = "dcompass",
    about = "High-performance DNS server with freestyle routing scheme support and DoT/DoH functionalities built-in."
)]
struct DcompassOpts {
    /// Path to the configuration file. Use built-in if not provided.
    #[structopt(short, long, parse(from_os_str))]
    config: Option<PathBuf>,

    /// Set this flag to validate the configuration file only.
    #[structopt(short, long, parse(from_flag))]
    validate: bool,
}

async fn init(p: Parsed) -> StdResult<(Router, SocketAddr, LevelFilter, NonZeroU32), DrouteError> {
    Ok((
        RouterBuilder::new(
            p.table,
            UpstreamsBuilder::from_map(p.upstreams, p.cache_size),
        )
        .async_try_into()
        .await?,
        p.address,
        p.verbosity,
        p.ratelimit,
    ))
}

async fn serve(
    socket: Arc<UdpSocket>,
    router: Arc<Router>,
    _ratelimit: NonZeroU32,
    tx: &Sender<()>,
) {
    #[cfg(target_pointer_width = "64")]
    let ratelimit = RateLimiter::direct(Quota::per_second(_ratelimit));
    loop {
        // Size recommended by DNS Flag Day 2020: "This is practical for the server operators that know their environment, and the defaults in the DNS software should reflect the minimum safe size which is 1232."
        let mut buf = BytesMut::with_capacity(1024);
        buf.resize(1024, 0);
        // On windows, some applications may go away after they got their first response, resulting in a broken pipe, we should discard errors on receiving/sending messages.
        let (len, src) = match socket.recv_from(&mut buf).await {
            Ok(r) => r,
            Err(e) => {
                warn!("failed to receive query: {}", e);
                continue;
            }
        };
        buf.resize(len, 0);

        let router = router.clone();
        let socket = socket.clone();
        let mut shutdown = tx.subscribe();
        #[rustfmt::skip]
        tokio::spawn(async move {
            tokio::select! {
                biased; res = worker(router, socket, buf.freeze(), src) => {
                    match res {
                        Ok(_) => (),
                        Err(e) => warn!("handling query failed: {}", e),
                    }
                }
                _ = shutdown.recv() => {
                    // If a shutdown signal is received, return from the spawned task.
                    // This will result in the task terminating.
                    log::warn!("worker shut down");
                }
            }
        });

        #[cfg(target_pointer_width = "64")]
        ratelimit.until_ready().await;
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: DcompassOpts = DcompassOpts::from_args();

    // If the config path is manually specified with `-c` flag, we use it and any error should fail early.
    // If there is no specified config but there is `config.yaml` under the path where user is invoking `dcompass` (not the absolute path of the binary), then we shall try that config. If the file exists but we failed to read, this should fail. Otherwise, we shall use the default anyway.
    let config = if let Some(config_path) = args.config {
        let display_path = config_path.as_path().display();
        let mut file = File::open(config_path.clone())
            .await
            .with_context(|| format!("Failed to open the file specified: {}", display_path))?;
        let mut config = String::new();
        file.read_to_string(&mut config)
            .await
            .with_context(|| format!("Failed to read from the file specified: {}", display_path))?;
        println!("Using the config file specified: {}", display_path);
        config
    } else {
        let mut config_path = std::env::current_dir()?;
        config_path.push("config.yaml");
        let display_path = config_path.as_path().display();
        match File::open(config_path.clone()).await {
            // We have found the config and successfully opened it.
            Ok(mut file) => {
                let mut config = String::new();
                file.read_to_string(&mut config).await.with_context(|| {
                    format!("Failed to read from the file found: {}", display_path)
                })?;
                println!("Using the config under current path: {}", display_path);
                config
            }
            // No config found, using built-in.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                println!("No config found or specified, using built-in config.");
                include_str!("../../configs/default.json").to_owned()
            }
            // Found but unable to open. We shall exit as this is intended.
            Err(e) => {
                return Err(e).with_context(|| {
                    format!("`config.yaml` found, but failed to open: {}", display_path)
                })
            }
        }
    };

    // Create whatever we need for get dcompass up and running.
    let (router, addr, verbosity, ratelimit) = init(
        serde_yaml::from_str(&config)
            .with_context(|| "Failed to parse the configuration file".to_string())?,
    )
    .await?;

    // If we are only required to validate the config, we shall be safe to exit now.
    if args.validate {
        println!("The configuration provided is valid.");
        return Ok(());
    }

    // Start logging
    SimpleLogger::new()
        // These modules are quite chatty, we want to disable it.
        .with_level(verbosity)
        .init()?;

    info!("dcompass ready!");

    let router = Arc::new(router);
    // Bind an UDP socket
    let socket = Arc::new(
        UdpSocket::bind(addr)
            .await
            .with_context(|| format!("failed to bind to {}", addr))?,
    );

    // Create a shutdown broadcast channel
    let (tx, _) = broadcast::channel::<()>(10);

    // We don't have to worry about incoming requests when shutting down, because when we initiate shutdown, the loop was already terminated
    #[rustfmt::skip]
    tokio::select! {
        _ = serve(socket, router, ratelimit, &tx) => (),
        _ = signal::ctrl_c() => {
            log::warn!("Ctrl-C received, shutting down");
	    sleep(Duration::from_millis(500)).await;
            // Error implies that there is no receiver/active worker, we are done
            if tx.send(()).is_ok() {
                while tx.receiver_count() != 0 {
                    log::warn!("waiting 5 seconds for workers to exit...");
                    sleep(Duration::from_secs(5)).await
                }
            }
            log::warn!("gracefully shut down!");
        }
    };
    Ok(())
}
