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

mod parser;
mod worker;

use self::{parser::Parsed, worker::worker};
use anyhow::{Context, Result};
use dmatcher::{domain::Domain, Label};
use droute::{error::DrouteError, router::Router};
use log::*;
use simple_logger::SimpleLogger;
use std::{net::SocketAddr, path::PathBuf, result::Result as StdResult, sync::Arc};
use structopt::StructOpt;
use tokio::{fs::File, net::UdpSocket, prelude::*};
use tokio_compat_02::FutureExt;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "dcompass",
    about = "High-performance DNS server with rule matching/DoT/DoH functionalities built-in."
)]
struct DcompassOpts {
    // Path to configuration file. Use built-in if not provided.
    #[structopt(short, long, parse(from_os_str))]
    config: Option<PathBuf>,
}

async fn init(
    p: Parsed<Label>,
) -> StdResult<(Router<Label, Domain<Label>>, SocketAddr, LevelFilter), DrouteError<Label>> {
    Ok((
        Router::new(
            p.upstreams,
            p.disable_ipv6,
            p.cache_size,
            p.default_tag,
            p.rules,
        )
        .await?,
        p.address,
        p.verbosity,
    ))
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: DcompassOpts = DcompassOpts::from_args();

    let config = if let Some(config_path) = args.config {
        let display_path = config_path.as_path().display();
        let mut file = File::open(config_path.clone())
            .await
            .with_context(|| format!("Failed to open the file: {}", display_path))?;
        let mut config = String::new();
        file.read_to_string(&mut config)
            .await
            .with_context(|| format!("Failed to read from the file: {}", display_path))?;
        config
    } else {
        include_str!("../../configs/default.json").to_owned()
    };
    let (router, addr, verbosity) = init(
        serde_json::from_str(&config)
            .with_context(|| "Failed to parse the configuration file".to_string())?,
    )
    .compat()
    .await?;

    SimpleLogger::new().with_level(verbosity).init()?;

    info!("Dcompass ready!");

    let router = Arc::new(router);
    // Bind an UDP socket
    let socket = Arc::new(
        UdpSocket::bind(addr)
            .await
            .with_context(|| format!("Failed to bind to {}", addr))?,
    );

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

#[cfg(test)]
mod tests {
    use super::init;
    use droute::error::DrouteError;
    use tokio_test::block_on;

    #[test]
    fn parse() {
        assert_eq!(
            block_on(init(
                serde_json::from_str(include_str!("../../configs/default.json")).unwrap()
            ))
            .is_ok(),
            true
        );
    }

    #[test]
    fn check_fail_rule() {
        // Notice that data dir is relative to cargo test path.
        assert_eq!(
            match block_on(init(
                serde_json::from_str(include_str!("../../configs/fail_rule.json")).unwrap()
            ))
            .err()
            .unwrap()
            {
                DrouteError::MissingTag(tag) => tag,
                e => panic!("Not the right error type: {}", e),
            },
            "undefined".into()
        );
    }

    #[test]
    fn check_success_rule() {
        assert_eq!(
            block_on(init(
                serde_json::from_str(include_str!("../../configs/success_rule.json")).unwrap()
            ))
            .is_ok(),
            true
        );
    }

    #[test]
    fn check_fail_default() {
        assert_eq!(
            match block_on(init(
                serde_json::from_str(include_str!("../../configs/fail_default.json")).unwrap()
            ))
            .err()
            .unwrap()
            {
                DrouteError::MissingTag(tag) => tag,
                e => panic!("Not the right error type: {}", e),
            },
            "undefined".into()
        );
    }

    #[test]
    fn check_fail_recursion() {
        match block_on(init(
            serde_json::from_str(include_str!("../../configs/fail_recursion.json")).unwrap(),
        ))
        .err()
        .unwrap()
        {
            DrouteError::HybridRecursion(_) => {}
            e => panic!("Not the right error type: {}", e),
        };
    }

    #[test]
    fn check_fail_multiple_def() {
        match block_on(init(
            serde_json::from_str(include_str!("../../configs/fail_multiple_def.json")).unwrap(),
        ))
        .err()
        .unwrap()
        {
            DrouteError::MultipleDef(_) => {}
            e => panic!("Not the right error type: {}", e),
        };
    }
}
