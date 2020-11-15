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

use self::parser::Parsed;
use self::worker::worker;
use anyhow::Result;
use dmatcher::{domain::Domain, Label};
use droute::{error::DrouteError, router::Router};
use log::*;
use simple_logger::SimpleLogger;
use std::net::SocketAddr;
use std::result::Result as StdResult;
use std::sync::Arc;
use tokio::fs::File;
use tokio::net::UdpSocket;
use tokio::prelude::*;
use tokio_compat_02::FutureExt;

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
    use clap::{load_yaml, App};

    let yaml = load_yaml!("args.yaml");
    let m = App::from(yaml).get_matches();

    let (router, addr, verbosity) = match m.value_of("config") {
        Some(c) => {
            let mut file = File::open(c).await?;
            let mut config = String::new();
            file.read_to_string(&mut config).await?;
            init(serde_json::from_str(&config)?).compat().await?
        }
        None => {
            init(serde_json::from_str(include_str!(
                "../../configs/default.json"
            ))?)
            .compat()
            .await?
        }
    };

    SimpleLogger::new().with_level(verbosity).init()?;

    info!("Dcompass ready!");

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
}
