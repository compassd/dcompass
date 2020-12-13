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

use anyhow::Result;
use droute::Router;
use log::*;
use std::{net::SocketAddr, sync::Arc};
use tokio::net::UdpSocket;
use trust_dns_proto::op::Message;

/// Handle a single incoming packet
pub async fn worker(
    router: Arc<Router>,
    socket: Arc<UdpSocket>,
    buf: &[u8],
    src: SocketAddr,
) -> Result<()> {
    let request = Message::from_vec(buf)?;

    info!("Received message: {:?}", request);
    socket
        .send_to(
            &router.resolve(Some(src.ip()), request).await?.to_vec()?,
            src,
        )
        .await
        .unwrap_or_else(|e| {
            warn!("Failed to send back response: {}", e);
            0
        });

    info!("Response completed. Sent back to {} successfully.", src);

    Ok(())
}
