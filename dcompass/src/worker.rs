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
use droute::router::{matcher::Matcher, Router};
use log::*;
use std::{
    fmt::{Debug, Display},
    hash::Hash,
    net::SocketAddr,
    sync::Arc,
};
use tokio::net::UdpSocket;
use tokio_compat_02::FutureExt;
use trust_dns_proto::op::Message;

/// Handle a single incoming packet
pub async fn worker<L, M: Matcher<Label = L>>(
    router: Arc<Router<L, M>>,
    socket: Arc<UdpSocket>,
    buf: &[u8],
    src: SocketAddr,
) -> Result<()>
where
    L: 'static + Display + Debug + Eq + Hash + Send + Clone + Sync,
{
    let request = Message::from_vec(buf)?;

    info!("Received message: {:?}", request);
    socket
        .send_to(&router.resolve(request).compat().await?.to_vec()?, src)
        .await?;

    info!("Response completed. Sent back to {} successfully.", src);

    Ok(())
}
