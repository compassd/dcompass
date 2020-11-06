use anyhow::Result;
use droute::router::Router;
use log::*;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio_compat_02::FutureExt;
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
        .send_to(&router.resolve(request).compat().await?.to_vec()?, src)
        .await?;

    info!("Response completed. Sent back to {} successfully.", src);

    Ok(())
}
