use anyhow::Result;
use droute::filter::Filter;
use log::*;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio_compat_02::FutureExt;
use trust_dns_proto::op::Message;

/// Handle a single incoming packet
pub async fn worker(filter: Arc<Filter>, socket: Arc<UdpSocket>, i: usize) -> Result<()> {
    info!("[Worker {}] started.", i);

    let mut buf = [0; 512];
    let (_, src) = socket.recv_from(&mut buf).await?;

    let request = Message::from_vec(&buf)?;

    info!("[Worker {}] Received message: {:?}", i, request);

    socket
        .send_to(&filter.resolve(request).compat().await?.to_vec()?, src)
        .await?;

    info!(
        "[Worker {}] Response completed. Sent back to {} successfully.",
        i, src
    );

    Ok(())
}
