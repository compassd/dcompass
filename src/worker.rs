use crate::filter::Filter;
use anyhow::Result;
use log::*;
use std::sync::Arc;
use tokio::net::UdpSocket;
use trust_dns_proto::op::response_code::ResponseCode;
use trust_dns_proto::op::Message;

/// Handle a single incoming packet
pub async fn worker(filter: Arc<Filter>, socket: Arc<UdpSocket>, i: i32) -> Result<()> {
    info!("[Worker {}] started.", i);

    let mut buf = [0; 512];
    let (_, src) = socket.recv_from(&mut buf).await?;

    let request = Message::from_vec(&buf)?;

    for q in request.queries() {
        info!("[Worker {}] Received query: {:?}", i, q);

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
                info!(
                    "[Worker {}] Response completed. Sent back to {} successfully.",
                    i, src
                );
            }
        };
    }

    Ok(())
}
