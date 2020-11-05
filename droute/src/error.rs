use thiserror::Error;
use trust_dns_client::error::ClientError;
use trust_dns_proto::error::ProtoError;

pub type Result<T> = std::result::Result<T, DrouteError>;

// WordCountError enumerates all possible errors returned by this library.
#[derive(Error, Debug)]
pub enum DrouteError {
    #[error("No upstream with tag {0} found")]
    MissingTag(usize),

    #[error("Cannot have number of workers less than 1: {0}")]
    InvalidWorker(usize),

    #[error(transparent)]
    ClientError(#[from] ClientError),

    #[error(transparent)]
    IOError(#[from] std::io::Error),

    #[error(transparent)]
    ProtoError(#[from] ProtoError),

    #[error(transparent)]
    ParseError(#[from] serde_json::Error),

    #[error(transparent)]
    TimeError(#[from] tokio::time::Elapsed),
}
