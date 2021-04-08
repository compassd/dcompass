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

use super::{QHandle, QHandleError, Result};
use async_trait::async_trait;
use std::sync::Arc;
use trust_dns_client::{op::Message, rr::dnssec::SupportedAlgorithms};
use trust_dns_proto::rr::Name;
use trust_dns_server::{
    authority::{Authority, LookupError, ZoneType},
    store::file::{FileAuthority, FileConfig},
};

// FileAuthority doesn't implement Clone, and QHandle requires us to Send + Sync.
#[derive(Clone)]
pub struct Zone(Arc<FileAuthority>);

impl Zone {
    pub fn new(zone_type: ZoneType, origin: String, path: String) -> Result<Self> {
        Ok(Self(Arc::new(
            FileAuthority::try_from_config(
                Name::from_utf8(origin)?,
                zone_type,
                false,
                None,
                &FileConfig {
                    zone_file_path: path,
                },
            )
            .map_err(QHandleError::ZoneCreationFailed)?,
        )))
    }
}

#[async_trait]
impl QHandle for Zone {
    async fn query(&self, mut msg: Message) -> Result<Message> {
        Ok(
            match self
                .0
                .search(
                    &msg.queries()[0].clone().into(),
                    false,
                    SupportedAlgorithms::new(),
                )
                .await
            {
                Ok(v) => {
                    msg.add_answers(v.iter().cloned());
                    msg
                }
                // Some error code specified, return specified error message
                Err(LookupError::ResponseCode(c)) => Message::error_msg(msg.id(), msg.op_code(), c),
                // Other error occured
                Err(e) => return Err(QHandleError::LookupError(e)),
            },
        )
    }
}
