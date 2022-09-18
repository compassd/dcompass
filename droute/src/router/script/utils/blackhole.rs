// Copyright 2022 LEXUGE
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

use super::Result;
use crate::MAX_TTL;
use bytes::{Bytes, BytesMut};
use domain::{
    base::{Dname, Message, MessageBuilder},
    rdata::Soa,
};
use once_cell::sync::Lazy;
use std::str::FromStr;

// Data from smartdns. https://github.com/pymumu/smartdns/blob/42b3e98b2a3ca90ea548f8cb5ed19a3da6011b74/src/dns_server.c#L651
static SOA_RDATA: Lazy<(Dname<Bytes>, u32, Soa<Dname<Bytes>>)> = Lazy::new(|| {
    (
        Dname::root_bytes(),
        MAX_TTL,
        Soa::new(
            Dname::from_str("a.gtld-servers.net").unwrap(),
            Dname::from_str("nstld.verisign-grs.com").unwrap(),
            1800.into(),
            1800,
            900,
            604800,
            86400,
        ),
    )
});

/// Create a message that stops the requestor to send the query again.
pub fn blackhole(query: &Message<Bytes>) -> Result<Message<Bytes>> {
    // Is 50 a good number?
    let mut builder = MessageBuilder::from_target(BytesMut::with_capacity(50))?
        .start_answer(query, domain::base::iana::Rcode::NoError)?
        .additional();

    builder.push(SOA_RDATA.clone())?;

    Ok(builder.into_message())
}
