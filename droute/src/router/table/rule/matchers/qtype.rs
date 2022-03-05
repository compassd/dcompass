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

use super::{super::super::State, MatchError, Matcher, Result};
use crate::AsyncTryInto;
use async_trait::async_trait;
use domain::base::iana::rtype::Rtype;
use serde::Deserialize;
use std::collections::HashSet;

/// A matcher that matches if first query is of any of the record types provided.
pub struct QType(HashSet<Rtype>);

impl QType {
    /// Create a new `QType` matcher.
    pub fn new(types: HashSet<Rtype>) -> Result<Self> {
        Ok(Self(types))
    }
}

impl Matcher for QType {
    fn matches(&self, state: &State) -> bool {
        self.0
            .contains(&state.query.first_question().unwrap().qtype())
    }
}

#[derive(Deserialize, Clone)]
#[serde(rename_all = "UPPERCASE")]
#[serde(remote = "Rtype")]
pub enum RtypeDef {
    A,
    Ns,
    Md,
    Mf,
    Cname,
    Soa,
    Mb,
    Mg,
    Mr,
    Null,
    Wks,
    Ptr,
    Hinfo,
    Minfo,
    Mx,
    Txt,
    Rp,
    Afsdb,
    X25,
    Isdn,
    Rt,
    Nsap,
    Nsapptr,
    Sig,
    Key,
    Px,
    Gpos,
    Aaaa,
    Loc,
    Nxt,
    Eid,
    Nimloc,
    Srv,
    Atma,
    Naptr,
    Kx,
    Cert,
    A6,
    Dname,
    Sink,
    Opt,
    Apl,
    Ds,
    Sshfp,
    Ipseckey,
    Rrsig,
    Nsec,
    Dnskey,
    Dhcid,
    Nsec3,
    Nsec3param,
    Tlsa,
    Smimea,
    Hip,
    Ninfo,
    Rkey,
    Talink,
    Cds,
    Cdnskey,
    Openpgpkey,
    Csync,
    Zonemd,
    Spf,
    Uinfo,
    Uid,
    Gid,
    Unspec,
    Nid,
    L32,
    L64,
    Lp,
    Eui48,
    Eui64,
    Tkey,
    Tsig,
    Ixfr,
    Axfr,
    Mailb,
    Maila,
    Any,
    Uri,
    Caa,
    Avc,
    Doa,
    Ta,
    Dlv,
    Int(u16),
}

// TODO: remove it once domain supports deserializing rtype
#[derive(Deserialize, Clone, PartialEq, Eq, Hash, Debug)]
#[serde(transparent)]
struct Adaptor(#[serde(with = "RtypeDef")] Rtype);

/// A builder for qtype matcher plugin
#[derive(Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(transparent)]
pub struct QTypeBuilder(HashSet<Adaptor>);

impl Default for QTypeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl QTypeBuilder {
    /// Create an empty builder
    pub fn new() -> Self {
        Self(HashSet::new())
    }

    /// Add a record type to match
    pub fn add_rr(mut self, rr: Rtype) -> Self {
        self.0.insert(Adaptor(rr));
        self
    }
}

#[async_trait]
impl AsyncTryInto<QType> for QTypeBuilder {
    type Error = MatchError;

    async fn async_try_into(self) -> Result<QType> {
        QType::new(self.0.iter().map(|x| x.0).collect())
    }
}
