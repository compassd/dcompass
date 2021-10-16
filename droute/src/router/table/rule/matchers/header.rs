use domain::base::{
    iana::{Opcode, Rcode},
    Header as DomainHeader,
};

use crate::router::table::State;

use super::Matcher;

// Copyright 2021 LEXUGE
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

use serde::Deserialize;

#[derive(Deserialize, Clone, PartialEq, Eq, Hash, Debug)]
#[serde(rename_all = "UPPERCASE")]
pub enum HeaderBit {
    // AA bit
    AA,
    // TC bit
    TC,
    // RD bit
    RD,
    // RA bit
    RA,
    // Z bit
    Z,
    // AD bit
    AD,
    // CD bit
    CD,
}

impl HeaderBit {
    fn match_bit(&self, header: &DomainHeader) -> bool {
        match self {
            HeaderBit::AA => header.aa(),
            HeaderBit::TC => header.tc(),
            HeaderBit::RD => header.rd(),
            HeaderBit::RA => header.ra(),
            HeaderBit::Z => header.z(),
            HeaderBit::AD => header.ad(),
            HeaderBit::CD => header.cd(),
        }
    }
}

#[derive(Deserialize, Clone, PartialEq, Eq, Hash, Debug)]
#[serde(rename_all = "UPPERCASE")]
#[serde(remote = "Rcode")]
enum RcodeDef {
    NoError,
    FormErr,
    ServFail,
    NXDomain,
    NotImp,
    Refused,
    YXDomain,
    YXRRSet,
    NXRRSet,
    NotAuth,
    NotZone,
    Int(u8),
}

#[derive(Deserialize, Clone, PartialEq, Eq, Hash, Debug)]
#[serde(rename_all = "UPPERCASE")]
#[serde(remote = "Opcode")]
enum OpcodeDef {
    Query,
    IQuery,
    Status,
    Notify,
    Update,
    Dso,
    Int(u8),
}

#[derive(Deserialize, Clone, PartialEq, Eq, Hash, Debug)]
#[serde(rename_all = "lowercase")]
/// Header matching conditions
pub enum HeaderCond {
    /// Matches a given header bit
    Bit(HeaderBit),
    /// Matches a given Opcode
    Opcode(#[serde(with = "OpcodeDef")] Opcode),
    /// Matches a given Rcode
    Rcode(#[serde(with = "RcodeDef")] Rcode),
}

impl HeaderCond {
    fn matches(&self, header: &DomainHeader) -> bool {
        match self {
            HeaderCond::Bit(bit) => bit.match_bit(header),
            HeaderCond::Opcode(opcode) => &header.opcode() == opcode,
            HeaderCond::Rcode(rcode) => &header.rcode() == rcode,
        }
    }
}

#[derive(Deserialize, Clone, PartialEq, Eq, Hash, Debug)]
#[serde(rename_all = "lowercase")]
/// Header matcher
pub struct Header {
    /// Matching condition
    pub cond: HeaderCond,
    /// Should we match on query msg?
    pub query: bool,
}

impl Matcher for Header {
    fn matches(&self, state: &State) -> bool {
        if self.query {
            self.cond.matches(&state.query.header())
        } else {
            self.cond.matches(&state.resp.header())
        }
    }
}
