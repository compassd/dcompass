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

use super::message::helper::{DnsRecordsIter, OptRecordsIter};
use crate::errors::{MessageError, ScriptError};
use bytes::Bytes;
use once_cell::sync::Lazy;
use rune::{runtime::Protocol, Module};
use std::str::FromStr;

macro_rules! create_new_type {
    ($new: ident, $orig: ty) => {
        #[derive(rune::Any, Clone)]
        pub struct $new(pub $orig);

        impl From<$new> for $orig {
            fn from(new: $new) -> Self {
                new.0
            }
        }

        impl From<&$new> for $orig {
            fn from(new: &$new) -> Self {
                new.0.clone()
            }
        }

        impl From<$orig> for $new {
            fn from(orig: $orig) -> Self {
                Self(orig)
            }
        }

        impl From<&$orig> for $new {
            fn from(orig: &$orig) -> Self {
                Self(orig.clone())
            }
        }
    };
}

macro_rules! create_str_kit {
    ($self: ty, $orig: ty, $m: ident) => {
        $m.inst_fn("to_str", |this: &$self| this.0.to_string())
            .unwrap();

        $m.inst_fn(Protocol::EQ, |this: &$self, other: &str| {
            this.0.to_string() == other
        })
        .unwrap();

        $m.function(
            &[stringify!($self), "from_str"],
            |s: &str| -> Result<$self, ScriptError> {
                let res: Result<_, MessageError> = <$orig>::from_str(s).map_err(|e| e.into());
                Ok(res?.into())
            },
        )
        .unwrap();
    };
}

create_new_type!(Message, domain::base::Message<Bytes>);
create_new_type!(Header, domain::base::Header);

create_new_type!(Dname, domain::base::Dname<Bytes>);
// TODO: implment these enums to make them usable
create_new_type!(Rcode, domain::base::iana::rcode::Rcode);
create_new_type!(OptRcode, domain::base::iana::OptRcode);
create_new_type!(Opcode, domain::base::iana::opcode::Opcode);
create_new_type!(Rtype, domain::base::iana::rtype::Rtype);
create_new_type!(Class, domain::base::iana::class::Class);

create_new_type!(
    Question,
    domain::base::question::Question<domain::base::Dname<Bytes>>
);

create_new_type!(AllOptData, domain::base::opt::AllOptData<Bytes>);
create_new_type!(ClientSubnet, domain::base::opt::ClientSubnet);
create_new_type!(Cookie, domain::base::opt::Cookie);
create_new_type!(OptRecord, domain::base::opt::OptRecord<Bytes>);

create_new_type!(Aaaa, domain::rdata::Aaaa);
create_new_type!(Cname, domain::rdata::Cname<domain::base::Dname<Bytes>>);
create_new_type!(Txt, domain::rdata::Txt<Bytes>);
create_new_type!(A, domain::rdata::A);

create_new_type!(IpAddr, std::net::IpAddr);
create_new_type!(
    DnsRecord,
    domain::base::Record<
        domain::base::Dname<Bytes>,
        domain::rdata::AllRecordData<Bytes, domain::base::Dname<Bytes>>,
    >
);
create_new_type!(DnsRecordData, domain::rdata::AllRecordData<Bytes, domain::base::Dname<Bytes>>);
create_new_type!(OptRecordData, domain::base::opt::AllOptData<Bytes>);

pub static TYPES_MODULE: Lazy<Module> = Lazy::new(|| {
    let mut m = Module::new();

    m.ty::<Message>().unwrap();
    m.ty::<Header>().unwrap();

    // DNS Primitives
    m.ty::<Dname>().unwrap();
    create_str_kit!(Dname, domain::base::Dname<Bytes>, m);

    m.ty::<Rcode>().unwrap();
    // Rcode doesn't implment FromStr
    m.inst_fn("to_str", |this: &Rcode| this.0.to_string())
        .unwrap();

    m.inst_fn(Protocol::EQ, |this: &Rcode, other: &str| {
        this.0.to_string() == other
    })
    .unwrap();

    m.ty::<OptRcode>().unwrap();
    // OptRcode doesn't implment FromStr
    m.inst_fn("to_str", |this: &OptRcode| this.0.to_string())
        .unwrap();

    m.inst_fn(Protocol::EQ, |this: &OptRcode, other: &str| {
        this.0.to_string() == other
    })
    .unwrap();

    m.ty::<Opcode>().unwrap();
    create_str_kit!(Opcode, domain::base::iana::opcode::Opcode, m);

    m.ty::<Rtype>().unwrap();
    create_str_kit!(Rtype, domain::base::iana::rtype::Rtype, m);

    m.ty::<Class>().unwrap();
    create_str_kit!(Class, domain::base::iana::class::Class, m);

    m.ty::<Question>().unwrap();

    // Record Primitives
    m.ty::<DnsRecord>().unwrap();
    m.ty::<DnsRecordData>().unwrap();
    m.ty::<OptRecord>().unwrap();
    m.ty::<AllOptData>().unwrap();
    m.ty::<A>().unwrap();
    m.ty::<Aaaa>().unwrap();
    m.ty::<Cname>().unwrap();
    m.ty::<Txt>().unwrap();
    m.ty::<Cookie>().unwrap();
    m.ty::<ClientSubnet>().unwrap();

    // Iterators
    m.ty::<OptRecordsIter>().unwrap();
    m.inst_fn(Protocol::INTO_ITER, OptRecordsIter::into_iterator)
        .unwrap();
    m.inst_fn("into_iter", OptRecordsIter::into_iterator)
        .unwrap();

    m.ty::<DnsRecordsIter>().unwrap();
    m.inst_fn(Protocol::INTO_ITER, DnsRecordsIter::into_iterator)
        .unwrap();
    m.inst_fn("into_iter", DnsRecordsIter::into_iterator)
        .unwrap();

    // Other types
    m.ty::<IpAddr>().unwrap();
    create_str_kit!(IpAddr, std::net::IpAddr, m);

    m
});
