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

mod helpers;

use domain::base::{name::PushError, octets::ParseError};
use rhai::{export_module, plugin::*};
use thiserror::Error;

pub use helpers::{DnsRecord, DnsRecordsIter};

/// A shorthand for returning utils error.
pub type MessageResult<T> = std::result::Result<T, MessageError>;

#[derive(Error, Debug)]
/// All possible errors that may incur when using message.
pub enum MessageError {
    /// The record data indicated is currently not supported.
    #[error("Record data not supported")]
    RecordUnsupported,

    /// Failed to parse the record
    #[error(transparent)]
    ParseError(#[from] ParseError),

    /// Failed to convert to Dname
    #[error(transparent)]
    PushError(#[from] PushError),
}

macro_rules! create_record_iter_impl {
    ($name: ident, $msg: ident) => {{
        use domain::{base::ParsedDname, rdata::AllRecordData};

        let $name = $msg
            .$name()
            .into_evalrst_err()?
            .limit_to::<AllRecordData<Bytes, ParsedDname<&Bytes>>>();

        let mut inner = Vec::new();
        for record in $name {
            // We don't abort on error, we simply skip them. Therefore, we cannot use Try operators
            if let Ok(record) = record {
                if let Ok(data) = from_ref(record.data().clone()) {
                    inner.push(
                        (
                            record.owner().to_dname().into_evalrst_err()?,
                            record.class(),
                            record.ttl(),
                            data,
                        )
                            .into(),
                    );
                }
            }
        }
        Ok(DnsRecordsIter(inner))
    }};
}

macro_rules! create_rdata_conversion {
    ($record: ident, $rtype: path) => {{
        use crate::{router::script::message::MessageError, IntoEvalAltResultError};
        use domain::rdata::AllRecordData;

        match $record.data() {
            $rtype(s) => Ok(s.clone()),
            _ => Err(MessageError::RecordUnsupported).into_evalrst_err(),
        }
    }};
}

#[export_module]
pub mod rhai_mod {
    pub mod indexers {
        use crate::{
            router::script::message::{DnsRecord, DnsRecordsIter},
            IntoEvalAltResultStr,
        };

        #[rhai_fn(index_get, pure, return_raw)]
        pub fn record_iter_index_get(
            iter: &mut DnsRecordsIter,
            index: i32,
        ) -> Result<DnsRecord, Box<EvalAltResult>> {
            if let Some(r) = iter.0.get(index as usize) {
                Ok(r.clone())
            } else {
                Err("index is out of bound for the DNS record iterator").into_evalrst_str()
            }
        }
    }

    pub mod convertions {
        use domain::rdata::{Aaaa, A};

        #[rhai_fn(pure, return_raw)]
        pub fn to_a(record: &mut DnsRecord) -> Result<A, Box<EvalAltResult>> {
            create_rdata_conversion!(record, AllRecordData::A)
        }

        #[rhai_fn(pure, return_raw)]
        pub fn to_aaaa(record: &mut DnsRecord) -> Result<Aaaa, Box<EvalAltResult>> {
            create_rdata_conversion!(record, AllRecordData::Aaaa)
        }
    }

    // Unfortunately, we cannot use macro because of the lack of eager expansion.
    pub mod strings_related {
        pub mod opcode {
            use domain::base::iana::Opcode;
            use rhai::ImmutableString;

            #[rhai_fn(pure)]
            pub fn to_string(opcode: &mut Opcode) -> String {
                opcode.to_string()
            }

            #[rhai_fn(pure, name = "==")]
            pub fn cmp_type_to_str(opcode: &mut Opcode, other: ImmutableString) -> bool {
                opcode.to_string() == other
            }

            #[rhai_fn(name = "==")]
            pub fn cmp_str_to_type(other: ImmutableString, opcode: Opcode) -> bool {
                opcode.to_string() == other
            }

            #[rhai_fn(pure, name = "!=")]
            pub fn cmp_ineq_type_to_str(opcode: &mut Opcode, other: ImmutableString) -> bool {
                opcode.to_string() != other
            }

            #[rhai_fn(name = "!=")]
            pub fn cmp_ineq_str_to_type(other: ImmutableString, opcode: Opcode) -> bool {
                opcode.to_string() != other
            }
        }

        pub mod rcode {
            use domain::base::iana::Rcode;
            use rhai::ImmutableString;

            #[rhai_fn(pure)]
            pub fn to_string(rcode: &mut Rcode) -> String {
                rcode.to_string()
            }

            #[rhai_fn(pure, name = "==")]
            pub fn cmp_type_to_str(rcode: &mut Rcode, other: ImmutableString) -> bool {
                rcode.to_string() == other
            }

            #[rhai_fn(name = "==")]
            pub fn cmp_str_to_type(other: ImmutableString, rcode: Rcode) -> bool {
                rcode.to_string() == other
            }

            #[rhai_fn(pure, name = "!=")]
            pub fn cmp_ineq_type_to_str(rcode: &mut Rcode, other: ImmutableString) -> bool {
                rcode.to_string() != other
            }

            #[rhai_fn(name = "!=")]
            pub fn cmp_ineq_str_to_type(other: ImmutableString, rcode: Rcode) -> bool {
                rcode.to_string() != other
            }
        }

        pub mod record {
            use crate::router::script::message::DnsRecord;
            use rhai::ImmutableString;

            #[rhai_fn(pure)]
            pub fn to_string(record: &mut DnsRecord) -> String {
                record.to_string()
            }

            #[rhai_fn(pure, name = "==")]
            pub fn cmp_type_to_str(record: &mut DnsRecord, other: ImmutableString) -> bool {
                record.to_string() == other
            }

            #[rhai_fn(name = "==")]
            pub fn cmp_str_to_type(other: ImmutableString, record: DnsRecord) -> bool {
                record.to_string() == other
            }

            #[rhai_fn(pure, name = "!=")]
            pub fn cmp_ineq_type_to_str(record: &mut DnsRecord, other: ImmutableString) -> bool {
                record.to_string() != other
            }

            #[rhai_fn(name = "!=")]
            pub fn cmp_ineq_str_to_type(other: ImmutableString, record: DnsRecord) -> bool {
                record.to_string() != other
            }
        }

        pub mod rtype {
            use domain::base::Rtype;
            use rhai::ImmutableString;

            #[rhai_fn(pure)]
            pub fn to_string(rtype: &mut Rtype) -> String {
                rtype.to_string()
            }

            #[rhai_fn(pure, name = "==")]
            pub fn cmp_type_to_str(rtype: &mut Rtype, other: ImmutableString) -> bool {
                rtype.to_string() == other
            }

            #[rhai_fn(name = "==")]
            pub fn cmp_str_to_type(other: ImmutableString, rtype: Rtype) -> bool {
                rtype.to_string() == other
            }

            #[rhai_fn(pure, name = "!=")]
            pub fn cmp_ineq_type_to_str(rtype: &mut Rtype, other: ImmutableString) -> bool {
                rtype.to_string() != other
            }

            #[rhai_fn(name = "!=")]
            pub fn cmp_ineq_str_to_type(other: ImmutableString, rtype: Rtype) -> bool {
                rtype.to_string() != other
            }
        }

        pub mod class {
            use domain::base::iana::Class;
            use rhai::ImmutableString;

            #[rhai_fn(pure)]
            pub fn to_string(class: &mut Class) -> String {
                class.to_string()
            }

            #[rhai_fn(pure, name = "==")]
            pub fn cmp_type_to_str(class: &mut Class, other: ImmutableString) -> bool {
                class.to_string() == other
            }

            #[rhai_fn(name = "==")]
            pub fn cmp_str_to_type(other: ImmutableString, class: Class) -> bool {
                class.to_string() == other
            }

            #[rhai_fn(pure, name = "!=")]
            pub fn cmp_ineq_type_to_str(class: &mut Class, other: ImmutableString) -> bool {
                class.to_string() != other
            }

            #[rhai_fn(name = "!=")]
            pub fn cmp_ineq_str_to_type(other: ImmutableString, class: Class) -> bool {
                class.to_string() != other
            }
        }

        pub mod dname {
            use bytes::Bytes;
            use domain::base::Dname;
            use rhai::ImmutableString;

            #[rhai_fn(pure)]
            pub fn to_string(dname: &mut Dname<Bytes>) -> String {
                dname.to_string()
            }

            #[rhai_fn(pure, name = "==")]
            pub fn cmp_type_to_str(dname: &mut Dname<Bytes>, other: ImmutableString) -> bool {
                dname.to_string() == other
            }

            #[rhai_fn(name = "==")]
            pub fn cmp_str_to_type(other: ImmutableString, dname: Dname<Bytes>) -> bool {
                dname.to_string() == other
            }

            #[rhai_fn(pure, name = "!=")]
            pub fn cmp_ineq_type_to_str(dname: &mut Dname<Bytes>, other: ImmutableString) -> bool {
                dname.to_string() != other
            }

            #[rhai_fn(name = "!=")]
            pub fn cmp_ineq_str_to_type(other: ImmutableString, dname: Dname<Bytes>) -> bool {
                dname.to_string() != other
            }
        }

        pub mod ipaddr {
            use rhai::ImmutableString;
            use std::net::IpAddr;

            #[rhai_fn(pure)]
            pub fn to_string(ipaddr: &mut IpAddr) -> String {
                ipaddr.to_string()
            }

            #[rhai_fn(pure, name = "==")]
            pub fn cmp_type_to_str(ipaddr: &mut IpAddr, other: ImmutableString) -> bool {
                ipaddr.to_string() == other
            }

            #[rhai_fn(name = "==")]
            pub fn cmp_str_to_type(other: ImmutableString, ipaddr: IpAddr) -> bool {
                ipaddr.to_string() == other
            }

            #[rhai_fn(pure, name = "!=")]
            pub fn cmp_ineq_type_to_str(ipaddr: &mut IpAddr, other: ImmutableString) -> bool {
                ipaddr.to_string() != other
            }

            #[rhai_fn(name = "!=")]
            pub fn cmp_ineq_str_to_type(other: ImmutableString, ipaddr: IpAddr) -> bool {
                ipaddr.to_string() != other
            }
        }
    }

    pub mod getters {
        use super::super::helpers::{from_ref, DnsRecordsIter};
        use crate::{IntoEvalAltResultError, IntoEvalAltResultStr};
        use bytes::Bytes;
        use domain::base::{Dname, Header, Message, Question, ToDname};
        use rhai::EvalAltResult;

        #[rhai_fn(get = "header", pure)]
        pub fn get_header(msg: &mut Message<Bytes>) -> Header {
            msg.header()
        }

        // Group them together, they will get flattened
        pub mod header {
            use domain::base::iana::{Opcode, Rcode};

            #[rhai_fn(get = "aa", pure)]
            pub fn get_aa(header: &mut Header) -> bool {
                header.aa()
            }

            #[rhai_fn(get = "ad", pure)]
            pub fn get_ad(header: &mut Header) -> bool {
                header.ad()
            }

            #[rhai_fn(get = "cd", pure)]
            pub fn get_cd(header: &mut Header) -> bool {
                header.cd()
            }

            #[rhai_fn(get = "id", pure)]
            pub fn get_id(header: &mut Header) -> u16 {
                header.id()
            }

            #[rhai_fn(get = "qr", pure)]
            pub fn get_qr(header: &mut Header) -> bool {
                header.qr()
            }

            #[rhai_fn(get = "ra", pure)]
            pub fn get_ra(header: &mut Header) -> bool {
                header.ra()
            }

            #[rhai_fn(get = "tc", pure)]
            pub fn get_tc(header: &mut Header) -> bool {
                header.tc()
            }

            #[rhai_fn(get = "z", pure)]
            pub fn get_z(header: &mut Header) -> bool {
                header.z()
            }

            #[rhai_fn(get = "rd", pure)]
            pub fn get_rd(header: &mut Header) -> bool {
                header.rd()
            }

            #[rhai_fn(get = "rcode", pure)]
            pub fn get_rcode(header: &mut Header) -> Rcode {
                header.rcode()
            }

            #[rhai_fn(get = "opcode", pure)]
            pub fn get_opcode(header: &mut Header) -> Opcode {
                header.opcode()
            }
        }

        #[rhai_fn(get = "first_question", pure, return_raw)]
        pub fn get_first_question(
            msg: &mut Message<Bytes>,
        ) -> Result<Question<Dname<Bytes>>, Box<EvalAltResult>> {
            let q = msg
                .first_question()
                .ok_or("no question or parse failed")
                .into_evalrst_str()?;
            Ok(Question::new(
                q.qname().to_dname().into_evalrst_err()?,
                q.qtype(),
                q.qclass(),
            ))
        }

        pub mod questions {
            use domain::base::{iana::Class, Rtype};

            #[rhai_fn(get = "qname", pure)]
            pub fn get_qname(question: &mut Question<Dname<Bytes>>) -> Dname<Bytes> {
                question.qname().clone()
            }

            #[rhai_fn(get = "qtype", pure)]
            pub fn get_qtype(question: &mut Question<Dname<Bytes>>) -> Rtype {
                question.qtype()
            }

            #[rhai_fn(get = "qclass", pure)]
            pub fn get_qclass(question: &mut Question<Dname<Bytes>>) -> Class {
                question.qclass()
            }
        }

        #[rhai_fn(get = "answer", pure, return_raw)]
        pub fn get_answer(msg: &mut Message<Bytes>) -> Result<DnsRecordsIter, Box<EvalAltResult>> {
            create_record_iter_impl!(answer, msg)
        }

        #[rhai_fn(get = "authority", pure, return_raw)]
        pub fn get_authority(
            msg: &mut Message<Bytes>,
        ) -> Result<DnsRecordsIter, Box<EvalAltResult>> {
            create_record_iter_impl!(authority, msg)
        }

        #[rhai_fn(get = "additional", pure, return_raw)]
        pub fn get_additional(
            msg: &mut Message<Bytes>,
        ) -> Result<DnsRecordsIter, Box<EvalAltResult>> {
            create_record_iter_impl!(additional, msg)
        }

        pub mod record {
            use crate::router::script::message::DnsRecord;
            use bytes::Bytes;
            use domain::base::{iana::Class, Dname, Rtype};

            #[rhai_fn(get = "owner", pure)]
            pub fn get_owner(record: &mut DnsRecord) -> Dname<Bytes> {
                record.owner().clone()
            }

            #[rhai_fn(get = "rtype", pure)]
            pub fn get_rtype(record: &mut DnsRecord) -> Rtype {
                record.rtype()
            }

            #[rhai_fn(get = "class", pure)]
            pub fn get_class(record: &mut DnsRecord) -> Class {
                record.class()
            }

            #[rhai_fn(get = "ttl", pure)]
            pub fn get_ttl(record: &mut DnsRecord) -> u32 {
                record.ttl()
            }

            pub mod rdata {
                pub mod a {
                    use domain::rdata::A;
                    use std::net::IpAddr;

                    #[rhai_fn(get = "ip", pure)]
                    pub fn get_ip(data: &mut A) -> IpAddr {
                        data.addr().into()
                    }
                }

                pub mod aaaa {
                    use domain::rdata::Aaaa;
                    use std::net::IpAddr;

                    #[rhai_fn(get = "ip", pure)]
                    pub fn get_ip(data: &mut Aaaa) -> IpAddr {
                        data.addr().into()
                    }
                }
            }
        }
    }
}
