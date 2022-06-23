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

use domain::base::{name::PushError, octets::ParseError, ShortBuf};
use rhai::{export_module, plugin::*};
use thiserror::Error;

pub use helpers::{DnsRecord, DnsRecordsIter, OptRecordsIter};

/// A shorthand for returning utils error.
pub type MessageResult<T> = std::result::Result<T, MessageError>;

#[derive(Error, Debug)]
/// All possible errors that may incur when using message.
pub enum MessageError {
    /// The record data indicated is currently not supported or mismatched on conversion.
    #[error("Record data not supported or mismatched")]
    RecordUnsupported,

    /// The Opt data indicated is currently not supported or mismatched on conversion.
    #[error("Option not supported or mismatched")]
    OptionUnsupported,

    /// Failed to parse the record
    #[error(transparent)]
    ParseError(#[from] ParseError),

    /// Failed to convert to Dname
    #[error(transparent)]
    PushError(#[from] PushError),

    /// Buffer is too short
    #[error(transparent)]
    ShortBuf(#[from] ShortBuf),
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
                if let Ok(data) = dns_record_from_ref(record.data().clone()) {
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

macro_rules! create_conversion {
    ($src: expr, $rtype: path, $type: tt, $err: path) => {{
        use crate::{router::script::message::MessageError, IntoEvalAltResultError};
        use $type;

        match $src {
            $rtype(s) => Ok(s.clone()),
            _ => Err($err).into_evalrst_err(),
        }
    }};
}

#[export_module]
pub mod rhai_mod {
    pub mod indexers {
        use crate::{
            router::script::message::{DnsRecord, DnsRecordsIter, OptRecordsIter},
            IntoEvalAltResultStr,
        };
        use domain::base::opt::AllOptData;

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

        // CAUTION: this doesn't update any DNS message.
        #[rhai_fn(index_set, return_raw)]
        pub fn record_iter_index_set(
            iter: &mut DnsRecordsIter,
            index: i32,
            record: DnsRecord,
        ) -> Result<(), Box<EvalAltResult>> {
            if let Some(r) = iter.0.get_mut(index as usize) {
                *r = record;
                Ok(())
            } else {
                Err("index is out of bound for the DNS record iterator").into_evalrst_str()
            }
        }

        #[rhai_fn(index_get, pure, return_raw)]
        pub fn option_iter_index_get(
            iter: &mut OptRecordsIter,
            index: i32,
        ) -> Result<AllOptData<bytes::Bytes>, Box<EvalAltResult>> {
            if let Some(r) = iter.0.get(index as usize) {
                Ok(r.clone())
            } else {
                Err("index is out of bound for the Opt record iterator").into_evalrst_str()
            }
        }
    }

    pub mod convertions {
        use crate::router::script::message::DnsRecord;
        use bytes::Bytes;
        use domain::{
            base::{
                opt::{AllOptData, ClientSubnet, Cookie, OptRecord},
                Record,
            },
            rdata::{Aaaa, AllRecordData, Txt, A},
        };

        #[rhai_fn(pure, return_raw)]
        pub fn to_a(record: &mut DnsRecord) -> Result<A, Box<EvalAltResult>> {
            create_conversion!(
                record.data(),
                AllRecordData::A,
                AllRecordData,
                MessageError::RecordUnsupported
            )
        }

        #[rhai_fn(pure, return_raw)]
        pub fn to_aaaa(record: &mut DnsRecord) -> Result<Aaaa, Box<EvalAltResult>> {
            create_conversion!(
                record.data(),
                AllRecordData::Aaaa,
                AllRecordData,
                MessageError::RecordUnsupported
            )
        }

        #[rhai_fn(pure, return_raw)]
        pub fn to_txt(record: &mut DnsRecord) -> Result<Txt<Bytes>, Box<EvalAltResult>> {
            create_conversion!(
                record.data(),
                AllRecordData::Txt,
                AllRecordData,
                MessageError::RecordUnsupported
            )
        }

        #[rhai_fn(pure, return_raw)]
        pub fn to_opt(record: &mut DnsRecord) -> Result<OptRecord<Bytes>, Box<EvalAltResult>> {
            let opt = create_conversion!(
                record.data(),
                AllRecordData::Opt,
                AllRecordData,
                MessageError::RecordUnsupported
            )?;
            Ok(OptRecord::from_record(Record::new(
                record.owner().clone(),
                record.class(),
                record.ttl(),
                opt,
            )))
        }

        #[rhai_fn(pure, return_raw)]
        pub fn to_cookie(option: &mut AllOptData<Bytes>) -> Result<Cookie, Box<EvalAltResult>> {
            create_conversion!(
                option,
                AllOptData::Cookie,
                AllOptData,
                MessageError::OptionUnsupported
            )
        }

        #[rhai_fn(pure, return_raw)]
        pub fn to_client_subnet(
            option: &mut AllOptData<Bytes>,
        ) -> Result<ClientSubnet, Box<EvalAltResult>> {
            create_conversion!(
                option,
                AllOptData::ClientSubnet,
                AllOptData,
                MessageError::OptionUnsupported
            )
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

        pub mod optrcode {
            use domain::base::iana::OptRcode;
            use rhai::ImmutableString;

            #[rhai_fn(pure)]
            pub fn to_string(optrcode: &mut OptRcode) -> String {
                optrcode.to_string()
            }

            #[rhai_fn(pure, name = "==")]
            pub fn cmp_type_to_str(optrcode: &mut OptRcode, other: ImmutableString) -> bool {
                optrcode.to_string() == other
            }

            #[rhai_fn(name = "==")]
            pub fn cmp_str_to_type(other: ImmutableString, optrcode: OptRcode) -> bool {
                optrcode.to_string() == other
            }

            #[rhai_fn(pure, name = "!=")]
            pub fn cmp_ineq_type_to_str(optrcode: &mut OptRcode, other: ImmutableString) -> bool {
                optrcode.to_string() != other
            }

            #[rhai_fn(name = "!=")]
            pub fn cmp_ineq_str_to_type(other: ImmutableString, optrcode: OptRcode) -> bool {
                optrcode.to_string() != other
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

        pub mod cookie {
            use domain::base::opt::Cookie;
            use rhai::ImmutableString;

            #[rhai_fn(pure)]
            pub fn to_string(cookie: &mut Cookie) -> String {
                hex::encode(cookie.cookie())
            }

            #[rhai_fn(pure, name = "==")]
            pub fn cmp_type_to_str(cookie: &mut Cookie, other: ImmutableString) -> bool {
                to_string(cookie) == other
            }

            #[rhai_fn(name = "==")]
            pub fn cmp_str_to_type(other: ImmutableString, mut cookie: Cookie) -> bool {
                to_string(&mut cookie) == other
            }

            #[rhai_fn(pure, name = "!=")]
            pub fn cmp_ineq_type_to_str(cookie: &mut Cookie, other: ImmutableString) -> bool {
                to_string(cookie) != other
            }

            #[rhai_fn(name = "!=")]
            pub fn cmp_ineq_str_to_type(other: ImmutableString, mut cookie: Cookie) -> bool {
                to_string(&mut cookie) != other
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
        use super::super::helpers::{dns_record_from_ref, DnsRecordsIter};
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

                pub mod txt {
                    use crate::IntoEvalAltResultError;
                    use domain::rdata::Txt;
                    use rhai::EvalAltResult;

                    #[rhai_fn(get = "text", pure, return_raw)]
                    pub fn get_text(data: &mut Txt<Bytes>) -> Result<String, Box<EvalAltResult>> {
                        // If the length of slice agrees with length indicated in the record header, it returns Some
                        data.as_flat_slice()
                            .map(|v| String::from_utf8(v.to_vec()).into_evalrst_err())
                            .unwrap_or_else(|| Ok("".to_string()))
                    }
                }

                pub mod opt {
                    use crate::{
                        router::script::message::helpers::OptRecordsIter, IntoEvalAltResultError,
                    };
                    use domain::base::{
                        iana::OptRcode,
                        opt::{AllOptData, OptRecord},
                        Header,
                    };
                    use rhai::EvalAltResult;

                    #[rhai_fn(get = "udp_payload_size", pure)]
                    pub fn get_udp_payload_size(data: &mut OptRecord<Bytes>) -> i32 {
                        data.udp_payload_size() as i32
                    }

                    #[rhai_fn(name = "rcode", pure)]
                    pub fn get_rcode(data: &mut OptRecord<Bytes>, header: Header) -> OptRcode {
                        data.rcode(header)
                    }

                    #[rhai_fn(get = "version", pure)]
                    pub fn get_version(data: &mut OptRecord<Bytes>) -> i32 {
                        data.version() as i32
                    }

                    #[rhai_fn(get = "dnssec_ok", pure)]
                    pub fn get_dnssec_ok(data: &mut OptRecord<Bytes>) -> bool {
                        data.dnssec_ok()
                    }

                    #[rhai_fn(get = "options", pure, return_raw)]
                    pub fn get_options(
                        data: &mut OptRecord<Bytes>,
                    ) -> Result<OptRecordsIter, Box<EvalAltResult>> {
                        Ok(OptRecordsIter(
                            data.iter()
                                .collect::<Result<Vec<AllOptData<Bytes>>, _>>()
                                .into_evalrst_err()?,
                        ))
                    }

                    pub mod options {
                        use crate::router::script::message::MessageError;
                        use domain::base::opt::AllOptData;
                        use rhai::EvalAltResult;

                        #[rhai_fn(get = "rtype", pure, return_raw)]
                        pub fn get_rtype(
                            data: &mut AllOptData<Bytes>,
                        ) -> Result<String, Box<EvalAltResult>> {
                            Ok(match data {
                                AllOptData::Chain(_) => "CHAIN",
                                AllOptData::ClientSubnet(_) => "CLIENT_SUBNET",
                                AllOptData::Cookie(_) => "COOKIE",
                                AllOptData::Dau(_) => "DAU",
                                AllOptData::Dhu(_) => "DHU",
                                AllOptData::Expire(_) => "EXPIRE",
                                AllOptData::ExtendedError(_) => "EXTENDED_ERROR",
                                AllOptData::KeyTag(_) => "KEY_TAG",
                                AllOptData::N3u(_) => "N3U",
                                AllOptData::Nsid(_) => "NSID",
                                AllOptData::Other(_) => "OTHER",
                                AllOptData::Padding(_) => "PADDING",
                                AllOptData::TcpKeepalive(_) => "TCP_KEEPALIVE",
                                _ => {
                                    return Err(MessageError::OptionUnsupported).into_evalrst_err()
                                }
                            }
                            .into())
                        }

                        pub mod client_subnet {
                            use domain::base::opt::ClientSubnet;
                            use std::net::IpAddr;

                            #[rhai_fn(pure, get = "addr")]
                            pub fn get_addr(client_subnet: &mut ClientSubnet) -> IpAddr {
                                client_subnet.addr()
                            }

                            #[rhai_fn(pure, get = "source_prefix_len")]
                            pub fn get_source_prefix_len(client_subnet: &mut ClientSubnet) -> i32 {
                                client_subnet.source_prefix_len() as i32
                            }

                            #[rhai_fn(pure, get = "scope_prefix_len")]
                            pub fn get_scope_prefix_len(client_subnet: &mut ClientSubnet) -> i32 {
                                client_subnet.scope_prefix_len() as i32
                            }
                        }
                    }
                }
            }
        }
    }

    pub mod setters {
        // Group them together, they will get flattened
        pub mod header {
            use domain::base::{
                iana::{Opcode, Rcode},
                Header,
            };

            #[rhai_fn(set = "aa")]
            pub fn set_aa(header: &mut Header, aa: bool) {
                header.set_aa(aa)
            }

            #[rhai_fn(set = "ad")]
            pub fn set_ad(header: &mut Header, ad: bool) {
                header.set_ad(ad)
            }

            #[rhai_fn(set = "cd")]
            pub fn set_cd(header: &mut Header, cd: bool) {
                header.set_cd(cd)
            }

            #[rhai_fn(set = "id")]
            pub fn set_id(header: &mut Header, id: u16) {
                header.set_id(id)
            }

            #[rhai_fn(set = "qr")]
            pub fn set_qr(header: &mut Header, qr: bool) {
                header.set_qr(qr)
            }

            #[rhai_fn(set = "ra")]
            pub fn set_ra(header: &mut Header, ra: bool) {
                header.set_ra(ra)
            }

            #[rhai_fn(set = "tc")]
            pub fn set_tc(header: &mut Header, tc: bool) {
                header.set_tc(tc)
            }

            #[rhai_fn(set = "z")]
            pub fn set_z(header: &mut Header, z: bool) {
                header.set_z(z)
            }

            #[rhai_fn(set = "rd")]
            pub fn set_rd(header: &mut Header, rd: bool) {
                header.set_rd(rd)
            }

            // TODO: add set_rcode_from_str
            #[rhai_fn(set = "rcode")]
            pub fn set_rcode(header: &mut Header, rcode: Rcode) {
                header.set_rcode(rcode)
            }

            #[rhai_fn(set = "rcode")]
            pub fn set_rcode_from_u8(header: &mut Header, rcode: u8) {
                header.set_rcode(rcode.into())
            }

            #[rhai_fn(set = "opcode")]
            pub fn set_opcode(header: &mut Header, opcode: Opcode) {
                header.set_opcode(opcode)
            }

            #[rhai_fn(set = "opcode")]
            pub fn set_opcode_from_u8(header: &mut Header, opcode: u8) {
                header.set_opcode(opcode.into())
            }
        }

        pub mod record {
            use crate::{router::script::message::DnsRecord, IntoEvalAltResultError};
            use bytes::Bytes;
            use domain::{
                base::{iana::Class, Dname},
                rdata::AllRecordData,
            };
            use rhai::{EvalAltResult, ImmutableString};
            use std::str::FromStr;

            pub fn create_record(
                owner: Dname<Bytes>,
                class: Class,
                ttl: i32,
                data: AllRecordData<Bytes, Dname<Bytes>>,
            ) -> DnsRecord {
                DnsRecord::new(owner, class, ttl as u32, data)
            }

            #[rhai_fn(name = "create_record", return_raw)]
            pub fn create_record_dname_str(
                owner: Dname<Bytes>,
                class: ImmutableString,
                ttl: i32,
                data: AllRecordData<Bytes, Dname<Bytes>>,
            ) -> Result<DnsRecord, Box<EvalAltResult>> {
                Ok(create_record(
                    owner,
                    Class::from_str(&class).into_evalrst_err()?,
                    ttl,
                    data,
                ))
            }

            #[rhai_fn(name = "create_record", return_raw)]
            pub fn create_record_str_class(
                owner: ImmutableString,
                class: Class,
                ttl: i32,
                data: AllRecordData<Bytes, Dname<Bytes>>,
            ) -> Result<DnsRecord, Box<EvalAltResult>> {
                Ok(create_record(
                    Dname::from_str(&owner).into_evalrst_err()?,
                    class,
                    ttl,
                    data,
                ))
            }

            #[rhai_fn(name = "create_record", return_raw)]
            pub fn create_record_str_str(
                owner: ImmutableString,
                class: ImmutableString,
                ttl: i32,
                data: AllRecordData<Bytes, Dname<Bytes>>,
            ) -> Result<DnsRecord, Box<EvalAltResult>> {
                Ok(create_record(
                    Dname::from_str(&owner).into_evalrst_err()?,
                    Class::from_str(&class).into_evalrst_err()?,
                    ttl,
                    data,
                ))
            }

            pub mod rdata {
                use bytes::Bytes;
                use domain::{base::Dname, rdata::AllRecordData};

                pub mod a {
                    use domain::rdata::A;
                    use rhai::{EvalAltResult, ImmutableString};
                    use std::net::Ipv4Addr;

                    use crate::IntoEvalAltResultError;

                    pub fn create_a(ip: Ipv4Addr) -> AllRecordData<Bytes, Dname<Bytes>> {
                        AllRecordData::A(A::new(ip))
                    }

                    #[rhai_fn(name = "create_a", return_raw)]
                    pub fn create_a_from_str(
                        ip: ImmutableString,
                    ) -> Result<AllRecordData<Bytes, Dname<Bytes>>, Box<EvalAltResult>>
                    {
                        Ok(create_a(ip.parse().into_evalrst_err()?))
                    }
                }

                pub mod aaaa {
                    use domain::rdata::Aaaa;
                    use rhai::{EvalAltResult, ImmutableString};
                    use std::net::Ipv6Addr;

                    use crate::IntoEvalAltResultError;

                    pub fn create_aaaa(ip: Ipv6Addr) -> AllRecordData<Bytes, Dname<Bytes>> {
                        AllRecordData::Aaaa(Aaaa::new(ip))
                    }

                    #[rhai_fn(name = "create_aaaa", return_raw)]
                    pub fn create_aaaa_from_str(
                        ip: ImmutableString,
                    ) -> Result<AllRecordData<Bytes, Dname<Bytes>>, Box<EvalAltResult>>
                    {
                        Ok(create_aaaa(ip.parse().into_evalrst_err()?))
                    }
                }

                pub mod txt {
                    use crate::IntoEvalAltResultError;
                    use domain::rdata::Txt;
                    use rhai::{EvalAltResult, ImmutableString};

                    #[rhai_fn(return_raw)]
                    pub fn create_txt(
                        text: ImmutableString,
                    ) -> Result<AllRecordData<Bytes, Dname<Bytes>>, Box<EvalAltResult>>
                    {
                        Ok(AllRecordData::Txt(
                            Txt::from_slice(text.as_bytes()).into_evalrst_err()?,
                        ))
                    }
                }

                pub mod opt {
                    use crate::{
                        router::script::message::helpers::{modify_opt, OptRecordsIter},
                        IntoEvalAltResultError,
                    };
                    use bytes::Bytes;
                    use domain::base::{opt::AllOptData, Message};
                    use rhai::EvalAltResult;

                    // Create an empty OPT section, this doesn't alter the message
                    pub fn create_opt_section() -> OptRecordsIter {
                        OptRecordsIter(Vec::new())
                    }

                    #[rhai_fn(return_raw)]
                    pub fn update_opt(
                        msg: &mut Message<Bytes>,
                        opt: OptRecordsIter,
                    ) -> Result<(), Box<EvalAltResult>> {
                        *msg = modify_opt(msg, opt).into_evalrst_err()?;
                        Ok(())
                    }

                    #[rhai_fn(return_raw)]
                    pub fn push_opt(
                        msg: &mut Message<Bytes>,
                        mut opt: OptRecordsIter,
                        data: AllOptData<Bytes>,
                    ) -> Result<(), Box<EvalAltResult>> {
                        opt.0.push(data);
                        update_opt(msg, opt)
                    }

                    #[rhai_fn(return_raw)]
                    pub fn insert_opt(
                        msg: &mut Message<Bytes>,
                        mut opt: OptRecordsIter,
                        index: i32,
                        data: AllOptData<Bytes>,
                    ) -> Result<(), Box<EvalAltResult>> {
                        opt.0.insert(index as usize, data);
                        update_opt(msg, opt)
                    }

                    #[rhai_fn(return_raw)]
                    pub fn remove_opt(
                        msg: &mut Message<Bytes>,
                        mut opt: OptRecordsIter,
                        index: i32,
                    ) -> Result<(), Box<EvalAltResult>> {
                        opt.0.remove(index as usize);
                        update_opt(msg, opt)
                    }

                    pub mod options {
                        pub mod client_subnet {
                            use domain::base::opt::{AllOptData, ClientSubnet};
                            use rhai::{EvalAltResult, ImmutableString};
                            use std::net::IpAddr;

                            use crate::IntoEvalAltResultError;

                            pub fn create_client_subnet(
                                source: i32,
                                scope: i32,
                                addr: IpAddr,
                            ) -> AllOptData<Bytes> {
                                AllOptData::ClientSubnet(ClientSubnet::new(
                                    source as u8,
                                    scope as u8,
                                    addr,
                                ))
                            }

                            #[rhai_fn(name = "create_client_subnet", return_raw)]
                            pub fn create_client_subnet_str(
                                source: i32,
                                scope: i32,
                                addr: ImmutableString,
                            ) -> Result<AllOptData<Bytes>, Box<EvalAltResult>>
                            {
                                Ok(create_client_subnet(
                                    source,
                                    scope,
                                    addr.parse().into_evalrst_err()?,
                                ))
                            }
                        }
                    }
                }
            }
        }

        pub mod answer {
            use bytes::Bytes;
            use domain::base::Message;
            use rhai::EvalAltResult;

            use crate::{
                router::script::message::{
                    helpers::{modify_message, SectionPayload},
                    rhai_mod::getters::get_answer,
                    DnsRecord, DnsRecordsIter,
                },
                IntoEvalAltResultError,
            };

            #[rhai_fn(return_raw)]
            pub fn update_answer(
                msg: &mut Message<Bytes>,
                records: DnsRecordsIter,
            ) -> Result<(), Box<EvalAltResult>> {
                *msg = modify_message(msg, SectionPayload::Answer(records)).into_evalrst_err()?;
                Ok(())
            }

            #[rhai_fn(return_raw)]
            pub fn insert_answer(
                msg: &mut Message<Bytes>,
                index: i32,
                record: DnsRecord,
            ) -> Result<(), Box<EvalAltResult>> {
                let mut records = get_answer(msg)?;
                records.0.insert(index as usize, record);
                update_answer(msg, records)
            }

            #[rhai_fn(return_raw)]
            pub fn push_answer(
                msg: &mut Message<Bytes>,
                record: DnsRecord,
            ) -> Result<(), Box<EvalAltResult>> {
                let mut records = get_answer(msg)?;
                records.0.push(record);
                update_answer(msg, records)
            }

            #[rhai_fn(return_raw)]
            pub fn remove_answer(
                msg: &mut Message<Bytes>,
                index: i32,
            ) -> Result<(), Box<EvalAltResult>> {
                let mut records = get_answer(msg)?;
                records.0.remove(index as usize);
                update_answer(msg, records)
            }
        }

        pub mod authority {
            use crate::{
                router::script::message::{
                    helpers::{modify_message, SectionPayload},
                    rhai_mod::getters::get_authority,
                    DnsRecord, DnsRecordsIter,
                },
                IntoEvalAltResultError,
            };
            use bytes::Bytes;
            use domain::base::Message;
            use rhai::EvalAltResult;

            #[rhai_fn(return_raw)]
            pub fn update_authority(
                msg: &mut Message<Bytes>,
                records: DnsRecordsIter,
            ) -> Result<(), Box<EvalAltResult>> {
                *msg =
                    modify_message(msg, SectionPayload::Authority(records)).into_evalrst_err()?;
                Ok(())
            }

            #[rhai_fn(return_raw)]
            pub fn insert_authority(
                msg: &mut Message<Bytes>,
                index: i32,
                record: DnsRecord,
            ) -> Result<(), Box<EvalAltResult>> {
                let mut records = get_authority(msg)?;
                records.0.insert(index as usize, record);
                update_authority(msg, records)
            }

            #[rhai_fn(return_raw)]
            pub fn push_authority(
                msg: &mut Message<Bytes>,
                record: DnsRecord,
            ) -> Result<(), Box<EvalAltResult>> {
                let mut records = get_authority(msg)?;
                records.0.push(record);
                update_authority(msg, records)
            }

            #[rhai_fn(return_raw)]
            pub fn remove_authority(
                msg: &mut Message<Bytes>,
                index: i32,
            ) -> Result<(), Box<EvalAltResult>> {
                let mut records = get_authority(msg)?;
                records.0.remove(index as usize);
                update_authority(msg, records)
            }
        }

        pub mod additional {
            use crate::{
                router::script::message::{
                    helpers::{modify_message, SectionPayload},
                    rhai_mod::getters::get_additional,
                    DnsRecord, DnsRecordsIter,
                },
                IntoEvalAltResultError,
            };
            use bytes::Bytes;
            use domain::base::Message;
            use rhai::EvalAltResult;

            #[rhai_fn(return_raw)]
            pub fn update_additional(
                msg: &mut Message<Bytes>,
                records: DnsRecordsIter,
            ) -> Result<(), Box<EvalAltResult>> {
                *msg =
                    modify_message(msg, SectionPayload::Additional(records)).into_evalrst_err()?;
                Ok(())
            }

            #[rhai_fn(return_raw)]
            pub fn insert_additional(
                msg: &mut Message<Bytes>,
                index: i32,
                record: DnsRecord,
            ) -> Result<(), Box<EvalAltResult>> {
                let mut records = get_additional(msg)?;
                records.0.insert(index as usize, record);
                update_additional(msg, records)
            }

            #[rhai_fn(return_raw)]
            pub fn push_additional(
                msg: &mut Message<Bytes>,
                record: DnsRecord,
            ) -> Result<(), Box<EvalAltResult>> {
                let mut records = get_additional(msg)?;
                records.0.push(record);
                update_additional(msg, records)
            }

            #[rhai_fn(return_raw)]
            pub fn remove_additional(
                msg: &mut Message<Bytes>,
                index: i32,
            ) -> Result<(), Box<EvalAltResult>> {
                let mut records = get_additional(msg)?;
                records.0.remove(index as usize);
                update_additional(msg, records)
            }
        }
    }
}
