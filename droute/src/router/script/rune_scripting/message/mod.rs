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

pub mod helper;

use super::types::*;
use crate::errors::{MessageError, ScriptError};
use bytes::Bytes;
use domain::base::ToDname;
use helper::{DnsRecordsIter, OptRecordsIter};
use once_cell::sync::Lazy;
use paste::paste;
use rune::{
    runtime::{Key, Protocol, TypeOf, VmError, VmErrorKind},
    Module,
};

macro_rules! create_indexers {
    ($iter: ty, $val: ty, $m: ident) => {
        $m.inst_fn(
            Protocol::INDEX_GET,
            |iter: &mut $iter, index: Key| -> Result<$val, VmError> {
                let index_int = match index {
                    Key::Integer(i) => i as usize,
                    _ => {
                        return Err(VmError::from(VmErrorKind::UnsupportedIndexGet {
                            target: <$iter>::type_info(),
                            index: index.type_info(),
                        }))
                    }
                };

                Ok(iter
                    .0
                    .get(index_int)
                    .ok_or_else(|| {
                        VmError::from(VmErrorKind::MissingIndexKey {
                            target: <$iter>::type_info(),
                            index,
                        })
                    })?
                    .into())
            },
        )
        .unwrap();

        $m.inst_fn(
            Protocol::INDEX_SET,
            |iter: &mut $iter, index: Key, record: $val| -> Result<(), VmError> {
                let index_int = match index {
                    Key::Integer(i) => i as usize,
                    _ => {
                        return Err(VmError::from(VmErrorKind::UnsupportedIndexGet {
                            target: <$iter>::type_info(),
                            index: index.type_info(),
                        }))
                    }
                };

                if let Some(r) = iter.0.get_mut(index_int) {
                    *r = record.into();
                    Ok(())
                } else {
                    Err(VmError::from(VmErrorKind::MissingIndexKey {
                        target: <$iter>::type_info(),
                        index,
                    }))
                }
            },
        )
        .unwrap();
    };
}

macro_rules! create_record_downcast {
    ($orig: ty, $final: ty, $path: path, $err: path, $m: ident) => {
        $m.inst_fn(
            paste! { stringify!([<to_ $final:lower>]) },
            |record: &$orig| -> Result<$final, ScriptError> {
                match record.0.data() {
                    $path(s) => Ok(s.clone().into()),
                    _ => Err($err.into()),
                }
            },
        )
        .unwrap();

        $m.inst_fn("to_rdata", |data: $final| -> DnsRecordData {
            DnsRecordData($path(data.0))
        })
        .unwrap();
    };
}

macro_rules! create_option_downcast {
    ($orig: ty, $final: ty, $path: path, $err: path, $m: ident) => {
        $m.inst_fn(
            paste! { stringify!([<to_ $final:lower>]) },
            |record: &$orig| -> Result<$final, ScriptError> {
                match record.0 {
                    $path(s) => Ok(s.clone().into()),
                    _ => Err($err.into()),
                }
            },
        )
        .unwrap();

        $m.inst_fn("to_opt_data", |data: $final| -> AllOptData {
            AllOptData($path(data.0))
        })
        .unwrap();
    };
}

#[rustfmt::skip]
macro_rules! create_record_iter_impl {
    ($name: ident, $m: ident) => {
        paste! {
            fn [<get_ $name>](msg: &Message) -> Result<DnsRecordsIter, ScriptError> {
                use domain::{base::ParsedDname, rdata::AllRecordData};
		use bytes::Bytes;

                let $name = msg.0
		    .$name()
		    .map_err(|e| {let e: MessageError = e.into(); e})?
		    .limit_to::<AllRecordData<Bytes, ParsedDname<&Bytes>>>();

                let mut inner = Vec::new();
                for record in $name {
		    // We don't abort on error, we simply skip them. Therefore, we cannot use Try operators
		    if let Ok(record) = record {
                        if let Ok(data) = helper::dns_record_from_ref(record.data().clone()) {
			    inner.push(
                                (
				    record.owner().to_dname().map_err(|e| {let e: MessageError = e.into(); e})?,
				    record.class(),
				    record.ttl(),
				    data,
                                )
                                    .into());
                        }
		    }
                }
                Ok(DnsRecordsIter(inner))
            }

            $m.field_fn(Protocol::GET, stringify!($name), [<get_ $name>]).unwrap();
        }
    };
}

macro_rules! create_section_kit {
    ($name: ident, $m: ident) => {
	use helper::{modify_message, SectionPayload};

        paste! {
	    fn [<update_ $name>](msg: &mut Message, records: DnsRecordsIter) -> Result<(), ScriptError> {
		*msg = modify_message(&msg.0, SectionPayload::[<$name:camel>](records))?.into();
                Ok(())
	    }

            $m.inst_fn(stringify!([<update_ $name >]), [<update_ $name>]).unwrap();
	    $m.inst_fn(stringify!([<clear_ $name>]), |msg: &mut Message| [<update_ $name>](msg, DnsRecordsIter(Vec::new()))).unwrap();
	    $m.inst_fn(stringify!([<insert_ $name>]), |msg: &mut Message, index: usize, record: DnsRecord| {
		let mut records = [<get_ $name>](msg)?;
                records.0.insert(index, record.0);
		[<update_ $name>](msg, DnsRecordsIter(Vec::new()))
	    }).unwrap();
	    $m.inst_fn(stringify!([<push_ $name>]), |msg: &mut Message, record: DnsRecord| {
		let mut records = [<get_ $name>](msg)?;
                records.0.push(record.0);
		[<update_ $name>](msg, DnsRecordsIter(Vec::new()))
	    }).unwrap();
	    $m.inst_fn(stringify!([<remove_ $name>]), |msg: &mut Message, index: usize| {
		let mut records = [<get_ $name>](msg)?;
                records.0.remove(index);
		[<update_ $name>](msg, DnsRecordsIter(Vec::new()))
	    }).unwrap();
        }
    };
}

macro_rules! create_header_bit_kit {
    ($name: ident, $m: ident) => {
        $m.field_fn(Protocol::GET, stringify!($name), |header: &Header| {
            header.0.$name()
        })
        .unwrap();
        paste! {
            $m.field_fn(Protocol::SET, stringify!($name), |header: &mut Header, $name: bool| {
                header.0.[<set_ $name>]($name)
            })
            .unwrap();
        }
    };
}

pub static MSG_MODULE: Lazy<Module> = Lazy::new(|| {
    let mut m = Module::new();

    // Indexers & iterators
    {
        create_indexers!(DnsRecordsIter, DnsRecord, m);
        create_indexers!(OptRecordsIter, AllOptData, m);
    }

    // Sections and iterators
    {
        m.field_fn(Protocol::GET, "header", |msg: &Message| -> Header {
            msg.0.header().into()
        })
        .unwrap();

        // Header
        {
            create_header_bit_kit!(aa, m);
            create_header_bit_kit!(ad, m);
            create_header_bit_kit!(cd, m);
            m.field_fn(Protocol::GET, "id", |header: &Header| header.0.aa())
                .unwrap();
            m.field_fn(Protocol::SET, "id", |header: &mut Header, id: u16| {
                header.0.set_id(id)
            })
            .unwrap();
            create_header_bit_kit!(qr, m);
            create_header_bit_kit!(ra, m);
            create_header_bit_kit!(tc, m);
            create_header_bit_kit!(z, m);
            create_header_bit_kit!(rd, m);
            m.field_fn(Protocol::GET, "rcode", |header: &Header| -> Rcode {
                header.0.rcode().into()
            })
            .unwrap();
            m.field_fn(
                Protocol::SET,
                "rcode",
                |header: &mut Header, rcode: Rcode| header.0.set_rcode(rcode.0),
            )
            .unwrap();

            m.field_fn(Protocol::GET, "opcode", |header: &Header| -> Opcode {
                header.0.opcode().into()
            })
            .unwrap();
            m.field_fn(
                Protocol::SET,
                "opcode",
                |header: &mut Header, opcode: Opcode| header.0.set_opcode(opcode.0),
            )
            .unwrap();
        }

        // Questions
        {
            m.field_fn(
                Protocol::GET,
                "first_question",
                |msg: &Message| -> Result<Question, ScriptError> {
                    let q = msg
                        .0
                        .first_question()
                        .ok_or_else::<ScriptError, _>(|| MessageError::NoFirstQuestion.into())?;
                    Ok(domain::base::question::Question::new(
                        q.qname().to_dname().map_err(|e| {
                            let e: MessageError = e.into();
                            e
                        })?,
                        q.qtype(),
                        q.qclass(),
                    )
                    .into())
                },
            )
            .unwrap();

            m.field_fn(Protocol::GET, "qname", |q: &Question| -> Dname {
                q.0.qname().clone().into()
            })
            .unwrap();

            m.field_fn(Protocol::GET, "qtype", |q: &Question| -> Rtype {
                q.0.qtype().into()
            })
            .unwrap();

            m.field_fn(Protocol::GET, "qclass", |q: &Question| -> Class {
                q.0.qclass().into()
            })
            .unwrap();
        }

        // Answer Section
        {
            create_record_iter_impl!(answer, m);
            create_section_kit!(answer, m);
        }

        // Additional Section
        {
            create_record_iter_impl!(additional, m);
            create_section_kit!(additional, m);

            // OPT-pseudosection meta-record
            // OptRecord includes all the options (represented by AllOptData) and some metadata like DNSSEC, UDP payload len, etc.
            {
                fn get_options(data: &mut OptRecord) -> Result<OptRecordsIter, ScriptError> {
                    Ok(OptRecordsIter(
                        data.0
                            .iter()
                            .collect::<Result<Vec<domain::base::opt::AllOptData<Bytes>>, _>>()
                            .map_err(|e| {
                                let e: MessageError = e.into();
                                e
                            })?,
                    ))
                }

                fn to_opt(record: &DnsRecord) -> Result<OptRecord, ScriptError> {
                    let opt: Result<_, ScriptError> = match record.0.data() {
                        domain::rdata::AllRecordData::Opt(s) => Ok(s.clone()),
                        _ => Err(MessageError::RecordUnsupported.into()),
                    };
                    Ok(OptRecord(domain::base::opt::OptRecord::from_record(
                        domain::base::Record::new(
                            record.0.owner().clone(),
                            record.0.class(),
                            record.0.ttl(),
                            opt?,
                        ),
                    )))
                }

                fn get_options_from_msg(msg: &Message) -> Result<OptRecordsIter, ScriptError> {
                    for record in get_additional(msg)?.into_iter() {
                        if record.0.rtype() == domain::base::iana::rtype::Rtype::Opt {
                            return get_options(&mut to_opt(&record)?);
                        }
                    }
                    Ok(OptRecordsIter(Vec::new()))
                }

                m.field_fn(Protocol::GET, "options", get_options_from_msg)
                    .unwrap();

                m.field_fn(
                    Protocol::GET,
                    "opt_section",
                    |msg: &Message| -> Result<Option<OptRecord>, ScriptError> {
                        for record in get_additional(msg)?.into_iter() {
                            if record.0.rtype() == domain::base::iana::rtype::Rtype::Opt {
                                return Ok(Some(to_opt(&record)?));
                            }
                        }
                        Ok(None)
                    },
                )
                .unwrap();

                m.field_fn(Protocol::GET, "udp_payload_size", |data: &OptRecord| {
                    data.0.udp_payload_size()
                })
                .unwrap();

                m.field_fn(Protocol::GET, "version", |data: &OptRecord| {
                    data.0.version()
                })
                .unwrap();

                m.field_fn(
                    Protocol::GET,
                    "rcode",
                    |data: &OptRecord, header: Header| -> OptRcode {
                        data.0.rcode(header.0).into()
                    },
                )
                .unwrap();

                m.field_fn(Protocol::GET, "dnssec_ok", |data: &OptRecord| {
                    data.0.dnssec_ok()
                })
                .unwrap();

                m.inst_fn(
                    "get_opt_rtype",
                    |data: &AllOptData| -> Result<String, ScriptError> {
                        Ok(match data.0 {
                            domain::base::opt::AllOptData::Chain(_) => "CHAIN",
                            domain::base::opt::AllOptData::ClientSubnet(_) => "CLIENT_SUBNET",
                            domain::base::opt::AllOptData::Cookie(_) => "COOKIE",
                            domain::base::opt::AllOptData::Dau(_) => "DAU",
                            domain::base::opt::AllOptData::Dhu(_) => "DHU",
                            domain::base::opt::AllOptData::Expire(_) => "EXPIRE",
                            domain::base::opt::AllOptData::ExtendedError(_) => "EXTENDED_ERROR",
                            domain::base::opt::AllOptData::KeyTag(_) => "KEY_TAG",
                            domain::base::opt::AllOptData::N3u(_) => "N3U",
                            domain::base::opt::AllOptData::Nsid(_) => "NSID",
                            domain::base::opt::AllOptData::Other(_) => "OTHER",
                            domain::base::opt::AllOptData::Padding(_) => "PADDING",
                            domain::base::opt::AllOptData::TcpKeepalive(_) => "TCP_KEEPALIVE",
                            _ => return Err(MessageError::OptionUnsupported.into()),
                        }
                        .into())
                    },
                )
                .unwrap();

                fn update_opt(msg: &mut Message, opt: OptRecordsIter) -> Result<(), ScriptError> {
                    *msg = helper::modify_opt(&msg.0, Some(opt))?.into();
                    Ok(())
                }

                m.inst_fn("update_opt", update_opt).unwrap();
                m.inst_fn(
                    "clear_opt",
                    |msg: &mut Message| -> Result<(), ScriptError> {
                        *msg = helper::modify_opt(&msg.0, None)?.into();
                        Ok(())
                    },
                )
                .unwrap();
                m.inst_fn(
                    "push_opt",
                    |msg: &mut Message, data: AllOptData| -> Result<(), ScriptError> {
                        let mut opt = get_options_from_msg(msg)?;
                        opt.0.push(data.0);
                        update_opt(msg, opt)
                    },
                )
                .unwrap();
                m.inst_fn(
                    "insert_opt",
                    |msg: &mut Message,
                     index: usize,
                     data: AllOptData|
                     -> Result<(), ScriptError> {
                        let mut opt = get_options_from_msg(msg)?;
                        opt.0.insert(index, data.0);
                        update_opt(msg, opt)
                    },
                )
                .unwrap();
                m.inst_fn(
                    "remove_opt",
                    |msg: &mut Message, index: usize| -> Result<(), ScriptError> {
                        let mut opt = get_options_from_msg(msg)?;
                        opt.0.remove(index);
                        update_opt(msg, opt)
                    },
                )
                .unwrap();
            }
        }

        // Authority Section
        {
            create_record_iter_impl!(authority, m);
            create_section_kit!(authority, m);
        }
    }

    // Record and Option types
    {
        m.function(
            &["DnsRecord", "new"],
            |owner: Dname, class: Class, ttl: u32, data: DnsRecordData| -> DnsRecord {
                DnsRecord(domain::base::Record::new(owner.0, class.0, ttl, data.0))
            },
        )
        .unwrap();

        m.field_fn(Protocol::GET, "owner", |record: &DnsRecord| -> Dname {
            record.0.owner().clone().into()
        })
        .unwrap();

        m.field_fn(Protocol::GET, "rtype", |record: &DnsRecord| -> Rtype {
            record.0.rtype().into()
        })
        .unwrap();

        m.field_fn(Protocol::GET, "class", |record: &DnsRecord| -> Class {
            record.0.class().into()
        })
        .unwrap();

        m.field_fn(
            Protocol::SET,
            "class",
            |record: &mut DnsRecord, class: Class| record.0.set_class(class.0),
        )
        .unwrap();

        m.field_fn(Protocol::GET, "ttl", |record: &DnsRecord| -> u32 {
            record.0.ttl()
        })
        .unwrap();

        m.field_fn(Protocol::SET, "ttl", |record: &mut DnsRecord, ttl: u32| {
            record.0.set_ttl(ttl)
        })
        .unwrap();

        // A
        {
            create_record_downcast!(
                DnsRecord,
                A,
                domain::rdata::AllRecordData::A,
                MessageError::RecordUnsupported,
                // "to_a",
                m
            );

            m.function(&["A", "new"], |addr: IpAddr| -> Result<A, ScriptError> {
                match addr.0 {
                    std::net::IpAddr::V4(addr) => Ok(domain::rdata::A::new(addr).into()),
                    _ => Err(MessageError::InvalidIpAddrType(addr.0).into()),
                }
            })
            .unwrap();

            m.field_fn(Protocol::GET, "ip", |data: &mut A| -> IpAddr {
                let addr: std::net::IpAddr = data.0.addr().into();
                addr.into()
            })
            .unwrap();

            m.field_fn(
                Protocol::SET,
                "ip",
                |data: &mut A, addr: &IpAddr| -> Result<(), ScriptError> {
                    match addr.0 {
                        std::net::IpAddr::V4(addr) => {
                            data.0.set_addr(addr);
                            Ok(())
                        }
                        _ => Err(MessageError::InvalidIpAddrType(addr.0).into()),
                    }
                },
            )
            .unwrap();
        }

        // AAAA
        {
            create_record_downcast!(
                DnsRecord,
                Aaaa,
                domain::rdata::AllRecordData::Aaaa,
                MessageError::RecordUnsupported,
                m
            );

            m.function(
                &["Aaaa", "new"],
                |addr: IpAddr| -> Result<Aaaa, ScriptError> {
                    match addr.0 {
                        std::net::IpAddr::V6(addr) => Ok(domain::rdata::Aaaa::new(addr).into()),
                        _ => Err(MessageError::InvalidIpAddrType(addr.0).into()),
                    }
                },
            )
            .unwrap();

            m.field_fn(Protocol::GET, "ip", |data: &Aaaa| -> IpAddr {
                let addr: std::net::IpAddr = data.0.addr().into();
                addr.into()
            })
            .unwrap();

            m.field_fn(
                Protocol::SET,
                "ip",
                |data: &mut Aaaa, addr: &IpAddr| -> Result<(), ScriptError> {
                    match addr.0 {
                        std::net::IpAddr::V6(addr) => {
                            data.0.set_addr(addr);
                            Ok(())
                        }
                        _ => Err(MessageError::InvalidIpAddrType(addr.0).into()),
                    }
                },
            )
            .unwrap();
        }

        // Cname
        {
            create_record_downcast!(
                DnsRecord,
                Cname,
                domain::rdata::AllRecordData::Cname,
                MessageError::RecordUnsupported,
                m
            );

            m.field_fn(Protocol::GET, "cname", |data: &Cname| -> Dname {
                data.0.cname().clone().into()
            })
            .unwrap();

            m.function(&["Cname", "new"], |cname: Dname| -> Cname {
                domain::rdata::Cname::new(cname.0).into()
            })
            .unwrap();
        }

        // Txt
        {
            create_record_downcast!(
                DnsRecord,
                Txt,
                domain::rdata::AllRecordData::Txt,
                MessageError::RecordUnsupported,
                m
            );

            m.field_fn(
                Protocol::GET,
                "txt",
                |data: &Txt| -> Result<String, ScriptError> {
                    // If the length of slice agrees with length indicated in the record header, it returns Some
                    data.0
                        .as_flat_slice()
                        .map(|v| {
                            String::from_utf8(v.to_vec())
                                .map_err(|e| ScriptError::MessageError(e.into()))
                        })
                        .unwrap_or_else(|| Ok("".to_string()))
                },
            )
            .unwrap();

            m.function(&["Txt", "new"], |text: &str| -> Result<Txt, ScriptError> {
                Ok(domain::rdata::Txt::from_slice(text.as_bytes())?.into())
            })
            .unwrap();
        }

        // Cookie
        {
            create_option_downcast!(
                AllOptData,
                Cookie,
                domain::base::opt::AllOptData::Cookie,
                MessageError::OptionUnsupported,
                m
            );

            m.inst_fn("to_str", |cookie: &Cookie| -> String {
                hex::encode(cookie.0.cookie())
            })
            .unwrap();
        }

        // ClientSubnet
        {
            create_option_downcast!(
                AllOptData,
                ClientSubnet,
                domain::base::opt::AllOptData::ClientSubnet,
                MessageError::OptionUnsupported,
                m
            );

            m.function(
                &["ClientSubnet", "new"],
                |source: u8, scope: u8, addr: IpAddr| -> ClientSubnet {
                    domain::base::opt::ClientSubnet::new(source, scope, addr.0).into()
                },
            )
            .unwrap();

            m.field_fn(
                Protocol::GET,
                "addr",
                |client_subnet: &ClientSubnet| -> IpAddr { client_subnet.0.addr().into() },
            )
            .unwrap();

            m.field_fn(
                Protocol::GET,
                "source_prefix_len",
                |client_subnet: &ClientSubnet| -> u8 { client_subnet.0.source_prefix_len() },
            )
            .unwrap();

            m.field_fn(
                Protocol::GET,
                "scope_prefix_len",
                |client_subnet: &ClientSubnet| -> u8 { client_subnet.0.scope_prefix_len() },
            )
            .unwrap();
        }
    }

    m
});
