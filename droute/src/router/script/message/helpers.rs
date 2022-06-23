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

use super::{MessageError, MessageResult as Result};
use bytes::{Bytes, BytesMut};
use domain::{
    base::{opt::AllOptData, Dname, Message, MessageBuilder, ParsedDname, Record, ToDname},
    rdata::{
        AllRecordData, Cname, Dname as DnameRecord, Mb, Md, Mf, Minfo, Mr, Mx, Ns, Nsec, Ptr,
        Rrsig, Soa, Srv, Tsig,
    },
};

pub type DnsRecord = Record<Dname<Bytes>, AllRecordData<Bytes, Dname<Bytes>>>;

pub(super) fn dns_record_from_ref(
    src: AllRecordData<Bytes, ParsedDname<&Bytes>>,
) -> Result<AllRecordData<Bytes, Dname<Bytes>>> {
    Ok(match src {
        AllRecordData::A(a) => a.into(),
        AllRecordData::Aaaa(aaaa) => aaaa.into(),
        AllRecordData::Cdnskey(cdnskey) => cdnskey.into(),
        AllRecordData::Cds(cds) => cds.into(),
        AllRecordData::Cname(cname) => AllRecordData::Cname(Cname::new(cname.cname().to_dname()?)),
        AllRecordData::Dname(dname) => {
            AllRecordData::Dname(DnameRecord::new(dname.dname().to_dname()?))
        }
        AllRecordData::Dnskey(dnskey) => dnskey.into(),
        AllRecordData::Ds(ds) => ds.into(),
        AllRecordData::Hinfo(hinfo) => hinfo.into(),
        AllRecordData::Mb(mb) => AllRecordData::Mb(Mb::new(mb.madname().to_dname()?)),
        AllRecordData::Md(md) => AllRecordData::Md(Md::new(md.madname().to_dname()?)),
        AllRecordData::Mf(mf) => AllRecordData::Mf(Mf::new(mf.madname().to_dname()?)),
        AllRecordData::Minfo(minfo) => {
            Minfo::new(minfo.rmailbx().to_dname()?, minfo.emailbx().to_dname()?).into()
        }
        AllRecordData::Mr(mr) => AllRecordData::Mr(Mr::new(mr.newname().to_dname()?)),
        AllRecordData::Mx(mx) => {
            AllRecordData::Mx(Mx::new(mx.preference(), mx.exchange().to_dname()?))
        }
        AllRecordData::Ns(ns) => AllRecordData::Ns(Ns::new(ns.nsdname().to_dname()?)),
        AllRecordData::Nsec(nsec) => AllRecordData::Nsec(Nsec::new(
            nsec.next_name().to_dname()?,
            nsec.types().clone(),
        )),
        AllRecordData::Nsec3(nsec3) => nsec3.into(),
        AllRecordData::Nsec3param(nsec3param) => nsec3param.into(),
        AllRecordData::Null(null) => null.into(),
        AllRecordData::Opt(opt) => opt.into(),
        AllRecordData::Other(other) => other.into(),
        AllRecordData::Ptr(ptr) => AllRecordData::Ptr(Ptr::new(ptr.ptrdname().to_dname()?)),
        AllRecordData::Rrsig(rrsig) => AllRecordData::Rrsig(Rrsig::new(
            rrsig.type_covered(),
            rrsig.algorithm(),
            rrsig.labels(),
            rrsig.original_ttl(),
            rrsig.expiration(),
            rrsig.inception(),
            rrsig.key_tag(),
            rrsig.signer_name().to_dname()?,
            rrsig.signature().clone(),
        )),
        AllRecordData::Srv(srv) => AllRecordData::Srv(Srv::new(
            srv.priority(),
            srv.weight(),
            srv.port(),
            srv.target().to_dname()?,
        )),
        AllRecordData::Tsig(tsig) => AllRecordData::Tsig(Tsig::new(
            tsig.algorithm().to_dname()?,
            tsig.time_signed(),
            tsig.fudge(),
            tsig.mac().clone(),
            tsig.original_id(),
            tsig.error(),
            tsig.other().clone(),
        )),
        AllRecordData::Txt(txt) => txt.into(),
        AllRecordData::Soa(soa) => Soa::new(
            soa.mname().to_dname()?,
            soa.rname().to_dname()?,
            soa.serial(),
            soa.refresh(),
            soa.retry(),
            soa.expire(),
            soa.minimum(),
        )
        .into(),
        _ => return Err(MessageError::RecordUnsupported),
    })
}

// An iterator over records
#[derive(Clone)]
pub struct DnsRecordsIter(pub Vec<DnsRecord>);

impl IntoIterator for DnsRecordsIter {
    type Item = DnsRecord;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

// An iterator over Opt records
#[derive(Clone)]
pub struct OptRecordsIter(pub Vec<AllOptData<Bytes>>);

impl IntoIterator for OptRecordsIter {
    type Item = AllOptData<Bytes>;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

pub fn modify_opt(msg: &Message<Bytes>, opt: OptRecordsIter) -> Result<Message<Bytes>> {
    let mut builder = MessageBuilder::from_target(BytesMut::with_capacity(crate::MAX_LEN))?;
    // Copy header
    *builder.header_mut() = msg.header();

    // Copy questions
    let mut builder = builder.question();
    for item in msg.question().flatten() {
        builder.push(item)?;
    }

    // Copy answer and authority sections
    let mut builder = builder.answer();
    for item in msg.answer()? {
        if let Some(record) = item?.into_record::<AllRecordData<_, _>>()? {
            builder.push(record)?;
        }
    }

    let mut builder = builder.authority();
    for item in msg.authority()? {
        if let Some(record) = item?.into_record::<AllRecordData<_, _>>()? {
            builder.push(record)?;
        }
    }

    // Copy other additional records
    let mut builder = builder.additional();
    for item in msg.additional()? {
        if let Some(record) = item?.into_record::<AllRecordData<_, _>>()? {
            builder.push(record)?;
        }
    }

    // Build OPT record
    builder.opt(|builder| {
        for option in opt.into_iter() {
            builder.push(&option)?
        }
        Ok(())
    })?;

    Ok(builder.into_message())
}

pub enum SectionPayload {
    Answer(DnsRecordsIter),
    Additional(DnsRecordsIter),
    Authority(DnsRecordsIter),
}

pub fn modify_message(
    msg: &Message<Bytes>,
    section_modified: SectionPayload,
) -> Result<Message<Bytes>> {
    let mut builder = MessageBuilder::from_target(BytesMut::with_capacity(crate::MAX_LEN))?;
    // Copy header
    *builder.header_mut() = msg.header();

    match section_modified {
        SectionPayload::Answer(records) => {
            // Copy questions
            let mut builder = builder.question();
            for item in msg.question().flatten() {
                builder.push(item)?;
            }

            // Push the payload
            let mut builder = builder.answer();
            for item in records.into_iter() {
                builder.push(item)?;
            }

            // Copy authority and additional sections
            let mut builder = builder.authority();
            for item in msg.authority()? {
                if let Some(record) = item?.into_record::<AllRecordData<_, _>>()? {
                    builder.push(record)?;
                }
            }

            let mut builder = builder.additional();
            for item in msg.additional()? {
                if let Some(record) = item?.into_record::<AllRecordData<_, _>>()? {
                    builder.push(record)?;
                }
            }

            Ok(builder.into_message())
        }
        SectionPayload::Authority(records) => {
            // Copy questions
            let mut builder = builder.question();
            for item in msg.question().flatten() {
                builder.push(item)?;
            }

            // Copy answers
            let mut builder = builder.answer();
            for item in msg.answer()? {
                if let Some(record) = item?.into_record::<AllRecordData<_, _>>()? {
                    builder.push(record)?;
                }
            }

            // Push the payload
            let mut builder = builder.authority();
            for item in records.into_iter() {
                builder.push(item)?;
            }

            // Copy the additional section
            let mut builder = builder.additional();
            for item in msg.additional()? {
                if let Some(record) = item?.into_record::<AllRecordData<_, _>>()? {
                    builder.push(record)?;
                }
            }

            Ok(builder.into_message())
        }
        SectionPayload::Additional(records) => {
            // Copy questions
            let mut builder = builder.question();
            for item in msg.question().flatten() {
                builder.push(item)?;
            }

            // Copy answer and authority sections
            let mut builder = builder.answer();
            for item in msg.answer()? {
                if let Some(record) = item?.into_record::<AllRecordData<_, _>>()? {
                    builder.push(record)?;
                }
            }

            let mut builder = builder.authority();
            for item in msg.authority()? {
                if let Some(record) = item?.into_record::<AllRecordData<_, _>>()? {
                    builder.push(record)?;
                }
            }

            // Push the payload
            let mut builder = builder.additional();
            for item in records.into_iter() {
                builder.push(item)?;
            }

            Ok(builder.into_message())
        }
    }
}
