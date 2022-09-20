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

use super::types::*;
use crate::{
    errors::ScriptError,
    utils::{blackhole, Domain, GeoIp, IpCidr},
};
use once_cell::sync::Lazy;
use rune::Module;
use std::sync::Arc;

#[derive(rune::Any, Clone)]
pub enum Utils {
    #[rune(constructor)]
    Domain(#[rune(get)] SealedDomain),
    #[rune(constructor)]
    GeoIp(#[rune(get)] SealedGeoIp),
    #[rune(constructor)]
    IpCidr(#[rune(get)] SealedIpCidr),
}

#[derive(rune::Any, Clone)]
pub struct SealedDomain(Arc<Domain>);

#[derive(rune::Any, Clone)]
pub struct SealedGeoIp(Arc<GeoIp>);

#[derive(rune::Any, Clone)]
pub struct SealedIpCidr(Arc<IpCidr>);

pub static UTILS_MODULE: Lazy<Module> = Lazy::new(|| {
    let mut m = Module::new();

    m.ty::<Utils>().unwrap();

    // Blackhole
    {
        m.function(
            &["blackhole"],
            |msg: &Message| -> Result<Message, ScriptError> { Ok(blackhole(&msg.into())?.into()) },
        )
        .unwrap();
    }

    // Domain list
    {
        m.ty::<Domain>().unwrap();
        m.ty::<SealedDomain>().unwrap();

        m.function(&["Domain", "new"], Domain::new).unwrap();
        m.inst_fn(
            "add_qname",
            |mut domain: Domain, qname: &str| -> Result<Domain, ScriptError> {
                domain.add_qname(qname)?;
                Ok(domain)
            },
        )
        .unwrap();
        m.inst_fn(
            "add_file",
            |mut domain: Domain, path: &str| -> Result<Domain, ScriptError> {
                domain.add_file(path)?;
                Ok(domain)
            },
        )
        .unwrap();

        m.inst_fn("seal", |domain: Domain| -> SealedDomain {
            SealedDomain(Arc::new(domain))
        })
        .unwrap();

        m.inst_fn("contains", |domain: &SealedDomain, qname: &Dname| -> bool {
            domain.0.contains(&qname.into())
        })
        .unwrap();
    }

    // GeoIP
    {
        m.ty::<GeoIp>().unwrap();
        m.ty::<SealedGeoIp>().unwrap();

        m.function(
            &["GeoIp", "create_default"],
            || -> Result<SealedGeoIp, ScriptError> {
                Ok(SealedGeoIp(Arc::new(GeoIp::create_default()?)))
            },
        )
        .unwrap();

        async fn geoip_from_path(path: &str) -> Result<SealedGeoIp, ScriptError> {
            Ok(SealedGeoIp(Arc::new(GeoIp::from_path(path).await?)))
        }

        m.async_function(&["GeoIp", "from_path"], geoip_from_path)
            .unwrap();

        m.inst_fn(
            "contains",
            |geoip: &SealedGeoIp, ip: &IpAddr, code: &str| -> bool {
                geoip.0.contains(ip.into(), code)
            },
        )
        .unwrap();
    }

    // IP CIDR
    {
        m.ty::<IpCidr>().unwrap();
        m.ty::<SealedIpCidr>().unwrap();

        m.function(&["IpCidr", "new"], IpCidr::new).unwrap();
        m.inst_fn(
            "add_file",
            |mut ipcidr: IpCidr, path: &str| -> Result<IpCidr, ScriptError> {
                ipcidr.add_file(path)?;
                Ok(ipcidr)
            },
        )
        .unwrap();

        m.inst_fn("seal", |cidr: IpCidr| -> SealedIpCidr {
            SealedIpCidr(Arc::new(cidr))
        })
        .unwrap();

        m.inst_fn("contains", |ipcidr: &SealedIpCidr, ip: &IpAddr| -> bool {
            ipcidr.0.contains(ip.into())
        })
        .unwrap();
    }

    m
});
