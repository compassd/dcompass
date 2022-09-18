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

#[derive(rune::Any, Clone)]
pub enum Utils {
    #[rune(constructor)]
    Domain(#[rune(get)] Domain),
    #[rune(constructor)]
    GeoIp(#[rune(get)] GeoIp),
    #[rune(constructor)]
    IpCidr(#[rune(get)] IpCidr),
}

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
        m.function(&["Domain", "new"], Domain::new).unwrap();
        m.inst_fn(
            "add_qname",
            |domain: &mut Domain, qname: &str| -> Result<(), ScriptError> {
                Ok(domain.add_qname(qname)?)
            },
        )
        .unwrap();
        m.inst_fn(
            "add_file",
            |domain: &mut Domain, path: &str| -> Result<(), ScriptError> {
                Ok(domain.add_file(path)?)
            },
        )
        .unwrap();
        m.inst_fn("contains", |domain: &mut Domain, qname: &Dname| -> bool {
            domain.contains(&qname.into())
        })
        .unwrap();
    }

    // GeoIP
    {
        m.ty::<GeoIp>().unwrap();

        m.function(
            &["GeoIp", "create_default"],
            || -> Result<GeoIp, ScriptError> { Ok(GeoIp::create_default()?) },
        )
        .unwrap();

        async fn geoip_from_path(path: &str) -> Result<GeoIp, ScriptError> {
            Ok(GeoIp::from_path(path).await?)
        }

        m.async_function(&["GeoIp", "from_path"], geoip_from_path)
            .unwrap();

        m.inst_fn(
            "contains",
            |geoip: &GeoIp, ip: &IpAddr, code: &str| -> bool { geoip.contains(ip.into(), code) },
        )
        .unwrap();
    }

    // IP CIDR
    {
        m.ty::<IpCidr>().unwrap();

        m.function(&["IpCidr", "new"], IpCidr::new).unwrap();
        m.inst_fn(
            "add_file",
            |ipcidr: &mut IpCidr, path: &str| -> Result<(), ScriptError> {
                ipcidr.add_file(path)?;
                Ok(())
            },
        )
        .unwrap();

        m.inst_fn("contains", |ipcidr: &IpCidr, ip: &IpAddr| -> bool {
            ipcidr.contains(ip.into())
        })
        .unwrap();
    }

    m
});
