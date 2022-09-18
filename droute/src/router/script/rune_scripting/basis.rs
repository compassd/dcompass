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
use crate::{errors::ScriptError, CacheMode, QueryContext, Upstreams};
use once_cell::sync::Lazy;
use rune::{runtime::Protocol, Module};

// A module containing upstreams methods and query context
pub static BASIS_MODULE: Lazy<Module> = Lazy::new(|| {
    let mut m = Module::new();

    // Workaround on https://github.com/rune-rs/rune/issues/399
    m.function(&["u8"], |val: usize| val as u8).unwrap();

    async fn send_default(
        upstreams: &Upstreams,
        tag: &str,
        msg: &Message,
    ) -> Result<Message, ScriptError> {
        send(upstreams, tag, CacheMode::default(), msg).await
    }

    async fn send(
        upstreams: &Upstreams,
        tag: &str,
        cache_mode: CacheMode,
        msg: &Message,
    ) -> Result<Message, ScriptError> {
        Ok(upstreams
            .send(&tag.into(), &cache_mode, &msg.into())
            .await?
            .into())
    }

    m.ty::<Upstreams>().unwrap();
    m.async_inst_fn("send", send).unwrap();
    m.async_inst_fn("send_default", send_default).unwrap();

    m.ty::<CacheMode>().unwrap();

    m.ty::<QueryContext>().unwrap();
    m.field_fn(Protocol::GET, "ip", |qctx: &QueryContext| -> IpAddr {
        qctx.ip.into()
    })
    .unwrap();
    m.field_fn(
        Protocol::SET,
        "ip",
        |qctx: &mut QueryContext, ip: IpAddr| qctx.ip = ip.into(),
    )
    .unwrap();

    m
});
