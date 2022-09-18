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

use super::{QueryContext, Result, ScriptBackend, ScriptBuilder, ScriptError};
use crate::{Upstreams, Validatable};
use async_trait::async_trait;
use bytes::Bytes;
use domain::base::Message;

/// A native "script" engine that allows scripting droute in rust.
pub struct NativeScript<F, T>
where
    F: Fn(Upstreams, Message<Bytes>, Option<QueryContext>) -> T + Send + Sync,
    T: std::future::Future<Output = Result<Message<Bytes>>> + Send,
{
    upstreams: Upstreams,
    script: F,
}

#[async_trait]
impl<F, T> ScriptBackend for NativeScript<F, T>
where
    F: Fn(Upstreams, Message<Bytes>, Option<QueryContext>) -> T + Send + Sync,
    T: std::future::Future<Output = Result<Message<Bytes>>> + Send,
{
    async fn route(
        &self,
        query: Message<Bytes>,
        ctx: Option<QueryContext>,
    ) -> Result<Message<Bytes>> {
        (self.script)(self.upstreams.clone(), query, ctx).await
    }
}

impl<F, T> Validatable for NativeScript<F, T>
where
    F: Fn(Upstreams, Message<Bytes>, Option<QueryContext>) -> T + Send + Sync,
    T: std::future::Future<Output = Result<Message<Bytes>>> + Send,
{
    type Error = ScriptError;

    fn validate(&self, _: Option<&Vec<crate::Label>>) -> Result<()> {
        self.upstreams.validate(None)?;
        Ok(())
    }
}

/// The builder for `NativeScript`
pub struct NativeScriptBuilder<F, T>
where
    F: Fn(Upstreams, Message<Bytes>, Option<QueryContext>) -> T + Send + Sync,
    T: std::future::Future<Output = Result<Message<Bytes>>> + Send,
{
    script: F,
}

impl<F, T> NativeScriptBuilder<F, T>
where
    F: Fn(Upstreams, Message<Bytes>, Option<QueryContext>) -> T + Send + Sync,
    T: std::future::Future<Output = Result<Message<Bytes>>> + Send,
{
    /// Create a builder from an async function that returns the resulting message
    pub fn new(script: F) -> Self {
        Self { script }
    }
}

#[async_trait(?Send)]
impl<F, T> ScriptBuilder<NativeScript<F, T>> for NativeScriptBuilder<F, T>
where
    F: Fn(Upstreams, Message<Bytes>, Option<QueryContext>) -> T + Send + Sync,
    T: std::future::Future<Output = Result<Message<Bytes>>> + Send,
{
    async fn build(self, upstreams: Upstreams) -> Result<NativeScript<F, T>> {
        Ok(NativeScript {
            upstreams,
            script: self.script,
        })
    }
}
