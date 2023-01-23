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

// General guideline:
// Use new types only in implementing the interface whenever possible
// And implement strings related functions for new types

// Basis module should not be placed at the module root because `types` module cannot be imported "AS IS" here.
mod basis;
mod message;
mod types;
mod utils;

use super::Result;
use crate::{
    errors::ScriptError, QueryContext, ScriptBackend, ScriptBuilder, Upstreams, Validatable,
};
use async_trait::async_trait;
use bytes::Bytes;
use domain::base::Message;
use rune::{
    runtime::RuntimeContext,
    termcolor::{ColorChoice, StandardStream},
    Context, Diagnostics, FromValue, Source, Sources, Unit, Vm,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use types::Message as NewMessage;
use utils::Utils;

/// A Rune script backend for droute
pub struct RuneScript {
    upstreams: Upstreams,
    // We cannot store Vm "as is" here as otherwise RuneScript is not Sync and &RuneScript wouldn't be Send.
    unit: Arc<Unit>,
    context: Arc<RuntimeContext>,
    inited: HashMap<String, Utils>,
}

#[async_trait]
impl ScriptBackend for RuneScript {
    async fn route(
        &self,
        query: Message<Bytes>,
        ctx: Option<QueryContext>,
    ) -> Result<Message<Bytes>> {
        let send_exec = {
            let vm = Vm::new(self.context.clone(), self.unit.clone());
            let query: NewMessage = query.into();

            vm.send_execute(
                ["route"],
                (self.upstreams.clone(), self.inited.clone(), ctx, query),
            )?
        };

        Ok(
            <std::result::Result<NewMessage, ScriptError> as FromValue>::from_value(
                send_exec.async_complete().await?,
            )??
            .into(),
        )
    }
}

impl Validatable for RuneScript {
    type Error = ScriptError;

    fn validate(&self, _: Option<&Vec<crate::Label>>) -> Result<()> {
        self.upstreams.validate(None)?;
        Ok(())
    }
}

/// A builder for `RuneScript`.
/// Two pub async functionas are required in the script: `pub async fn init()` and `pub async fn route(upstreams, init, ctx, query)`.
#[derive(Serialize, Deserialize, Clone)]
pub struct RuneScriptBuilder(String);

impl RuneScriptBuilder {
    /// Create a `RuneScriptBuilder` from the script source code.
    pub fn new(script: impl ToString) -> Self {
        Self(script.to_string())
    }
}

#[async_trait(?Send)]
impl ScriptBuilder<RuneScript> for RuneScriptBuilder {
    /// Build `Script` with upstreams
    async fn build(self, upstreams: Upstreams) -> Result<RuneScript> {
        // Prepare the init script
        let mut context = Context::with_default_modules()?;

        // Types module should always install first.
        context.install(&types::TYPES_MODULE)?;

        context.install(&message::MSG_MODULE)?;
        context.install(&basis::BASIS_MODULE)?;
        context.install(&utils::UTILS_MODULE)?;
        let runtime = Arc::new(context.runtime());

        let mut sources = Sources::new();
        sources.insert(Source::new("script", self.0));

        let mut diagnostics = Diagnostics::new();

        // We CANNOT do ? here because otherwise we abort early, missing out diagnostics.
        let unit = rune::prepare(&mut sources)
            .with_context(&context)
            .with_diagnostics(&mut diagnostics)
            .build();

        // Emit both init and route diagnostics.
        if !diagnostics.is_empty() {
            let mut writer = StandardStream::stderr(ColorChoice::Always);
            diagnostics.emit(&mut writer, &sources)?;
        }

        let unit = Arc::new(unit?);

        // Run the init script
        let mut vm = Vm::new(runtime.clone(), unit.clone());

        // Don't error if we cannot find init function, just return an empty object
        let inited = if unit.function(rune::Hash::type_hash(["init"])).is_some() {
            <Result<HashMap<String, Utils>>>::from_value(vm.async_call(&["init"], ()).await?)??
        } else {
            HashMap::<String, Utils>::new()
        };

        Ok(RuneScript {
            upstreams,
            unit,
            context: runtime,
            inited,
        })
    }
}
