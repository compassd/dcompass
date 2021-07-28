// Copyright 2020 LEXUGE
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

mod blackhole;
/// Builders for built-in actions and more.
pub mod builder;
mod query;

pub use self::{
    blackhole::Blackhole,
    query::{CacheMode, Query},
};

use super::super::{
    super::upstreams::{error::UpstreamError, Upstreams},
    State,
};
use crate::Label;
use async_trait::async_trait;
use std::fmt::Debug;
use thiserror::Error;

/// A shorthand for returning action error.
pub type Result<T> = std::result::Result<T, ActionError>;

#[derive(Error, Debug)]
/// Errors may caused by `Action`.
pub enum ActionError {
    /// Error forwarded from `UpstreamError`.
    #[error(transparent)]
    UpstreamError(#[from] UpstreamError),

    /// Other error.
    #[error("An error encountered in action: {0}")]
    Other(String),

    /// Short Buf
    #[error(transparent)]
    ShortBuf(#[from] domain::base::ShortBuf),
}

#[async_trait]
/// `Action` trait which can manipulate the `State` passed in.
pub trait Action: Sync + Send {
    /// Do something(or nothing) upon `State`.
    async fn act(&self, state: &mut State, upstreams: &Upstreams) -> Result<()>;

    /// All upstreams may used by this `Action`.
    fn used_upstream(&self) -> Option<Label>;
}
