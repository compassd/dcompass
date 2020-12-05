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

//! This module provides universal error type used in the library. The error type uses `thiserror`.

pub use crate::router::{table::TableError, upstreams::error::UpstreamError};
use std::fmt::Debug;
use thiserror::Error;

pub(crate) type Result<T> = std::result::Result<T, DrouteError>;

/// DrouteError enumerates all possible errors returned by this library.
#[derive(Error, Debug)]
pub enum DrouteError {
    /// Error related to the `table` section.
    #[error(transparent)]
    TableError(#[from] TableError),

    /// Error related to the `upstreams` section.
    #[error(transparent)]
    UpstreamError(#[from] UpstreamError),
}
