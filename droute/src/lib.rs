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

#![deny(missing_docs)]
#![deny(unsafe_code)]
// Documentation
//! This is the core library for dcompass. It implements configuration parsing scheme, DNS query routing rules, and upstream managements.
pub mod error;
#[doc(hidden)]
pub mod mock;
mod router;

use hashbrown::HashSet;

#[cfg(feature = "serde-cfg")]
/// This module contains the data structures with serialization supports.
pub mod parsed {
    pub use super::router::{table::parsed::*, upstreams::parsed::*};
}
pub use self::router::{
    table::{
        rule::{actions, matchers, Rule},
        Table,
    },
    upstreams::{client_pool, Upstream, UpstreamKind, Upstreams},
    Router,
};

use std::sync::Arc;

// Maximum TTL as defined in https://tools.ietf.org/html/rfc2181, 2147483647
//   Setting this to a value of 1 day, in seconds
const MAX_TTL: u32 = 86400_u32;

type Label = Arc<str>;

/// A object that can be validated
pub trait Validatable {
    /// The possible errors from the validation.
    type Error;
    /// Validate oneself.
    /// `used`: some of the tags used by other parts, which should be existed.
    fn validate(&self, used: Option<&HashSet<Label>>) -> std::result::Result<(), Self::Error>;
}
