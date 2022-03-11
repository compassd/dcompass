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

use governor::{
    clock::{QuantaClock, QuantaInstant},
    middleware::NoOpMiddleware,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter,
};
use std::num::NonZeroU32;

type QosPolicyInner =
    Option<RateLimiter<NotKeyed, InMemoryState, QuantaClock, NoOpMiddleware<QuantaInstant>>>;

#[derive(Default)]
pub struct QosPolicy(QosPolicyInner);

impl From<Option<NonZeroU32>> for QosPolicy {
    fn from(qps: Option<NonZeroU32>) -> Self {
        if let Some(qps) = qps {
            Self(Some(RateLimiter::direct(Quota::per_second(qps))))
        } else {
            Self(None)
        }
    }
}

impl QosPolicy {
    pub fn check(&self) -> bool {
        match &self.0 {
            Some(ratelimit) => ratelimit.check().is_ok(),
            None => true,
        }
    }
}
