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

use std::num::NonZeroU32;

#[derive(Default)]
pub struct QosPolicy;

impl From<Option<NonZeroU32>> for QosPolicy {
    fn from(_: Option<NonZeroU32>) -> Self {
        Self
    }
}

impl QosPolicy {
    pub fn check(&self) -> bool {
        true
    }
}
