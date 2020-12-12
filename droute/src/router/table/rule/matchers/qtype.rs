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

use super::{super::super::State, Matcher, Result};
use hashbrown::HashSet;
use trust_dns_proto::rr::record_type::RecordType;

/// A matcher that matches if first query is of any of the record types provided.
pub struct QType(HashSet<RecordType>);

impl QType {
    /// Create a new `QType` matcher.
    pub fn new(types: HashSet<RecordType>) -> Result<Self> {
        Ok(Self(types))
    }
}

impl Matcher for QType {
    fn matches(&self, state: &State) -> bool {
        self.0.contains(&state.query.queries()[0].query_type())
    }
}
