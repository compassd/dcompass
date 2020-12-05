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

use super::Matcher;
use trust_dns_proto::{op::query::Query, rr::resource::Record};

pub struct Any;

impl Any {
    pub fn new() -> Self {
        Self
    }
}

impl Matcher for Any {
    fn matches(&self, _: &[Query], _: &[Record]) -> bool {
        true
    }
}
