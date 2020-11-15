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

use dmatcher::domain::Domain;
use std::hash::Hash;

pub trait Matcher {
    type Label;

    fn new() -> Self;
    // TODO: change to ref style.
    fn matches(&self, input: &str) -> Option<&Self::Label>;
    fn insert(&mut self, input: &str, tag: &Self::Label);
    fn insert_multi(&mut self, input: &str, tag: &Self::Label);
}

impl<L: Eq + Hash + Clone> Matcher for Domain<L> {
    type Label = L;

    fn new() -> Self {
        Self::new()
    }
    fn matches(&self, input: &str) -> Option<&Self::Label> {
        self.matches(input)
    }

    fn insert(&mut self, input: &str, tag: &Self::Label) {
        self.insert(input, tag)
    }

    fn insert_multi(&mut self, input: &str, tag: &Self::Label) {
        self.insert_multi(input, tag)
    }
}
