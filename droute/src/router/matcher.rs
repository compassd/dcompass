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

//! Trait of a matcher.

use dmatcher::domain::Domain;
use std::hash::Hash;

/// A matcher is a matching algorithm that matches input `&str` to `&Self::Label`.
pub trait Matcher {
    /// Type of the "label" the matcher supports.
    type Label;

    /// Create a new matcher.
    fn new() -> Self;
    /// Given a specific input, return back the corresponding label for its destination.
    fn matches(&self, input: &str) -> Option<&Self::Label>;
    /// Insert an (input, tag) pair where and `tag` is a label for destination.
    fn insert(&mut self, input: &str, tag: &Self::Label);
    /// Insert a set of input with a single tag. Input can be splitted with `\n` with each line a legal `input` for `insert()` method above.
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
