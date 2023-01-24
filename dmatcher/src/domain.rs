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

//! This is a simple domain matching algorithm to match domains against a set of user-defined domain rules.
//!
//! Features:
//!
//! -  Super fast (187 ns per match for a 73300+ domain rule set)
//! -  No dependencies
//!

use bytes::Bytes;
use domain::base::{name::OwnedLabel, Dname};
use std::{collections::HashMap, sync::Arc};

#[derive(PartialEq, Clone)]
struct LevelNode {
    next_lvs: HashMap<Arc<OwnedLabel>, LevelNode>,
}

impl LevelNode {
    fn new() -> Self {
        Self {
            next_lvs: HashMap::new(),
        }
    }
}

/// Domain matcher algorithm
#[derive(Clone)]
pub struct Domain {
    root: LevelNode,
}

impl Default for Domain {
    fn default() -> Self {
        Self::new()
    }
}

impl Domain {
    /// Create a matcher.
    pub fn new() -> Self {
        Self {
            root: LevelNode::new(),
        }
    }

    /// Pass in a string containing `\n` and get all domains inserted.
    pub fn insert_multi(&mut self, domain: &[Dname<Bytes>]) {
        // This gets rid of empty substrings for stability reasons. See also https://github.com/LEXUGE/dcompass/issues/33.
        domain.iter().for_each(|d| self.insert(d));
    }

    /// Pass in a domain and insert it into the matcher.
    /// This ignores any line containing chars other than A-Z, a-z, 1-9, and -.
    /// See also: https://tools.ietf.org/html/rfc1035
    pub fn insert(&mut self, domain: &Dname<Bytes>) {
        let mut ptr = &mut self.root;
        for lv in domain.iter().rev() {
            ptr = ptr
                .next_lvs
                .entry(Arc::new(lv.to_owned()))
                .or_insert_with(LevelNode::new);
        }
    }

    /// Match the domain against inserted domain rules. If `apple.com` is inserted, then `www.apple.com` and `stores.www.apple.com` is considered as matched while `apple.cn` is not.
    pub fn matches(&self, domain: &Dname<Bytes>) -> bool {
        let mut ptr = &self.root;
        for lv in domain.iter().rev() {
            // We have reached the end of our rule set, breaking
            if ptr.next_lvs.is_empty() {
                break;
            }
            // If not empty...
            ptr = match ptr.next_lvs.get(&lv.to_owned()) {
                Some(v) => v,
                None => return false,
            };
        }

        // If we exhausted our rule set, then this is a match
        // e.g. apps.apple.com is a match for apple.com
        ptr.next_lvs.is_empty()
        // Otherwise:
        // If there are still rules left but we have reached the end of our test case, then it is not a match.
        // e.g. apple.com is not a match for apps.apple.com
    }
}

#[cfg(test)]
mod tests {
    use super::Domain;
    use domain::base::Dname;
    use std::str::FromStr;

    macro_rules! dname {
        ($s:expr) => {
            Dname::from_str($s).unwrap()
        };
    }

    #[test]
    fn matches() {
        let mut matcher = Domain::new();
        matcher.insert(&dname!("apple.com"));
        matcher.insert(&dname!("apple.cn"));
        assert_eq!(matcher.matches(&dname!("store.apple.com")), true);
        assert_eq!(matcher.matches(&dname!("store.apple.com.")), true);
        assert_eq!(matcher.matches(&dname!("baidu.com")), false);
    }

    #[test]
    fn matches_2() {
        let mut matcher = Domain::new();
        matcher.insert(&dname!("tejia.taobao.com"));
        matcher.insert(&dname!("temai.m.taobao.com"));
        matcher.insert(&dname!("tui.taobao.com"));
        assert_eq!(matcher.matches(&dname!("a.tui.taobao.com")), true);
        assert_eq!(matcher.matches(&dname!("tejia.taobao.com")), true);
        assert_eq!(matcher.matches(&dname!("m.taobao.com")), false);
        assert_eq!(matcher.matches(&dname!("taobao.com")), false);
    }

    #[test]
    fn insert_multi() {
        let mut matcher = Domain::new();
        matcher.insert_multi(&[dname!("apple.com"), dname!("apple.cn")]);
        assert_eq!(matcher.matches(&dname!("store.apple.cn")), true);
        assert_eq!(matcher.matches(&dname!("store.apple.com.")), true);
        assert_eq!(matcher.matches(&dname!("baidu.com")), false);
    }
}
