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
//! -  Super fast (167 ns per match for a 73300+ domain rule set)
//! -  No dependencies
//!
//! # Getting Started
//!
//! ```
//! use dmatcher::domain::Domain;
//! let mut matcher = Domain::new();
//! matcher.insert("apple.com");
//! assert_eq!(matcher.matches("store.apple.com"), true);
//! ```

use hashbrown::HashMap;
use std::sync::Arc;

#[derive(Debug, PartialEq, Clone)]
struct LevelNode {
    next_lvs: HashMap<Arc<str>, LevelNode>,
}

impl LevelNode {
    fn new() -> Self {
        Self {
            next_lvs: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone)]
/// Domain matcher algorithm
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

    #[cfg(test)]
    fn get_root(&self) -> &LevelNode {
        &self.root
    }

    /// Pass in a string containing `\n` and get all domains inserted.
    pub fn insert_multi(&mut self, domain: &str) {
        domain.split('\n').for_each(|lv| self.insert(lv));
    }

    /// Pass in a domain and insert it into the matcher.
    pub fn insert(&mut self, domain: &str) {
        let lvs: Vec<&str> = domain
            .split('.')
            .filter(|lv| !lv.is_empty())
            .rev()
            .collect();
        let mut ptr = &mut self.root;
        for lv in lvs {
            ptr = ptr
                .next_lvs
                .entry(Arc::from(lv))
                .or_insert_with(LevelNode::new);
        }
    }

    /// Match the domain against inserted domain rules. If `apple.com` is inserted, then `www.apple.com` and `stores.www.apple.com` is considered as matched while `apple.cn` is not.
    pub fn matches(&self, domain: &str) -> bool {
        let lvs: Vec<&str> = domain
            .split('.')
            .filter(|lv| !lv.is_empty())
            .rev()
            .collect();
        let mut ptr = &self.root;
        for lv in lvs {
            if ptr.next_lvs.is_empty() {
                break;
            }
            // If not empty...
            ptr = match ptr.next_lvs.get(lv) {
                Some(v) => v,
                None => return false,
            };
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::{Domain, LevelNode};
    use hashbrown::HashMap;
    use std::sync::Arc;

    #[test]
    fn matches() {
        let mut matcher = Domain::new();
        matcher.insert("apple.com");
        matcher.insert("apple.cn");
        assert_eq!(matcher.matches("store.apple.com"), true);
        assert_eq!(matcher.matches("store.apple.com."), true);
        assert_eq!(matcher.matches("baidu.com"), false);
        assert_eq!(matcher.matches("你好.store.www.apple.cn"), true);
    }

    #[test]
    fn insertion() {
        let mut matcher = Domain::new();
        matcher.insert("apple.com");
        matcher.insert("apple.cn");
        println!("{:?}", matcher.get_root());
        assert_eq!(
            matcher.get_root(),
            &LevelNode {
                next_lvs: [
                    (
                        "cn".into(),
                        LevelNode {
                            next_lvs: [(
                                "apple".into(),
                                LevelNode {
                                    next_lvs: []
                                        .iter()
                                        .cloned()
                                        .collect::<HashMap<Arc<str>, LevelNode>>()
                                }
                            )]
                            .iter()
                            .cloned()
                            .collect::<HashMap<Arc<str>, LevelNode>>()
                        }
                    ),
                    (
                        "com".into(),
                        LevelNode {
                            next_lvs: [(
                                "apple".into(),
                                LevelNode {
                                    next_lvs: []
                                        .iter()
                                        .cloned()
                                        .collect::<HashMap<Arc<str>, LevelNode>>()
                                }
                            )]
                            .iter()
                            .cloned()
                            .collect::<HashMap<Arc<str>, LevelNode>>()
                        }
                    )
                ]
                .iter()
                .cloned()
                .collect::<HashMap<Arc<str>, LevelNode>>()
            }
        );
    }
}
