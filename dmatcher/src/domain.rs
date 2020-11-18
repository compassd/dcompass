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
//! use dmatcher::{domain::Domain, Label};
//! let mut matcher = Domain::<Label>::new();
//! matcher.insert("apple.com", &"global".into());
//! assert_eq!(matcher.matches("store.apple.com"), Some(&"global".into()));
//! ```

use hashbrown::HashMap;
use std::{hash::Hash, sync::Arc};

#[derive(Debug, PartialEq, Clone)]
struct LevelNode<L> {
    dst: Option<L>,
    next_lvs: HashMap<Arc<str>, LevelNode<L>>,
}

impl<L> LevelNode<L> {
    fn new() -> Self {
        Self {
            dst: None,
            next_lvs: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone)]
/// Domain matcher algorithm
pub struct Domain<L> {
    root: LevelNode<L>,
}

impl<L: Eq + Hash + Clone> Default for Domain<L> {
    fn default() -> Self {
        Self::new()
    }
}

impl<L: Eq + Hash + Clone> Domain<L> {
    /// Create a matcher.
    pub fn new() -> Self {
        Self {
            root: LevelNode::new(),
        }
    }

    #[cfg(test)]
    fn get_root(&self) -> &LevelNode<L> {
        &self.root
    }

    /// Pass in a string containing `\n` and get all domains inserted.
    pub fn insert_multi(&mut self, domain: &str, dst: &L) {
        let lvs: Vec<&str> = domain.split('\n').collect();
        for lv in lvs {
            self.insert(lv, dst);
        }
    }

    /// Pass in a domain and insert it into the matcher.
    pub fn insert(&mut self, domain: &str, dst: &L) {
        let lvs: Vec<&str> = domain.split('.').rev().collect();
        let mut ptr = &mut self.root;
        for lv in lvs {
            if lv.is_empty() {
                // We should not include sub-levels like ""
                continue;
            }
            ptr = ptr
                .next_lvs
                .entry(Arc::from(lv))
                .or_insert_with(LevelNode::new);
        }
        ptr.dst = Some(dst.clone());
    }

    /// Match the domain against inserted domain rules. If `apple.com` is inserted, then `www.apple.com` and `stores.www.apple.com` is considered as matched while `apple.cn` is not.
    pub fn matches(&self, domain: &str) -> Option<&L> {
        let lvs: Vec<&str> = domain.split('.').rev().collect();
        let mut ptr = &self.root;
        for lv in lvs {
            if lv.is_empty() {
                // We should not include sub-levels like ""
                continue;
            }
            if ptr.next_lvs.is_empty() {
                break;
            }
            // If not empty...
            ptr = match ptr.next_lvs.get(lv) {
                Some(v) => v,
                None => return None,
            };
        }
        ptr.dst.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::{Domain, LevelNode};
    use crate::Label;
    use hashbrown::HashMap;

    #[test]
    fn matches() {
        let mut matcher = Domain::<Label>::new();
        matcher.insert("apple.com", &"global".into());
        matcher.insert("apple.cn", &"domestic".into());
        assert_eq!(matcher.matches("store.apple.com"), Some(&"global".into()));
        assert_eq!(matcher.matches("store.apple.com."), Some(&"global".into()));
        assert_eq!(matcher.matches("baidu.com"), None);
        assert_eq!(
            matcher.matches("你好.store.www.apple.cn"),
            Some(&"domestic".into())
        );
    }

    #[test]
    fn insertion() {
        let mut matcher = Domain::new();
        matcher.insert("apple.com", &"global".into());
        matcher.insert("apple.cn", &"domestic".into());
        println!("{:?}", matcher.get_root());
        assert_eq!(
            matcher.get_root(),
            &LevelNode {
                dst: None,
                next_lvs: [
                    (
                        "cn".into(),
                        LevelNode {
                            dst: None,
                            next_lvs: [(
                                "apple".into(),
                                LevelNode {
                                    dst: Some("domestic".into()),
                                    next_lvs: []
                                        .iter()
                                        .cloned()
                                        .collect::<HashMap<Label, LevelNode<Label>>>()
                                }
                            )]
                            .iter()
                            .cloned()
                            .collect::<HashMap<Label, LevelNode<Label>>>()
                        }
                    ),
                    (
                        "com".into(),
                        LevelNode {
                            dst: None,
                            next_lvs: [(
                                "apple".into(),
                                LevelNode {
                                    dst: Some("global".into()),
                                    next_lvs: []
                                        .iter()
                                        .cloned()
                                        .collect::<HashMap<Label, LevelNode<Label>>>()
                                }
                            )]
                            .iter()
                            .cloned()
                            .collect::<HashMap<Label, LevelNode<Label>>>()
                        }
                    )
                ]
                .iter()
                .cloned()
                .collect::<HashMap<Label, LevelNode<Label>>>()
            }
        );
    }
}
