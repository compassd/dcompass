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

use super::parser::Rule;
use crate::error::Result;
use dmatcher::{Dmatcher, Label};
use log::*;
use tokio::{fs::File, prelude::*};
// use tokio_compat_02::FutureExt;

pub struct Filter {
    default_tag: Label,
    matcher: Dmatcher,
}

impl Filter {
    async fn insert_rules(rules: Vec<Rule>) -> Result<(Dmatcher, Vec<Label>)> {
        let mut matcher = Dmatcher::new();
        let mut v = vec![];
        for r in rules {
            let mut file = File::open(r.path).await?;
            let mut data = String::new();
            file.read_to_string(&mut data).await?;
            matcher.insert_lines(data, &r.dst)?;
            v.push(r.dst);
        }
        Ok((matcher, v))
    }

    pub async fn new(default_tag: Label, rules: Vec<Rule>) -> Result<(Self, Vec<Label>)> {
        let (matcher, dsts) = Self::insert_rules(rules).await?;
        Ok((
            Self {
                default_tag,
                matcher,
            },
            dsts,
        ))
    }

    pub fn default_tag(&self) -> Label {
        self.default_tag.clone()
    }

    pub fn get_upstream(&self, domain: &str) -> Result<Label> {
        Ok(match self.matcher.matches(domain)? {
            Some(u) => {
                info!("Domain {} routed via upstream with tag {}", domain, u);
                u
            }
            None => {
                info!(
                    "Domain {} routed via upstream with default tag {}",
                    domain,
                    self.default_tag()
                );
                self.default_tag()
            }
        })
    }
}
