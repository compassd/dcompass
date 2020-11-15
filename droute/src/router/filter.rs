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

use super::matcher::Matcher;
use crate::error::Result;
use log::*;
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display};
use tokio::{fs::File, prelude::*};

#[derive(Serialize, Deserialize, Clone)]
pub struct Rule<L> {
    pub dst: L,
    pub path: String,
}

pub(crate) struct Filter<L, M> {
    default_tag: L,
    matcher: M,
    dsts: Vec<L>,
}

impl<L: Display + Debug + Clone, M: Matcher<Label = L>> Filter<L, M> {
    pub async fn new(default_tag: L, rules: Vec<Rule<L>>) -> Result<L, Self> {
        let mut matcher = M::new();
        let mut dsts = vec![];
        for r in rules {
            let mut file = File::open(r.path).await?;
            let mut data = String::new();
            file.read_to_string(&mut data).await?;
            matcher.insert_multi(&data, &r.dst);
            dsts.push(r.dst);
        }

        Ok(Self {
            default_tag,
            matcher,
            dsts,
        })
    }

    pub fn get_dsts(&self) -> &[L] {
        &self.dsts
    }

    pub fn default_tag(&self) -> &L {
        &self.default_tag
    }

    pub fn get_upstream(&self, domain: &str) -> &L {
        match self.matcher.matches(domain) {
            Some(u) => {
                info!("Domain {} routed via upstream with tag {}", domain, u);
                &u
            }
            None => {
                info!(
                    "Domain {} routed via upstream with default tag {}",
                    domain,
                    self.default_tag()
                );
                self.default_tag()
            }
        }
    }
}
