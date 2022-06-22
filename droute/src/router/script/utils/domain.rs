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

use super::Result;
use bytes::Bytes;
use dmatcher::domain::Domain as DomainAlg;
use domain::base::{name::FromStrError, Dname};
use std::{path::PathBuf, str::FromStr};

/// The domain matcher
#[derive(Clone)]
pub struct Domain(DomainAlg);

fn into_dnames(list: &str) -> std::result::Result<Vec<Dname<Bytes>>, FromStrError> {
    list.split('\n')
        .filter(|&x| {
            (!x.is_empty())
                && (x.chars().all(|c| {
                    char::is_ascii_alphabetic(&c)
                        | char::is_ascii_digit(&c)
                        | (c == '-')
                        | (c == '.')
                }))
        })
        .map(Dname::from_str)
        .collect()
}

impl Domain {
    /// Create an empty `domain` matcher
    pub fn new() -> Self {
        Self(DomainAlg::new())
    }

    pub fn add_qname(&mut self, s: impl AsRef<str>) -> Result<()> {
        self.0.insert_multi(&into_dnames(s.as_ref())?);
        Ok(())
    }

    pub fn add_file(&mut self, path: impl AsRef<str>) -> Result<()> {
        let (mut file, _) = niffler::from_path(PathBuf::from_str(path.as_ref()).unwrap())?;
        let mut data = String::new();
        file.read_to_string(&mut data)?;
        self.0.insert_multi(&into_dnames(&data)?);
        Ok(())
    }

    pub fn contains(&self, qname: Dname<Bytes>) -> bool {
        self.0.matches(&qname)
    }
}
