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

use bytes::Bytes;
use criterion::{criterion_group, criterion_main, Criterion};
use dmatcher::domain::Domain;
use domain::base::Dname;
use std::{fs::File, io::Read, str::FromStr};

fn bench_match(c: &mut Criterion) {
    let mut file = File::open("./benches/sample.txt").unwrap();
    let mut contents = String::new();
    let mut matcher = Domain::new();
    file.read_to_string(&mut contents).unwrap();
    let domains: Vec<Dname<Bytes>> = contents
        .split('\n')
        .filter(|&x| !x.is_empty())
        .map(|x| Dname::from_str(x).unwrap())
        .collect();

    let test = Dname::from_str("store.www.baidu.com").unwrap();
    matcher.insert_multi(&domains);
    c.bench_function("match", |b| {
        b.iter(|| assert_eq!(matcher.matches(&test), true))
    });
}

criterion_group!(benches, bench_match);
criterion_main!(benches);
