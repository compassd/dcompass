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

use self::RecordStatus::*;
use crate::{Label, MAX_TTL};
use clru::CLruCache;
use log::*;
use std::{
    borrow::Borrow,
    hash::{Hash, Hasher},
    num::NonZeroUsize,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use trust_dns_client::op::{Message, Query, ResponseCode};

// Code to use (&A, &B) for accessing HashMap, clipped from https://stackoverflow.com/questions/45786717/how-to-implement-hashmap-with-two-keys/45795699#45795699.
trait KeyPair<A, B> {
    /// Obtains the first element of the pair.
    fn a(&self) -> &A;
    /// Obtains the second element of the pair.
    fn b(&self) -> &B;
}

impl<'a, A, B> Borrow<dyn KeyPair<A, B> + 'a> for (A, B)
where
    A: Eq + Hash + 'a,
    B: Eq + Hash + 'a,
{
    fn borrow(&self) -> &(dyn KeyPair<A, B> + 'a) {
        self
    }
}

impl<A: Hash, B: Hash> Hash for (dyn KeyPair<A, B> + '_) {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.a().hash(state);
        self.b().hash(state);
    }
}

impl<A: Eq, B: Eq> PartialEq for (dyn KeyPair<A, B> + '_) {
    fn eq(&self, other: &Self) -> bool {
        self.a() == other.a() && self.b() == other.b()
    }
}

impl<A: Eq, B: Eq> Eq for (dyn KeyPair<A, B> + '_) {}

impl<A, B> KeyPair<A, B> for (A, B) {
    fn a(&self) -> &A {
        &self.0
    }
    fn b(&self) -> &B {
        &self.1
    }
}

impl<A, B> KeyPair<A, B> for (&A, &B) {
    fn a(&self) -> &A {
        self.0
    }
    fn b(&self) -> &B {
        self.1
    }
}

struct CacheRecord {
    created_instant: Instant,
    msg: Message,
    ttl: Duration,
}

impl CacheRecord {
    pub fn new(msg: Message) -> Self {
        let ttl = Duration::from_secs(u64::from(
            msg.answers()
                .iter()
                .map(|r| r.ttl())
                .min()
                .unwrap_or(MAX_TTL),
        ));
        Self {
            created_instant: Instant::now(),
            msg,
            ttl,
        }
    }

    pub fn get(&self) -> Message {
        self.msg.clone()
    }

    pub fn validate(&self) -> bool {
        Instant::now().saturating_duration_since(self.created_instant) <= self.ttl
    }
}

pub enum RecordStatus {
    Alive(Message),
    Expired(Message),
}

// A LRU cache for responses
#[derive(Clone)]
pub struct RespCache {
    #[allow(clippy::type_complexity)]
    cache: Arc<Mutex<CLruCache<(Label, Vec<Query>), CacheRecord>>>,
}

impl RespCache {
    pub fn new(size: NonZeroUsize) -> Self {
        Self {
            cache: Arc::new(Mutex::new(CLruCache::new(size))),
        }
    }

    pub fn put(&self, tag: Label, msg: Message) {
        if msg.response_code() == ResponseCode::NoError {
            self.cache
                .lock()
                .unwrap()
                .put((tag, msg.queries().to_vec()), CacheRecord::new(msg));
        } else {
            info!("Response errored, not caching erroneous upstream response.");
        };
    }

    pub fn get(&self, tag: &Label, msg: &Message) -> Option<RecordStatus> {
        let queries: Vec<Query> = msg.queries().to_vec();
        let mut cache = self.cache.lock().unwrap();
        match cache.get(&(tag, &queries) as &dyn KeyPair<Label, Vec<Query>>) {
            Some(r) => {
                // Get record only once.
                let resp = r.get();
                if r.validate() {
                    info!("Cache hit for queries: {:?}", queries);
                    Some(Alive(resp))
                } else {
                    info!("TTL passed, returning expired record.");
                    Some(Expired(resp))
                }
            }
            Option::None => Option::None,
        }
    }
}
