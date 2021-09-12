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
use bytes::Bytes;
use clru::CLruCache;
use domain::base::{name::ToDname, question::Question, Dname, Message};
use log::*;
use std::{
    borrow::Borrow,
    hash::{Hash, Hasher},
    num::NonZeroUsize,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

// Code to use (&A, &B) for accessing HashMap, clipped from https://stackoverflow.com/questions/45786717/how-to-implement-hashmap-with-two-keys/45795699#45795699.
trait KeyPair<A: ?Sized, B: ?Sized> {
    /// Obtains the first element of the pair.
    fn a(&self) -> &A;
    /// Obtains the second element of the pair.
    fn b(&self) -> &B;
}

impl<'a, A: ?Sized, B: ?Sized, C, D> Borrow<dyn KeyPair<A, B> + 'a> for (C, D)
where
    A: Eq + Hash + 'a,
    B: Eq + Hash + 'a,
    C: Borrow<A> + 'a,
    D: Borrow<B> + 'a,
{
    fn borrow(&self) -> &(dyn KeyPair<A, B> + 'a) {
        self
    }
}

impl<A: Hash + ?Sized, B: Hash + ?Sized> Hash for (dyn KeyPair<A, B> + '_) {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.a().hash(state);
        self.b().hash(state);
    }
}

impl<A: Eq + ?Sized, B: Eq + ?Sized> PartialEq for (dyn KeyPair<A, B> + '_) {
    fn eq(&self, other: &Self) -> bool {
        self.a() == other.a() && self.b() == other.b()
    }
}

impl<A: Eq + ?Sized, B: Eq + ?Sized> Eq for (dyn KeyPair<A, B> + '_) {}

impl<A: ?Sized, B: ?Sized, C, D> KeyPair<A, B> for (C, D)
where
    C: Borrow<A>,
    D: Borrow<B>,
{
    fn a(&self) -> &A {
        self.0.borrow()
    }
    fn b(&self) -> &B {
        self.1.borrow()
    }
}

struct CacheRecord {
    created_instant: Instant,
    msg: Message<Bytes>,
    ttl: Duration,
}

impl CacheRecord {
    pub fn new(msg: Message<Bytes>) -> Self {
        let ttl = Duration::from_secs(u64::from(
            msg.answer()
                .ok()
                .map(|records| {
                    records
                        .filter(|r| r.is_ok())
                        .map(|r| r.unwrap().ttl())
                        .min()
                })
                .flatten()
                .unwrap_or(MAX_TTL),
        ));

        Self {
            created_instant: Instant::now(),
            msg,
            ttl,
        }
    }

    pub fn get(&self) -> Message<Bytes> {
        self.msg.clone()
    }

    pub fn validate(&self) -> bool {
        Instant::now().saturating_duration_since(self.created_instant) <= self.ttl
    }
}

pub enum RecordStatus {
    Alive(Message<Bytes>),
    Expired(Message<Bytes>),
}

// A LRU cache for responses
#[derive(Clone)]
pub struct RespCache {
    #[allow(clippy::type_complexity)]
    cache: Arc<Mutex<CLruCache<(Label, Question<Dname<Bytes>>), CacheRecord>>>,
}

impl RespCache {
    pub fn new(size: NonZeroUsize) -> Self {
        Self {
            cache: Arc::new(Mutex::new(CLruCache::new(size))),
        }
    }

    pub fn put(&self, tag: Label, msg: Message<Bytes>) {
        if msg.no_error() {
            // We are assured that it should parse and exist
            let question = msg.first_question().unwrap();
            self.cache.lock().unwrap().put(
                (
                    tag,
                    (
                        question.qname().to_bytes(),
                        question.qtype(),
                        question.qclass(),
                    )
                        .into(),
                ),
                // Clone should be cheap here
                CacheRecord::new(msg),
            );
        } else {
            info!("response errored, not caching erroneous upstream response.");
        };
    }

    pub fn get(&self, tag: &Label, msg: &Message<Bytes>) -> Option<RecordStatus> {
        let mut cache = self.cache.lock().unwrap();
        let question = msg.first_question().unwrap();
        let qname = question.qname().to_bytes();
        let question: Question<Dname<Bytes>> =
            (qname.clone(), question.qtype(), question.qclass()).into();

        match cache.get(&(tag, question) as &dyn KeyPair<Label, Question<Dname<Bytes>>>) {
            Some(r) => {
                // Get record only once.
                let resp = r.get();
                if r.validate() {
                    info!("cache hit for {}", qname);
                    Some(Alive(resp))
                } else {
                    info!("TTL passed for {}, returning expired record.", qname);
                    Some(Expired(resp))
                }
            }
            Option::None => Option::None,
        }
    }
}
