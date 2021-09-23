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
use domain::base::{name::ToDname, Message};
use log::*;
use std::{
    borrow::Borrow,
    hash::{Hash, Hasher},
    net::IpAddr,
    num::NonZeroUsize,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

// Expire every hour
const ECS_CACHE_TTL: Duration = Duration::from_secs(60 * 60);

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

#[derive(Clone)]
pub struct CacheRecord<T> {
    created_instant: Instant,
    content: T,
    ttl: Duration,
}

impl<T: Clone> CacheRecord<T> {
    pub fn new(content: T, ttl: Duration) -> Self {
        Self {
            created_instant: Instant::now(),
            content,
            ttl,
        }
    }

    pub fn get(&self) -> T {
        self.content.clone()
    }

    pub fn validate(&self) -> bool {
        Instant::now().saturating_duration_since(self.created_instant) <= self.ttl
    }
}

pub enum RecordStatus<T> {
    Alive(T),
    Expired(T),
}

// A LRU cache for responses
#[derive(Clone)]
pub struct RespCache {
    #[allow(clippy::type_complexity)]
    cache: Arc<Mutex<CLruCache<(Label, Bytes), CacheRecord<Message<Bytes>>>>>,
}

impl RespCache {
    pub fn new(size: NonZeroUsize) -> Self {
        Self {
            cache: Arc::new(Mutex::new(CLruCache::new(size))),
        }
    }

    pub fn put(&self, tag: Label, query: &Message<Bytes>, msg: Message<Bytes>) {
        if msg.no_error() {
            // We are assured that it should parse and exist
            let ttl = Duration::from_secs(u64::from(
                query
                    .answer()
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
            self.cache.lock().unwrap().put(
                // We discard the first two bytes which are the places for ID
                (tag, query.as_octets().slice(2..)),
                // Clone should be cheap here
                CacheRecord::new(msg, ttl),
            );
        } else {
            info!("response errored, not caching erroneous upstream response.");
        };
    }

    pub fn get(&self, tag: &Label, msg: &Message<Bytes>) -> Option<RecordStatus<Message<Bytes>>> {
        let question = msg.first_question().unwrap();
        let qname = question.qname().to_bytes();

        match self
            .cache
            .lock()
            .unwrap()
            .get(&(tag, msg.as_octets().slice(2..)) as &dyn KeyPair<Label, Bytes>)
        {
            Some(r) => {
                // Get record only once.
                if r.validate() {
                    info!("cache hit for {}", qname);
                    Some(Alive(r.get()))
                } else {
                    info!("TTL passed for {}, returning expired record.", qname);
                    Some(Expired(r.get()))
                }
            }
            Option::None => Option::None,
        }
    }
}

// A LRU cache mapping local address to EDNS Client Subnet external IP addr
#[derive(Clone)]
pub struct EcsCache {
    cache: Arc<Mutex<Option<CacheRecord<IpAddr>>>>,
}

impl EcsCache {
    pub fn new() -> Self {
        Self {
            cache: Arc::new(Mutex::new(None)),
        }
    }

    pub async fn put(&self, external_ip: IpAddr) {
        *self.cache.lock().unwrap() = Some(CacheRecord::new(external_ip, ECS_CACHE_TTL));
    }

    pub fn get(&self, ip: &IpAddr) -> Option<RecordStatus<IpAddr>> {
        match &mut *self.cache.lock().unwrap() {
            Some(r) => {
                // Get record only once.
                if r.validate() {
                    info!("ECS external IP cache hit for private IP {}", ip);
                    Some(Alive(r.get()))
                } else {
                    info!(
                        "TTL passed for private IP {}, returning expired record.",
                        ip
                    );
                    Some(Expired(r.get()))
                }
            }
            Option::None => Option::None,
        }
    }
}

impl Default for EcsCache {
    fn default() -> Self {
        Self::new()
    }
}
