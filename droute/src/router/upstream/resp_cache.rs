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

use log::*;
use lru::LruCache;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use trust_dns_client::op::{Message, Query};

// Maximum TTL as defined in https://tools.ietf.org/html/rfc2181, 2147483647
//   Setting this to a value of 1 day, in seconds
pub const MAX_TTL: u32 = 86400_u32;

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

// A LRU cache for responses
pub struct RespCache {
    cache: Mutex<LruCache<Vec<Query>, CacheRecord>>,
}

impl RespCache {
    pub fn new(size: usize) -> Self {
        Self {
            cache: Mutex::new(LruCache::new(size)),
        }
    }

    pub fn put(&self, msg: Message) {
        self.cache
            .lock()
            .unwrap()
            .put(msg.queries().to_vec(), CacheRecord::new(msg));
    }

    pub fn get(&self, msg: &Message) -> Option<Message> {
        let queries: Vec<Query> = msg.queries().to_vec();
        let mut cache = self.cache.lock().unwrap();
        match cache.get(&queries) {
            Some(r) => {
                if r.validate() {
                    info!("Cache hit for queries: {:?}", queries);
                    Some(r.get())
                } else {
                    info!("TTL passed, purging cache.");
                    cache.pop(&queries);
                    None
                }
            }
            None => None,
        }
    }
}
