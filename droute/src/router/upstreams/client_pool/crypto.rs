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

// This module is under feature gate `crypto`.

use std::{collections::VecDeque, sync::Mutex};
#[cfg(feature = "doh")]
mod https;
#[cfg(feature = "dot")]
mod tls;

#[cfg(feature = "doh")]
pub use self::https::Https;
#[cfg(feature = "dot")]
pub use self::tls::Tls;

#[cfg(any(feature = "doh", feature = "dot"))]
use rustls::{ClientConfig, KeyLogFile, ProtocolVersion, RootCertStore};
#[cfg(any(feature = "doh", feature = "dot"))]
use std::sync::Arc;

// Not used if there is no DoT or DoH enabled.
#[cfg(any(feature = "doh", feature = "dot"))]
const ALPN_H2: &[u8] = b"h2";

// Create client config for TLS and HTTPS clients
#[cfg(any(feature = "doh", feature = "dot"))]
fn create_client_config(no_sni: &bool) -> Arc<ClientConfig> {
    let mut root_store = RootCertStore::empty();
    root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
    let versions = vec![ProtocolVersion::TLSv1_2];

    let mut client_config = ClientConfig::new();
    client_config.root_store = root_store;
    client_config.versions = versions;
    client_config.alpn_protocols.push(ALPN_H2.to_vec());
    client_config.key_log = Arc::new(KeyLogFile::new());
    client_config.enable_sni = !no_sni; // Disable SNI on need.

    Arc::new(client_config)
}

const MAX_INSTANCE_NUM: usize = 128;

#[derive(Clone)]
pub(self) struct Pool<T> {
    inner: Arc<Mutex<VecDeque<T>>>,
}

impl<T> Pool<T> {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(VecDeque::new())),
        }
    }

    pub fn get(&self) -> Option<T> {
        {
            // This ensures during the lock, queue's state is unchanged. (We shall only lock once).
            let mut p = self.inner.lock().unwrap();
            if p.is_empty() {
                None
            } else {
                // queue is not empty
                Some(p.pop_front().unwrap())
            }
        }
    }

    pub fn put(&self, c: T) {
        let mut p = self.inner.lock().unwrap();
        p.push_back(c);
        p.truncate(MAX_INSTANCE_NUM);
    }
}
