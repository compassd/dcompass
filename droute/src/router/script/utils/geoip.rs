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
#[cfg(not(any(feature = "geoip-cn", feature = "geoip-maxmind")))]
use super::UtilsError;
use log::info;
use maxminddb::{geoip2::Country, Reader};
use std::{net::IpAddr, path::PathBuf, str::FromStr, sync::Arc};

/// A matcher that matches if IP address in the record of the first A/AAAA response is in the list of countries.
#[derive(Clone)]
#[cfg_attr(feature = "rune-scripting", derive(rune::Any))]
pub struct GeoIp {
    db: Arc<Reader<Vec<u8>>>,
}

// If both geoip-maxmind and geoip-cn are enabled, geoip-maxmind will be used
fn get_builtin_db() -> Result<Vec<u8>> {
    #[cfg(feature = "geoip-maxmind")]
    return Ok(include_bytes!("../../../../../data/full.mmdb").to_vec());
    #[cfg(all(feature = "geoip-cn", not(feature = "geoip-maxmind")))]
    return Ok(include_bytes!("../../../../../data/cn.mmdb").to_vec());
    #[cfg(not(any(feature = "geoip-cn", feature = "geoip-maxmind")))]
    Err(UtilsError::NoBuiltInDb)
}

impl GeoIp {
    /// Create a geoip matcher from the database file with the given path
    pub async fn from_path(path: impl AsRef<str>) -> Result<Self> {
        // Per std documentation, this is infallible
        let buf: Vec<u8> = tokio::fs::read(PathBuf::from_str(path.as_ref()).unwrap()).await?;
        Ok(Self {
            db: Arc::new(Reader::from_source(buf)?),
        })
    }

    /// Create a geoip matcher from the database file with the given buffer
    #[cfg(test)]
    pub fn from_buf(buf: Vec<u8>) -> Result<Self> {
        Ok(Self {
            db: Arc::new(Reader::from_source(buf)?),
        })
    }

    /// Create a geoip matcher from the buffer
    pub fn create_default() -> Result<Self> {
        let buf = get_builtin_db()?;
        Ok(Self {
            db: Arc::new(Reader::from_source(buf)?),
        })
    }

    /// Whether the given country code contains the given IP address
    pub fn contains(&self, ip: IpAddr, code: &str) -> bool {
        let r = if let Ok(r) = self.db.lookup::<Country>(ip) {
            r
        } else {
            return false;
        };

        r.country
            .and_then(|c| {
                c.iso_code.map(|n| {
                    info!("IP `{}` has ISO country code `{}`", ip, n);
                    n == code
                })
            })
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::GeoIp;
    use once_cell::sync::Lazy;

    // Starting from droute's crate root
    static DB: Lazy<Vec<u8>> =
        Lazy::new(|| include_bytes!("../../../../../data/full.mmdb").to_vec());

    #[tokio::test]
    async fn builtin_db_not_china() {
        assert_eq!(
            GeoIp::from_buf(DB.clone())
                .unwrap()
                .contains("1.1.1.1".parse().unwrap(), "CN"),
            false
        )
    }

    #[tokio::test]
    async fn not_china() {
        assert_eq!(
            GeoIp::from_buf(DB.clone())
                .unwrap()
                .contains("1.1.1.1".parse().unwrap(), "CN"),
            false
        )
    }

    #[tokio::test]
    async fn mixed() {
        let geoip = GeoIp::from_buf(DB.clone()).unwrap();
        assert_eq!(geoip.contains("180.101.49.12".parse().unwrap(), "CN"), true);
        assert_eq!(geoip.contains("69.162.81.155".parse().unwrap(), "US"), true)
    }
}
