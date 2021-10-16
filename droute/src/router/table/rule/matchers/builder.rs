// Copyright 2021 LEXUGE
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

use crate::AsyncTryInto;

#[cfg(feature = "geoip")]
pub use super::geoip::GeoIpBuilder;
pub use super::{domain::DomainBuilder, ipcidr::IpCidrBuilder, qtype::QTypeBuilder};
use super::{header::Header, MatchError, Matcher, Result as MatcherResult};
use async_trait::async_trait;
use serde::Deserialize;

/// The builder for Builtin Matchers
#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "lowercase")]
pub enum BuiltinMatcherBuilders {
    /// Matches domains in domain list files specified.
    Domain(DomainBuilder),

    /// Matches query types provided. Query types are like AAAA, A, TXT.
    QType(QTypeBuilder),

    /// Matches if IP address in the record of the first response is in the list of countries.
    #[cfg(feature = "geoip")]
    GeoIp(GeoIpBuilder),

    /// Matches if IP address in the record of the first response is in the list of IP CIDR.
    IpCidr(IpCidrBuilder),

    /// Matches if header fulfills given condition
    Header(Header),
}

// TODO: This should be derived
#[async_trait]
impl AsyncTryInto<Box<dyn Matcher>> for BuiltinMatcherBuilders {
    async fn try_into(self) -> MatcherResult<Box<dyn Matcher>> {
        Ok(match self {
            Self::Domain(v) => Box::new(v.try_into().await?),
            Self::Header(h) => Box::new(h),
            Self::QType(q) => Box::new(q.try_into().await?),
            Self::IpCidr(s) => Box::new(s.try_into().await?),
            #[cfg(feature = "geoip")]
            Self::GeoIp(g) => Box::new(g.try_into().await?),
        })
    }

    type Error = MatchError;
}
