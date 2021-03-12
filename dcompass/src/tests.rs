// Copyright 2020, 2021 LEXUGE
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

use super::init;
use droute::error::*;

#[tokio::test]
async fn check_default() {
    init(serde_yaml::from_str(include_str!("../../configs/default.json")).unwrap())
        .await
        .unwrap();
}

#[tokio::test]
async fn check_success_ipcidr() {
    assert_eq!(
        init(serde_yaml::from_str(include_str!("../../configs/success_cidr.yaml")).unwrap())
            .await
            .is_ok(),
        true
    );
}

#[cfg(all(feature = "geoip-maxmind", not(feature = "geoip-cn")))]
#[tokio::test]
async fn check_example_maxmind() {
    assert_eq!(
        init(serde_yaml::from_str(include_str!("../../configs/example.yaml")).unwrap())
            .await
            .is_ok(),
        true
    );
}

#[cfg(all(feature = "geoip-cn", not(feature = "geoip-maxmind")))]
#[tokio::test]
async fn check_example_cn() {
    assert_eq!(
        init(serde_yaml::from_str(include_str!("../../configs/example.yaml")).unwrap())
            .await
            .is_ok(),
        true
    );
}

#[tokio::test]
async fn check_success_rule() {
    assert_eq!(
        init(serde_yaml::from_str(include_str!("../../configs/success_rule.json")).unwrap())
            .await
            .is_ok(),
        true
    );
}

#[tokio::test]
async fn check_success_query_cache_mode() {
    assert_eq!(
        init(serde_yaml::from_str(include_str!("../../configs/query_cache_policy.yaml")).unwrap())
            .await
            .is_ok(),
        true
    );
}

#[tokio::test]
async fn check_success_geoip() {
    assert_eq!(
        init(serde_yaml::from_str(include_str!("../../configs/success_geoip.yaml")).unwrap())
            .await
            .is_ok(),
        true
    );
}

#[tokio::test]
async fn check_success_rule_yaml() {
    assert_eq!(
        init(serde_yaml::from_str(include_str!("../../configs/success_rule_yaml.yaml")).unwrap())
            .await
            .is_ok(),
        true
    );
}

#[tokio::test]
async fn check_fail_undef() {
    assert_eq!(
        match init(serde_yaml::from_str(include_str!("../../configs/fail_undef.json")).unwrap())
            .await
            .err()
            .unwrap()
        {
            DrouteError::UpstreamError(UpstreamError::MissingTag(tag)) => tag,
            e => panic!("Not the right error type: {}", e),
        },
        "undefined".into()
    );
}

#[tokio::test]
async fn check_fail_recursion() {
    match init(serde_yaml::from_str(include_str!("../../configs/fail_recursion.json")).unwrap())
        .await
        .err()
        .unwrap()
    {
        DrouteError::UpstreamError(UpstreamError::HybridRecursion(_)) => {}
        e => panic!("Not the right error type: {}", e),
    };
}

#[tokio::test]
async fn check_fail_multiple_def() {
    match init(serde_yaml::from_str(include_str!("../../configs/fail_multiple_def.json")).unwrap())
        .await
        .err()
        .unwrap()
    {
        DrouteError::UpstreamError(UpstreamError::MultipleDef(_)) => {}
        e => panic!("Not the right error type: {}", e),
    };
}

#[tokio::test]
async fn fail_unused_upstreams() {
    match init(
        serde_yaml::from_str(include_str!("../../configs/fail_unused_upstreams.yaml")).unwrap(),
    )
    .await
    .err()
    .unwrap()
    {
        DrouteError::UpstreamError(UpstreamError::UnusedUpstreams(_)) => {}
        e => panic!("Not the right error type: {}", e),
    };
}
