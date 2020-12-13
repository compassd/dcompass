# dcompass
![Automated build](https://github.com/LEXUGE/dcompass/workflows/Build%20dcompass%20on%20various%20targets/badge.svg)  
Your DNS supercharged! A high-performance DNS server with freestyle routing scheme support, DoT/DoH functionalities built-in.

# Features
- Fast (~2500 qps in wild where upstream perf is about the same)
- Fearless hot switch between network environments
- Freestyle routing rules that are easy to compose and maintain
- DoH/DoT/UDP supports
- "Always-on" cache mechanism to ensure DNS quality under severe network environments.
- Option to send no SNI indication to better counter censorship
- Option to disable AAAA query for those having network with incomplete IPv6 supports
- Written in pure Rust

# Notice
Breaking changes happened as new routing scheme has been adopted, see configuration section below to adapt.

# Usages
```
dcompass -c path/to/config.json # Or YAML
```

# Packages
1. GitHub Action build is set up for targets `x86_64-unknown-linux-musl`, `armv7-unknown-linux-musleabihf`, `armv5te-unknown-linux-musleabi`, `x86_64-pc-windows-gnu`, `x86_64-apple-darwin`, `aarch64-unknown-linux-musl` and more. You can download binaries at [release page](https://github.com/LEXUGE/dcompass/releases). Typically, arm users should use binaries corresponding to their architecture. In particular, Raspberry Pi users can try all three (`armv7-unknown-linux-musleabihf`, `armv5te-unknown-linux-musleabi`, `aarch64-unknown-linux-musl`).
2. NixOS package is available at [here](https://github.com/icebox-nix/netkit.nix). Also, for NixOS users, a NixOS modules is provided with systemd services and easy-to-setup interfaces in the same repository where package is provided.

# Configuration
Configuration file contains different fields:
- `cache_size`: Size of the DNS cache system. Larger size implies higher cache capacity (use LRU algorithm as the backend).
- `verbosity`: Log level filter. Possible values are `trace`, `debug`, `info`, `warn`, `error`, `off`.
- `address`: The address to bind on.
- `table`: A routing table composed of `rule` blocks. The table cannot be empty and should contains a single rule named with `start`. Each rule contains `tag`, `if`, `then`, and `else`. Latter two of which are tuples of the form `(action, next)`, which means take the action first and goto the next rule with the tag specified.
- `upstreams`: A set of upstreams. `timeout` is the time in seconds to timeout, which takes no effect on method `Hybrid` (default to 5). `tag` is the name of the upstream. `methods` is the method for each upstream.

Different actions:
- `skip`: Do nothing.
- `disable`: Set response with a SOA message to curb further query. It is often used accompanied with `qtype` matcher to disable certain types of queries.
- `query(tag)`: Send query via upstream with specified tag.

Different matchers: (More matchers to come, including `cidr`)
- `any`: Matches anything.
- `domain(list of file paths)`: Matches domain in specified domain lists
- `qtype(list of record types)`: Matches record type specified.
- `geoip(list of ISO country codes)`: If there is one or more `A` or `AAAA` records at the current state and the first of which has got a country code in the list specified, then it matches, otherwise it always doesn't match.

Different querying methods:
- `https`: DNS over HTTPS querying methods. `no_sni` means don't send SNI (useful to counter censorship). `name` is the TLS certification name of the remote server. `addr` is the remote server address.
- `tls`: DNS over TLS querying methods. `no_sni` means don't send SNI (useful to counter censorship). `name` is the TLS certification name of the remote server. `addr` is the remote server address.
- `udp`: Typical UDP querying method. `addr` is the remote server address.
- `hybrid`: Race multiple upstreams together. the value of which is a set of tags of upstreams. Note, you can include another `hybrid` inside the set as long as they don't form chain dependencies, which is prohibited and would be detected by `dcompass` in advance.

Below is an example that races multiple upstreams, disables `AAAA` queries, and dispatches queries using domain matching (Both `JSON` and `YAML` are accepted):
<details><summary>Configuration example</summary>
```yaml
---
verbosity: info
cache_size: 4096
address: 0.0.0.0:2053
table:
- tag: start
  if:
    qtype:
    - AAAA
  then:
  - disable
  - end
  else:
  - skip
  - dispatch

- tag: dispatch
  if:
    domain:
    - PATH TO DOMAIN LIST
  then:
  - query: domestic
  - end
  else:
  - query: secure
  - end


upstreams:
- timeout: 2
  method:
    udp: 114.114.114.114:53
  tag: 114DNS

- timeout: 2
  method:
    udp: 223.6.6.6:53
  tag: Ali

- method:
    hybrid:
    - 114DNS
    - Ali
  tag: domestic

- method:
    https:
      no_sni: true
      name: cloudflare-dns.com
      addr: 1.1.1.1:443
  tag: cloudflare

- method:
    https:
      no_sni: true
      name: dns.quad9.net
      addr: 9.9.9.9:443
  tag: quad9

- method:
    hybrid:
    - cloudflare
    - quad9
  tag: secure
```
</details>

Table example of using GeoIP to mitigate pollution

```yaml
table:
- tag: start
  if: any
  then:
  - query: domestic
  - check_secure
- tag: check_secure
  if:
    geoip:
    - CN
  else:
  - query: secure
  - end
```

# Behind the scene details
- if one incoming DNS message contains more than one DNS query (which is impossible in wild), matchers only care about the first one.
- If a cache record is expired, we return back the expired cache and start a background query to update the cache, if which failed, the expired cache would be still returned back and background query would start again for next query on the same domain. The cache only gets purged if the internal LRU cache system purges it. This ensures cache is always available while dcompass complies TTL.

# Benchmark
Mocked benchmark:
```
non_cache_resolve       time:   [10.624 us 10.650 us 10.679 us]
                        change: [-0.9733% -0.0478% +0.8159%] (p = 0.93 > 0.05)
                        No change in performance detected.
Found 12 outliers among 100 measurements (12.00%)
  1 (1.00%) low mild
  6 (6.00%) high mild
  5 (5.00%) high severe

cached_resolve          time:   [10.712 us 10.748 us 10.785 us]
                        change: [-5.2060% -4.1827% -3.1967%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 10 outliers among 100 measurements (10.00%)
  2 (2.00%) low mild
  7 (7.00%) high mild
  1 (1.00%) high severe
```

Following benchmarks are not mocked, but they are rather based on multiple perfs in wild. Not meant to be accurate for statical purposes.
- On `i7-10710U`, dnsperf gets out `~760 qps` with `0.12s avg latency` and `0.27% ServFail` rate for a test of `15004` queries.
- As a reference SmartDNS gets `~640 qps` for the same test on the same hardware.

# TODO-list
- [ ] Support multiple inbound servers with different types like `DoH`, `DoT`, `TCP`, and `UDP`.
- [ ] IP-CIDR matcher for both source address and response address
- [ ] GeoIP matcher for source address
- [ ] Custom response action

# License
All three components `dmatcher`, `droute`, `dcompass` are licensed under GPLv3+.
`dcompass` and `droute` with `geoip` feature gate enabled include GeoLite2 data created by MaxMind, available from <a href="https://www.maxmind.com">https://www.maxmind.com</a>.
