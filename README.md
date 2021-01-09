# dcompass
![Automated build](https://github.com/LEXUGE/dcompass/workflows/Build%20dcompass%20on%20various%20targets/badge.svg)  
Your DNS supercharged! A high-performance DNS server with freestyle routing scheme support, DoT/DoH functionalities built-in.  
[中文版](README-CN.md)

# Why Do I Ever Need It?
Imagine you are living in a county where your ISP constantly hijacks your DNS requests and responses.  
There are solutions like DNS-over-HTTPS or DNS-over-TLS. You can use software like [CoreDNS](https://coredns.io) or stubby, but they don't simply solve the problem as only using DoT/DoH is slower in most cases.  
In order to concurrently query and not be trapped by ISP, you then try to have software like [SmartDNS](https://github.com/pymumu/smartdns) or [Overture](https://github.com/shawn1m/overture) to offer yourself some flexibility on dispatching DNS requests. However, everyone have their own story, those preset rules don't fit all at once.  
What's even worse is that you probably want to have DNS-level ad-blocking functionality, do you really want to add another layer of AdGuard Home? Can you do all of these at once?  
Indeed, you can. `dcompass` gives you full-freedom in matching and handling every DNS requests via custom routing table, and also finely-grained control over usages of upstreams.  

In short, `dcompass` enables you to write your own logic of how your DNS server should behave, as simple as possible.

# Features
- Fast (~2500 qps in wild where upstream perf is about the same)
- Fearless hot switch between network environments
- Customized routing rules that are easy to compose and maintain
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
Or you can simply run `dcompass` from the folder where your configuration file named `config.yml` resides.  
You can also validate your configuration
```
dcompass -c path/to/config.json -v
```

# Packages
You can download binaries at [release page](https://github.com/LEXUGE/dcompass/releases).
1. GitHub Action build is set up for targets `x86_64-unknown-linux-musl`, `armv7-unknown-linux-musleabihf`, `armv5te-unknown-linux-musleabi`, `x86_64-pc-windows-gnu`, `x86_64-apple-darwin`, `aarch64-unknown-linux-musl` and more. Typically, arm users should use binaries corresponding to their architecture. In particular, Raspberry Pi users can try all three (`armv7-unknown-linux-musleabihf`, `armv5te-unknown-linux-musleabi`, `aarch64-unknown-linux-musl`). Each of the targets has three different versions, namely `full`, `cn`, `min`. `full` version includes the full maxmind GeoIP2 database, while `cn` includes [GeoIP2-CN](https://github.com/Hackl0us/GeoIP2-CN/) database only. `min` includes no database at all.
2. NixOS package is available at [here](https://github.com/icebox-nix/netkit.nix). Also, for NixOS users, a NixOS modules is provided with systemd services and easy-to-setup interfaces in the same repository where package is provided.

# Quickstart
See [example.yaml](configs/example.yaml)

# Configuration
Configuration file contains different fields:
- `cache_size`: Size of the DNS cache system. Larger size implies higher cache capacity (use LRU algorithm as the backend).
- `verbosity`: Log level filter. Possible values are `trace`, `debug`, `info`, `warn`, `error`, `off`.
- `address`: The address to bind on.
- `table`: A routing table composed of `rule` blocks. The table cannot be empty and should contains a single rule named with `start`. Each rule contains `tag`, `if`, `then`, and `else`. Latter two of which are of the form `(action1, action 2, ... , next)` (you can omit the action and write ONLY `(next)`), which means take the actions first and goto the next rule with the tag specified.
- `upstreams`: A set of upstreams. `timeout` is the time in seconds to timeout, which takes no effect on method `Hybrid` (default to 5). `tag` is the name of the upstream. `methods` is the method for each upstream.

Different actions:
- `disable`: Set response with a SOA message to curb further query. It is often used accompanied with `qtype` matcher to disable certain types of queries.
- `query(tag)`: Send query via upstream with specified tag.

Different matchers: (More matchers to come)
- `any`: Matches anything.
- `domain(list of file paths)`: Matches domain in specified domain lists
- `qtype(list of record types)`: Matches record type specified.
- `geoip(on: resp or src, codes: list of country codes, path: optional path to the mmdb database file)`: If there is one or more `A` or `AAAA` records at the current state and the first of which has got a country code in the list specified, then it matches, otherwise it always doesn't match.
- `ipcidr(on: resp or src, list: list of files that contain CIDR entries)`: Same as `geoip`, but it instead matches on CIDR.

Different querying methods:
- `https`: DNS over HTTPS querying methods. `no_sni` means don't send SNI (useful to counter censorship). `name` is the TLS certification name of the remote server. `addr` is the remote server address.
- `tls`: DNS over TLS querying methods. `no_sni` means don't send SNI (useful to counter censorship). `name` is the TLS certification name of the remote server. `addr` is the remote server address.
- `udp`: Typical UDP querying method. `addr` is the remote server address.
- `hybrid`: Race multiple upstreams together. the value of which is a set of tags of upstreams. Note, you can include another `hybrid` inside the set as long as they don't form chain dependencies, which is prohibited and would be detected by `dcompass` in advance.

See [example.yaml](configs/example.yaml) for a pre-configured out-of-box anti-pollution configuration (Only works with `full` or `cn` version, to use with `min`, please provide your own database).  

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
      on: resp
      codes:
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
- [x] IP-CIDR matcher for both source address and response address
- [x] GeoIP matcher for source address
- [ ] Custom response action

# License
All three components `dmatcher`, `droute`, `dcompass` are licensed under GPLv3+.
`dcompass` and `droute` with `geoip` feature gate enabled include GeoLite2 data created by MaxMind, available from <a href="https://www.maxmind.com">https://www.maxmind.com</a>.
