# dcompass
Your DNS supercharged! A high-performance DNS server with rule matching/DoT/DoH functionality built-in.

# Features
- Fast (~760 qps)
- Fearless hot switch between network environments
- Freestyle routing rules that are easy to compose and maintain
- DoH/DoT/UDP supports
- "Always-on" cache mechanism to ensure DNS quality under severe network environments.
- Option to send no SNI indication to better counter censorship
- Option to disable AAAA query for those having network with incomplete IPv6 supports
- Written in pure Rust

# Usages
```
dcompass -c path/to/config.json
```

# Packages
1. GitHub Action periodic build is set up for target `linux-x86_64`, `linux-armv7`, `windows-x86_64`, `macos-x86_64`, running once a week. You can download artifacts at [here](https://github.com/LEXUGE/dcompass/actions?query=workflow%3A%22Build+dcompass+on+various+targets%22).
2. NixOS package is available at [here](https://github.com/icebox-nix/netkit.nix). Also, for NixOS users, a NixOS modules is provided with systemd services and easy-to-setup interfaces in the same repository where package is provided.

# Configuration
Here is a simple configuration file with different fields:
- `disable_ipv6`: Send back SOA response directly back for any AAAA queries
- `cache_size`: Size of the DNS cache system. Larger size implies higher cache capacity (use LRU algorithm as the backend).
- `verbosity`: Log level filter. Possible values are `Trace`, `Debug`, `Info`, `Warn`, `Error`, `Off`.
- `address`: The address to bind on.
- `default_tag`: The tag of the upstream to route when no rules match.
- `rules`: A set of filtering rules that each has a `path` to the rule list (currently only domain lists are supported) and `dst` which is the tag of the upstream to route if it matches this rule. If one domain appears on multiple lists, the latter list and its corresponding `dst` would override the former ones.
- `upstreams`: A set of upstreams. `timeout` is the time in seconds to timeout, which takes no effect on method `Hybrid` (default to 5). `tag` is the name of the upstream. `methods` is the method for each upstream.

Different querying methods:
- `Https`: DNS over HTTPS querying methods. `no_sni` means don't send SNI (useful to counter censorship). `name` is the TLS certification name of the remote server. `addr` is the remote server address.
- `Tls`: DNS over TLS querying methods. `no_sni` means don't send SNI (useful to counter censorship). `name` is the TLS certification name of the remote server. `addr` is the remote server address.
- `Udp`: Typical UDP querying method. `addr` is the remote server address.
- `Hybrid`: Race multiple upstreams together. the value of which is a set of tags of upstreams. Note, you can include another `Hybrid` inside the set as long as they don't form chain dependencies, which is prohibited and would be detected by `dcompass` in advance.
```json
{
    "disable_ipv6": true,
    "cache_size": 4096,
    "verbosity": "Info",
    "address": "0.0.0.0:53",
    "default_tag": "secure",
    "rules": [
        {
            "path": "PATH TO DOMAIN LIST",
            "dst": "domestic"
        }
    ],
    "upstreams": [
        {
            "timeout": 2,
            "method": {
                "Udp": "114.114.114.114:53"
            },
            "tag": "114dns"
        },
        {
            "timeout": 2,
            "method": {
                "Udp": "223.5.5.5:53"
            },
            "tag": "ali"
        },
        {
            "timeout": 3,
            "method": {
                "Hybrid": [
                    "114dns",
                    "ali"
                ]
            },
            "tag": "domestic"
        },
        {
            "timeout": 4,
            "method": {
                "Https": {
                    "no_sni": true,
                    "name": "cloudflare-dns.com",
                    "addr": "1.1.1.1:443"
                }
            },
            "tag": "cloudflare"
        },
        {
            "timeout": 4,
            "method": {
                "Https": {
                    "no_sni": true,
                    "name": "dns.quad9.net",
                    "addr": "9.9.9.9:443"
                }
            },
            "tag": "quad9"
        },
        {
            "timeout": 5,
            "method": {
                "Hybrid": [
                    "cloudflare",
                    "quad9"
                ]
            },
            "tag": "secure"
        }
    ]
}
```

# Behind the scene details
- if `disable_ipv6` is set to `true`, a SOA message would be sent back every time we receive an `AAAA` query.
- if one incoming DNS message contains more than one DNS query (which is impossible in wild), `default_tag` would be used to send the query.
- If a cache record is expired, we return back the expired cache and start a background query to update the cache, if which failed, the expired cache would be still returned back and background query would start again for next query on the same domain. The cache only gets purged if the internal LRU cache system purges it. This ensures cache is always available while dcompass complies TTL.

# Benchmark
Following benchmarks are not mocked, but they are rather based on multiple perfs in wild. Not meant to be accurate for statical purposes.
- On `i7-10710U`, dnsperf gets out `~760 qps` with `0.12s avg latency` and `0.27% ServFail` rate for a test of `15004` queries.
- As a reference SmartDNS gets `~640 qps` for the same test on the same hardware.
