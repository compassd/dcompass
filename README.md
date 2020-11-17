# dcompass
Your DNS supercharged! A high-performance DNS server with rule matching/DoT/DoH functionality built-in.

# Features
- Fast (~760 qps)
- Fearless hot switch between network environments
- Freestyle routing rules that are easy to compose and maintain
- DoH/UDP supports (DoT is on the way!)
- "Always-on" cache mechanism to ensure DNS quality under severe network environments.
- Option to send no SNI indication to better counter censorship
- Option to disable AAAA query for those having network with incomplete IPv6 supports
- Written in pure Rust

# Config
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
On `i7-10710U`, dnsperf gets out `762 qps` with `0.12s avg latency` and `0.27% ServFail` rate for a test of `15004` queries.  
As a reference SmartDNS gets `647 qps` for the same test on the same hardware.
