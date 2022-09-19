# dcompass

![Automated build](https://github.com/LEXUGE/dcompass/workflows/Build%20dcompass%20on%20various%20targets/badge.svg)
[![Join telegram channel](https://badges.aleen42.com/src/telegram.svg)](https://t.me/dcompass_channel)  
A high-performance programmable DNS component.  
[中文版（未更新）](README-CN.md)

# Features

- Fast (~50000 qps in wild where upstream perf is about the same)
- Rust-like scripting with [rune](https://rune-rs.github.io)
- Fearless hot switch between network environments
- Written in pure Rust

# Notice
**[2022-09-19] More efficient and robust scripting with rune**  
Introducing dcompass v0.3.0. With the rune script engine, dcompass is about 2-6x faster than the previous version with unparalleled concurrency stability. However, existing configurations are no longer valid. Please see example configs to migrate.

**[2022-06-22] All-new script engine**  
Introducing dcompass v0.2.0. With the new script engine, you can now access every bit, every record, and every section of every DNS message. Program dcompass into whatever you want! However, existing configurations are no longer valid. Please see examples to migrate.

**[2021-9-16] Expression Engine and breaking changes**  
dcompass is now equipped with an expression engine which let you easily and freely compose logical expressions with existing matchers. This enables us to greatly improve config readablity and versatility. However, all existing config files involving if rule block are no longer working. Please see examples to migrate.

**[2021-07-28] 2x faster and breaking changes**  
We adopted a brand new bare metal DNS library `domain` which allows us to manipulate DNS messages without much allocation. This adoption significantly improves the memory footprint and throughput of dcompass. Due to this major refactorization, DoT/TCP/zone protocol are temporarily unavailable, however, UDP and DoH connections are now blazing fast. We will gradually put back those protocols.

# Usages

```
dcompass -c path/to/config.json # Or YAML
```

Or you can simply run `dcompass` from the folder where your configuration file named `config.yml` resides.  
You can also validate your configuration

```
dcompass -c path/to/config.json -v
```

# Quickstart

See [example.yaml](configs/example.yaml)  

Below is a script using GeoIP to mitigate DNS pollution

```yaml
script: |
  pub async fn route(upstreams, inited, ctx, query) {
    let resp = upstreams.send_default("domestic", query).await?;

    for ans in resp.answer? {
      match ans.rtype.to_str() {
        "A" if !inited.geoip.0.contains(ans.to_a()?.ip, "CN") => { return upstreams.send_default("secure", query).await; }
        "AAAA" if !inited.geoip.0.contains(ans.to_aaaa()?.ip, "CN") => { return upstreams.send_default("secure", query).await; }
        _ => continue,
      }
    }
    Ok(resp)
  }

  pub async fn init() {
    Ok(#{"geoip": Utils::GeoIp(GeoIp::create_default()?)})
  }
```

And another script that adds EDNS Client Subnet record into the OPT pseudo-section:

```yaml
script: |
  pub async fn route(upstreams, inited, ctx, query) {
    // Optionally remove all the existing OPT pseudo-section(s)
    // query.clear_opt();

    query.push_opt(ClientSubnet::new(u8(15), u8(0), IpAddr::from_str("23.62.93.233")?).to_opt_data())?;

    upstreams.send_default("ali", query).await
  }
```

Or implement your simple xip.io service:
```yaml
script: |
  pub async fn route(upstreams, inited, ctx, query) {
    let header = query.header;
    header.qr = true;
    query.header = header;

    let ip_str = query.first_question?.qname.to_str();
    let ip = IpAddr::from_str(ip_str.replace(".xip.io", ""))?;

    query.push_answer(DnsRecord::new(query.first_question?.qname, Class::from_str("IN")?, 3600, A::new(ip)?.to_rdata()))?;

    Ok(query)
  }
```

# Configuration

Configuration file contains different fields:

- `verbosity`: Log level filter. Possible values are `trace`, `debug`, `info`, `warn`, `error`, `off`.
- `address`: The address to bind on.
- `script`: The routing script composed of `init` and `route` snippets. `init` is run once to prepare repeatedly used components like matchers in order to avoid overhead. `script` snippet is run for every incoming DNS request concurrently.
- `upstreams`: A set of upstreams. `timeout` is the time in seconds to timeout, which takes no effect on method `Hybrid` (default to 5). `tag` is the name of the upstream. `methods` is the method for each upstream.

Different utilities:

- `blackhole(Message)`: Set response with a SOA message to curb further query. It is often used accompanied with `qtype` to disable certain types of queries.
- `upstreams.send(tag, [optional] cache policy, Message)`: Send query via upstream with specified tag. Configure cache policy with one of the three levels: `disabled`, `standard`, `persistent`. See also [example](configs/query_cache_policy.yaml).

Geo IP matcher:

- `GeoIp::create_default() -> Result<GeoIp>`: Create a new Geo IP matcher from builtin Geo IP database.
- `GeoIp::from_path(path) -> Result<GeoIp>`: Create a new GeoIp matcher from the Geo IP database file with the path given.
- `geoip.contains(IP address, country code)`: whether the IPs belonged to the given country code contains the given IP address

IP CIDR matcher:

- `IpCidr::new()`: Create an empty IP CIDR matcher.
- `ipcidr.add_file(path)`: Read IP CIDR rules from the given file and add them to the IP CIDR matcher.
- `ipcidr.contains(IP address)`: whether the given IP address matches any rule in the IP CIDR matcher.

Domain matcher:

- `Domain::new()`: Create an empty domain matcher.
- `domain.add_qname(domain)`: Add the given domain to the domain matcher's ruleset.
- `domain.add_file(path)`: Read domains from the given file and add them to the domain matcher.
- `domain.contains(domain)`: whether the given domain matches any rule in the domain matcher.

Different querying methods:

- `https`: DNS over HTTPS querying methods. `uri` is the remote server address in the form like `https://cloudflare-dns.com/dns-query`. `addr` is the server IP address (both IPv6 and IPv4) are accepted. HTTP and SOCKS5 proxies are also accepted on establishing connections via `proxy`, whose format is like `socks5://[user:[passwd]]@[ip:[port]]`.
- `tls`: DNS over TLS querying methods. `sni` controls whether to send SNI (useful to counter censorship). `domain` is the TLS certification name of the remote server. `addr` is the remote server address. `max_reuse` controls the maximum number of recycling of each client instance.
- `udp`: Typical UDP querying method. `addr` is the remote server address.
- `hybrid`: Race multiple upstreams together. the value of which is a set of tags of upstreams. Note, you can include another `hybrid` inside the set as long as they don't form chain dependencies, which is prohibited and would be detected by `dcompass` in advance.
- `zone`: [CURRENTLY UNSUPOORTED] use local DNS zone file to provide customized responses. See also [zone config example](configs/success_zone.yaml)

See [example.yaml](configs/example.yaml) for a pre-configured out-of-box anti-pollution configuration (Only works with `full` or `cn` version, to use with `min`, please provide your own database).

# Packages

You can download binaries at [release page](https://github.com/LEXUGE/dcompass/releases).

1. GitHub Action build is set up `x86_64`, `i686`, `arm`, and `mips`. Check them out on release page!
2. NixOS package is available at this repo as a flake. Also, for NixOS users, a NixOS modules is provided with systemd services and easy-to-setup interfaces in the same repository where package is provided.

```
└───packages
    ├───aarch64-linux
    │   ├───dcompass-cn: package 'dcompass-cn-git'
    │   └───dcompass-maxmind: package 'dcompass-maxmind-git'
    ├───i686-linux
    │   ├───dcompass-cn: package 'dcompass-cn-git'
    │   └───dcompass-maxmind: package 'dcompass-maxmind-git'
    ├───x86_64-darwin
    │   ├───dcompass-cn: package 'dcompass-cn-git'
    │   └───dcompass-maxmind: package 'dcompass-maxmind-git'
    └───x86_64-linux
        ├───dcompass-cn: package 'dcompass-cn-git'
        └───dcompass-maxmind: package 'dcompass-maxmind-git'
```

cache is available at [cachix](https://dcompass.cachix.org), with public key `dcompass.cachix.org-1:uajJEJ1U9uy/y260jBIGgDwlyLqfL1sD5yaV/uWVlbk=` (`outputs.publicKey`).

# Benchmark

Mocked benchmark (server served on local loopback):

```
Gnuplot not found, using plotters backend
non_cache_resolve       time:   [20.548 us 20.883 us 21.282 us]
                        change: [-33.128% -30.416% -27.511%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 11 outliers among 100 measurements (11.00%)
  6 (6.00%) high mild
  5 (5.00%) high severe

cached_resolve          time:   [2.6429 us 2.6493 us 2.6566 us]
                        change: [-90.684% -90.585% -90.468%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 2 outliers among 100 measurements (2.00%)
  1 (1.00%) high mild
  1 (1.00%) high severe
```

# TODO-list

- [ ] Support multiple inbound servers with different types like `DoH`, `DoT`, `TCP`, and `UDP`.
- [ ] RESTful API and web dashboard
- [x] Flexible DNS message editing API
- [x] Script engine
- [x] IP-CIDR matcher for both source address and response address
- [x] GeoIP matcher for source address

# License

All three components `dmatcher`, `droute`, `dcompass` are licensed under GPLv3+.
`dcompass` with `geoip` feature gate enabled includes GeoLite2 data created by MaxMind, available from <a href="https://www.maxmind.com">https://www.maxmind.com</a>.
