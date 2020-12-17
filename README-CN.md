# dcompass
![自动构建](https://github.com/LEXUGE/dcompass/workflows/Build%20dcompass%20on%20various%20targets/badge.svg)  
一个高性能的 DNS 服务器，支持插件式路由规则，DoT 以及 DoH  
[中文版](README-CN.md)

# 特色
- 高速 (实测约 2500 qps, 接近上游当前环境下的性能上限）
- 无需畏惧网络环境的切换（如 4G 切换到 Wi-Fi ）
- 自由路由规则编写，简洁易维护的规则语法
- 丰富的匹配器，作用器插件来实现大部分的需求
- DoH/DoT/UDP 协议支持
- 惰性 Cache 实现，在尽可能遵守 TTL 的前提下提高返回速度，保障恶劣网络环境下的使用体验
- 可选不发送 SNI 来防止连接被切断
- 原生跨平台实现，支持 Linux (ARM/x86)/Windows/macOS
- 纯 Rust 实现，占用低且内存安全

# 注意
目前程序处于活跃开发阶段，时刻可能发生不向后兼容的变动，请以 [example.yaml](example.yaml) 为准。

# 用法
```
dcompass -c path/to/config.json # 或 YAML 配置文件
```

# 软件包
1. Github Action 会自动每天按照 main branch 和最新的 maxmind GeoIP 数据库对一些平台进行编译并上传到 [release page](https://github.com/LEXUGE/dcompass/releases)。如果是 Raspberry Pi 用户，建议尝试 `armv7-unknown-linux-musleabihf`, `armv5te-unknown-linux-musleabi`, `aarch64-unknown-linux-musl`。
2. NixOS 打包文件在[这里](https://github.com/icebox-nix/netkit.nix). 同时，对于 NixOS 用户，我们提供了一个包含 systemd 服务的 NixOS module 来方便用户配置。

# 配置（待翻译）
配置文件包含不同的 fields
- `cache_size`: DNS Cache 的大小. Larger size implies higher cache capacity (use LRU algorithm as the backend).
- `verbosity`: Log 等级. Possible values are `trace`, `debug`, `info`, `warn`, `error`, `off`.
- `address`: 监听的地址。
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

一个无需任何外部文件的防污染分流且开箱及用的配置文件 [example.yaml](example.yaml)。  

使用 GeoIP 来防污染的路由表（table）样例

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

# 值得说明的细节
- 如果一个数据包包含有多个 DNS 请求（实际几乎不可能），匹配器只会对多个 DNS 请求的第一个进行匹配。
- Cache record 一旦存在，只有在 LRU 算法将其丢弃时才会被丢弃，否则即使过期，还是会被返回，并且后台会并发一个任务来尝试更新这个 cache。

# Benchmark
模拟测试（忽略网络请求的时间）:
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

下面是实测，不具有统计学意义
- On `i7-10710U`, dnsperf gets out `~760 qps` with `0.12s avg latency` and `0.27% ServFail` rate for a test of `15004` queries.
- As a reference SmartDNS gets `~640 qps` for the same test on the same hardware.

# 计划
- [ ] 支持自由配置的 inbound server 选项，包括 `DoH`, `DoT`, `TCP`, 和 `UDP`。
- [ ] IP-CIDR 匹配器，可用于 source IP 或 response IP
- [x] GeoIP 匹配器，可用于 source IP 或 response IP
- [ ] 支持自由返回结果的上游（upstream）

# License
All three components `dmatcher`, `droute`, `dcompass` are licensed under GPLv3+.
`dcompass` and `droute` with `geoip` feature gate enabled include GeoLite2 data created by MaxMind, available from <a href="https://www.maxmind.com">https://www.maxmind.com</a>.
