# dcompass
![自动构建](https://github.com/LEXUGE/dcompass/workflows/Build%20dcompass%20on%20various%20targets/badge.svg)  
一个高性能的 DNS 服务器，支持插件式路由规则，DoT 以及 DoH  
[中文版](README-CN.md)

# Why Do You Ever Need It
如果你对 [SmartDNS](https://github.com/pymumu/smartdns) 或 [Overture](https://github.com/shawn1m/overture) 的逻辑或速度不满，不妨尝试一下 `dcompass`

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
目前程序处于活跃开发阶段，时刻可能发生不向后兼容的变动，请以 [example.yaml](configs/example.yaml) 为准。

# 用法
```
dcompass -c path/to/config.json # 或 YAML 配置文件
```
你也可以直接在配置文件 (config.yml) 相同的文件夹下直接运行 `dcompass`

# 软件包
1. Github Action 会自动每天按照 main branch 和最新的 maxmind GeoIP 数据库对一些平台进行编译并上传到 [release page](https://github.com/LEXUGE/dcompass/releases)。如果是 Raspberry Pi 用户，建议尝试 `armv7-unknown-linux-musleabihf`, `armv5te-unknown-linux-musleabi`, `aarch64-unknown-linux-musl`。每个 target 都带有 `full`, `cn`, `min` 三个版本， `full` 包含 maxmind GeoIP2 database, `cn` 包含 GeoIP2-CN databse （只含有中国 IP）， `min` 不内置数据库。
2. NixOS 打包文件在[这里](https://github.com/icebox-nix/netkit.nix). 同时，对于 NixOS 用户，我们提供了一个包含 systemd 服务的 NixOS module 来方便用户配置。

# 配置（待翻译）
**有关最新资料，请参阅最新英文版本。**
配置文件包含不同的 fields
- `cache_size`: DNS Cache 的大小。更大的大小意味着更高的缓存容量(使用LRU算法作为后端)。
- `verbosity`: Log 等级.值可能为trace, debug, info, warn, error, off。
- `address`: 监听的地址。
- `table`:由“规则”块组成的路由表。该表不能为空，而且应该包含一个名为“start”的规则。每条规则包含“tag”、“if”、“then”和“else值。后两个应该是' (action, next) '形式的元组，这意味着首先执行操作，然后使用指定的标记转到下一个规则。
- `upstreams`: 一组上游。' timeout '是距离timeout的秒数，它对方法' Hybrid '(默认为5)不起作用。“tag”是上游的名称。' methods '是每个上游的方法。

不同的进程:
- `skip`: 什么也不做。
- `disable`: 使用SOA消息设置响应以限制进一步查询。它通常与' qtype '匹配器一起使用，以禁用某些类型的查询。
- `query(标签)`: 通过上游发送带有指定标签的查询。

不同的匹配器: (还将有更多的匹配器，包括`cidr`)
- `any`: 匹配任何东西。
- `domain(文件路径列表)`: 匹配指定域列表中的域。
- `qtype(记录类型列表)`: 匹配指定的记录类型。
- `geoip(位置: resp或src, 代码: :国家代码列表, 路径:MMDB数据库文件的可选路径)`: 如果有一个或多个' A '或' AAAA '记录处于当前状态，并且其中的第一个记录在列表中指定了国家代码，那么它就匹配，否则总是不匹配。

不同的查询方式:
- `https`: DNS覆盖HTTPS查询方法。' no_sni '表示不发送SNI(用于对抗审查)。' name '是远程服务器的TLS认证名称。' addr '是远程服务器地址。
- `tls`: DNS覆盖TLS查询方法。' no_sni '表示不发送SNI(用于对抗审查)。' name '是远程服务器的TLS认证名称。' addr '是远程服务器地址。
- `udp`:典型的UDP查询方法。' addr '是远程服务器地址。
- `hybrid`: 在多个上游一起运行。取值为上游标签的集合。注意，你可以在集合中包含另一个' hybrid '，只要它们不形成链依赖关系，这是被禁止的，并且会被' dcompass '提前检测到。

一个无需任何外部文件的防污染分流且开箱及用的配置文件 [example.yaml](configs/example.yaml)（只支持 `full` 和 `cn`， `min` 如需使用此配置需要自带 GeoIP database）。  

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

# 版权
`dmatcher`、`droute`、`dcompass`这三个组件都是在GPLv3+下授权的。
`dcompass`和`droute`与`geoip`功能门启用包括由MaxMind创建的GeoLite2数据，可从<a href="https://www.maxmind.com">https://www.maxmind.com</a>。
