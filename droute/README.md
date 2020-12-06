# droute
`droute` is a simple, robust, pluggable DNS routing library. It supports DoT, DoH, upstream-racing, and customized routing schemes with plugins. It is also the backend for `dcompass`, a robust DNS server.

# Feature gates
It has following feature gates to be enabled on need:
- `doh`: enable DNS over HTTPS upstream support
- `dot`: enable DNS over TLS upstream support
- `serde-cfg`: enable serde-aided structure serialization/deserialization
