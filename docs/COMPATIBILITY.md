# Compatibility and Capability Matrix

## Reference contract

The only compatibility baseline is official subconverter v0.9.0 commit `b9ad0c2ee2b959e2b10195e928bf8f30f55a6a78`. `tests/fixtures/reference.toml` records release URLs and SHA-256 values. `tools/generate-golden.ps1` validates that identity before starting the reference executable.

The default golden suite compares semantic models:

- YAML/JSON: nodes, protocol types, options, groups, rules, and order.
- Text configurations: sections and normalized semantic fields, preserving node, member, and rule order.
- SS/SSR/SSD/V2Ray/Trojan/Mixed: decoded protocol fields and node order.
- HTTP: status, content type, disposition, subscription metadata, update interval, and empty HEAD bodies.

The matrix contains one pinned case for every target plus multi-protocol Clash, Surge v4, SingBox, and Mixed cases covering SS, SSR, VMess, Trojan, HTTP, and SOCKS5. Focused compatibility tests additionally cover Snell, WireGuard, malformed input, Unicode, and Rust-only Hysteria extensions.

Rust-only Hysteria and Hysteria2 support is an extension and is excluded from the v0.9.0 pass rate.

## Adapter capabilities

| Capability | CLI | Native server | Worker |
| --- | --- | --- | --- |
| Conversion and target exporters | Yes | Yes | Yes |
| Direct links and remote subscriptions | Yes | Yes | Yes |
| Local files/templates | Trusted local | Token + configured roots | Read-only KV assets |
| Pref + external config overlays | Yes | Yes | Per-request CONFIG KV |
| Subscription/config/ruleset cache | Process lifetime | Process lifetime | KV TTL |
| QuickJS filter/sort/rename/emoji/subscription scripts | Yes | Authorized requests | `501` |
| Cron scripts | No route | Yes | `501` |
| Gist upload | No | Authorized requests | `501` |
| `readconf` / `updateconf` | No | Token required | `501` |
| `flushcache` / `refreshrules` | No | Token required | `501` |
| `/get` / `/getlocal` | No | Only when `api_mode=false` | `501` |

Worker cannot perform native DNS resolution before `fetch`. It rejects literal private, loopback, link-local, ULA, metadata, credential-bearing, and disallowed redirect URLs; Cloudflare's edge isolation remains part of the hostname-resolution boundary.

## Native public routes

- `GET /version`
- `GET|HEAD /sub`
- `GET /sub2clashr`
- `GET /surge2clash`
- `GET /getruleset`
- `GET /getprofile`
- `GET /render`
- `GET /refreshrules`
- `GET /readconf`
- `POST /updateconf`
- `GET /flushcache`
- `GET /get` when API mode is disabled
- `GET /getlocal` when API mode is disabled

The machine-readable version of this matrix is `tests/fixtures/capabilities.toml`.
