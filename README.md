# subconverter-rs

Production-oriented Rust replacement for official `subconverter` v0.9.0, fixed at commit `b9ad0c2ee2b959e2b10195e928bf8f30f55a6a78`.

Compatibility is semantic: nodes, groups, rules, ordering, HTTP status, and response headers are compared after parsing. YAML/JSON field order, formatting, comments, and whitespace are not part of the contract. Reference release metadata and SHA-256 values are pinned in `tests/fixtures/reference.toml`.

## Crates

- `subconverter-core`: proxy models, config parsing, URL/base64 helpers, route-compatible request handling, and conversion entrypoints.
- `subconverter-cli`: local CLI and generator-mode shell.
- `subconverter-server`: native HTTP server compatible with the original routes.
- `subconverter-worker`: Cloudflare Worker adapter using the same core.

## Compatibility Surface

Native CLI/server targets:

- Clash, ClashR
- Surge v2/v3/v4 (v3 is the default)
- Quan, QuanX, Loon, Surfboard, Mellow
- SingBox
- SS, SSSub, SSD, SSR, V2Ray, Trojan, Mixed
- `target=auto`

Hysteria and Hysteria2 remain Rust extensions and are not claimed as v0.9.0 compatibility targets.

Native server routes:

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
- `GET /get`
- `GET /getlocal`

Conversion behavior is centralized in `subconverter-core`. `tests/fixtures/cases.full.toml` contains 18 target cases plus four multi-protocol cases and is always executed by `cargo test`; it has no environment-variable skip path.

Implemented `/sub` request compatibility includes explicit targets and `target=auto` User-Agent inference, remote/local/direct subscription sources, `default_url` fallback with API mode token gating, external `config`, `enable_insert`/`insert_url` with request `insert` and `prepend` overrides, inline `groups` and `ruleset` parameters, managed Clash `rule-providers` backed by `/getruleset` when `expand=false`, `classic=true` classical Clash provider generation, node `group` override, node `include`/`exclude`, `rename`, emoji add/remove controls, deprecated Clash node filtering via `filter_deprecated_nodes`/`fdn`, `sort`, `list`, `append_type`, common node switches such as `udp`, `tfo`, `scv`, and `tls13`, config defaults such as `append_proxy_type`, `sort_flag`, `udp_flag`, `tcp_fast_open_flag`, `skip_cert_verify_flag`, and `tls13_flag`, response headers for `interval`/`filename`, `Subscription-UserInfo` forwarding/derivation with `append_sub_userinfo` and `append_info` gating, and Surge/Surfboard managed-config prefixes when enabled.

Implemented `/getprofile` compatibility includes profile token/global token validation, `[Profile]` argument parsing, repeated `url`/`rename`/`include`/`exclude` merging, and `name=a|b` multi-profile URL merging.

Configuration is applied in this order: defaults, pref configuration, external configuration, then request parameters. INI, TOML, and YAML overlays preserve omitted values and honor explicit `false` values. Native adapters support authorized QuickJS filter/sort/rename/emoji/subscription scripts with a default 16 MiB memory cap and one-second deadline.

See [compatibility and adapter capabilities](docs/COMPATIBILITY.md) and the [migration and security guide](docs/MIGRATION.md).

## Run

```powershell
cargo run -p subconverter-server
curl http://127.0.0.1:25500/version
```

## CLI

Single target conversion:

```powershell
cargo run -p subconverter-cli -- --target clash --url .\subscription.txt --artifact .\out\clash.yaml
```

Generator mode without `--target` writes the supported artifact targets into the artifact directory:

```powershell
cargo run -p subconverter-cli -- -g --url .\subscription.txt --artifact .\out
```

## Container

Build and run the native server container:

```powershell
docker build -t subconverter-rs .
docker run --rm -p 25500:25500 subconverter-rs
curl http://127.0.0.1:25500/version
```

The image copies `base/` into `/app/base`, exposes `25500`, and defaults `LISTEN=0.0.0.0` plus `PORT=25500`. Native non-container execution remains bound to `127.0.0.1` by default.

## Verification

Run the workspace tests and core cross-target compile checks:

```powershell
cargo test --workspace
.\tools\check-core-std-targets.ps1
.\tools\smoke-server.ps1
.\tools\smoke-container.ps1
```

Or run the local verification bundle:

```powershell
.\tools\verify.ps1
```

Validate the pinned reference manifest and run the full semantic golden suite:

```powershell
.\tools\generate-golden.ps1 -Manifest cases.full.toml -ValidateOnly
cargo test -p subconverter-core --test golden
```

Golden regeneration refuses an executable whose version metadata or SHA-256 does not match `tests/fixtures/reference.toml`.

Pass explicit target triples to check targets that are installed in CI or locally:

```powershell
.\tools\check-core-std-targets.ps1 -Target x86_64-unknown-linux-gnu,wasm32-unknown-unknown
```

## Cloudflare Worker

The Worker adapter loads pref configuration from CONFIG KV for every request, applies environment overrides, and uses the same core conversion logic. Remote subscriptions use Workers `fetch`; templates and other read-only assets use ASSETS KV.

Supported Worker vars/secrets:

- `PORT`
- `LISTEN`
- `API_MODE`
- `MANAGED_PREFIX`
- `API_TOKEN`
- `UPSTREAM_USER_AGENT`
- `ASSET_KV_BINDING`
- `CONFIG_KV_BINDING`
- `CACHE_KV_BINDING`

`wrangler.toml` intentionally contains no deployable KV namespace. Generate a deployment-only file from a real namespace ID:

```powershell
$env:CF_KV_NAMESPACE_ID = "<real namespace id>"
$env:CF_CUSTOM_DOMAIN = "subconv.example.com"
$env:CF_UPSTREAM_USER_AGENT = "subconverter-rs/0.1.0"
.\tools\generate-worker-config.ps1
.\tools\deploy-worker.ps1
```

`CF_CUSTOM_DOMAIN` is optional. When set, the generated config deploys the hostname as a
Cloudflare Worker Custom Domain. `CF_UPSTREAM_USER_AGENT` is also optional. Remote
downloads omit `User-Agent` by default for subconverter v0.9.0 compatibility; set this
variable only when an upstream subscription provider requires a user agent.

Build or check the Worker locally:

```powershell
cd crates/subconverter-worker
worker-build --release . --features cloudflare
cd ..\..
cargo check -p subconverter-worker --target wasm32-unknown-unknown --features cloudflare
```

The generated `work/wrangler.generated.toml` and Worker build directory are ignored artifacts. Worker deliberately returns `501` for QuickJS scripts, cron, Gist upload, `readconf`, `updateconf`, `flushcache`, `refreshrules`, `/get`, and `/getlocal`.
