# Migration and Security Guide

## Moving from v0.9.0

1. Keep the existing v0.9.0 service available on a separate port for differential checks.
2. Copy trusted base templates, rules, profiles, and pref configuration. Do not copy caches, tokens, logs, generated outputs, or real subscription data into source control.
3. Convert pref configuration to INI, TOML, or YAML as needed. Effective priority is request parameters over external config over pref config over defaults.
4. Set a non-empty `API_TOKEN` before enabling management operations or client-selected local files.
5. Run `.\tools\verify.ps1 -SkipContainer` and compare representative production requests against the pinned reference.
6. Start the native server, verify `/version`, one local conversion, one remote conversion, HEAD behavior, and response headers, then switch traffic.

For a managed native deployment, extract a release and run
`subconverter-server service install` from an elevated terminal. It creates a
minimal secure `pref.toml`; copy reviewed settings into the managed data
directory and restart. Re-running the install command upgrades the binary and
official `base/` while preserving configuration, profiles, scripts, and logs.
See [native service deployment](SERVICES.md) for OS paths and rollback-safe
uninstallation.

## Secure defaults

- `api_mode=true`.
- Native listens on `127.0.0.1` by default.
- Management routes return `403` unless a non-empty configured token matches.
- Client-selected local files require a token and must remain under `base/` or `profiles/`.
- Remote URLs must use HTTPS and resolve to public addresses.
- Loopback, private, link-local, ULA, cloud metadata, credential-bearing, and unsafe redirect targets are blocked.
- Download limit is 1 MiB.
- Connect timeout is 10 seconds; total timeout is 30 seconds.
- Redirect limit is five.
- QuickJS defaults to 16 MiB and a one-second execution deadline.

Error mapping is stable: policy refusal `403`, oversize `413`, unsupported adapter capability `501`, upstream failure `502`, and upstream timeout `504`.

The stricter management-token and network/file policies are intentional compatibility deviations from the historically open deployment style. Relax them only through explicit trusted configuration:

```toml
[security]
allow_private_network = true
allow_plain_http = true
allowed_local_roots = ["base", "profiles"]
max_download_bytes = 1048576
connect_timeout_seconds = 10
request_timeout_seconds = 30
max_redirects = 5
```

Do not expose `/get`, `/getlocal`, or management routes to untrusted clients even when a token is configured.

## Worker deployment

Worker provides the portable conversion subset. QuickJS, cron, Gist, local management, and mutable management routes intentionally return `501`.

Create a KV namespace, then generate the deployment configuration without editing `wrangler.toml`:

```powershell
$env:CF_KV_NAMESPACE_ID = "<real namespace id>"
.\tools\generate-worker-config.ps1
.\tools\deploy-worker.ps1
```

Store pref configuration as one of `pref.toml`, `pref.yml`, `pref.yaml`, or `pref.ini` in CONFIG KV. Store templates and other read-only assets in ASSETS KV. Environment variables override KV pref values.
