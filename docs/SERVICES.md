# Native service deployment

`subconverter-server` can install and manage itself as a Windows SCM service,
systemd unit, launchd daemon, systemd user unit, or macOS LaunchAgent. The same
server runtime is used in foreground and managed modes.

## Commands

Run an elevated terminal for a system installation:

```text
subconverter-server service install
subconverter-server service status
subconverter-server service restart
subconverter-server service stop
subconverter-server service start
subconverter-server service uninstall
```

Installation defaults to system scope, enables startup at boot, and starts the
service immediately. Use `--no-start` to register it without starting:

```text
subconverter-server service install --no-start
```

Linux and macOS also support a per-user login service:

```text
subconverter-server service install --scope user
subconverter-server service status --scope user
```

Windows uses the real Service Control Manager and rejects `--scope user`.
systemd user units and LaunchAgents start when that user logs in. Installation
does not enable Linux linger.

The status command prints exactly one of the following and uses the listed exit
code:

| Output | Exit code |
| --- | ---: |
| `running` | 0 |
| `stopped` | 3 |
| `not-installed` | 4 |

Only one fixed instance may be installed on a machine. Linux and macOS reject
installation when the other scope is already installed.

## Foreground and custom paths

No arguments preserve the original foreground behavior. An explicit data
directory can be selected with:

```text
subconverter-server serve --data-dir /path/to/state
```

The installer discovers `base/` beside the release binary or in the current
directory. Release layouts can be specified explicitly:

```text
subconverter-server service install \
  --asset-dir /path/to/extracted-release \
  --data-dir /path/to/state
```

`--asset-dir` must contain a `base/` directory. It never becomes part of the
service command line after installation.

## Managed locations

| Platform and scope | Program | Data |
| --- | --- | --- |
| Windows system | `%ProgramFiles%\subconverter-rs\subconverter-server.exe` | `%ProgramData%\subconverter-rs` |
| Linux system | `/usr/local/bin/subconverter-server` | `/var/lib/subconverter-rs` |
| Linux user | `<data>/bin/subconverter-server` | `$XDG_DATA_HOME/subconverter-rs` or `~/.local/share/subconverter-rs` |
| macOS system | `/usr/local/bin/subconverter-server` | `/Library/Application Support/subconverter-rs` |
| macOS user | `<data>/bin/subconverter-server` | `~/Library/Application Support/subconverter-rs` |

System services run as `LocalService`, `subconverter`, and `_subconverter` on
Windows, Linux, and macOS respectively. The installer protects the data and
program directories and keeps managed `base/` assets read-only to the service
account. User services run with the current user's permissions.

The first installation creates this active, minimal security configuration
instead of activating `pref.example.toml`:

```toml
[common]
api_mode = true
api_access_token = ""
base_path = "base"

[server]
listen = "127.0.0.1"
port = 25500

[security]
upstream_user_agent = ""
```

An empty token intentionally leaves management routes inaccessible. Add a
strong token directly to the protected `pref.toml` before exposing any
management route. Tokens and subscription URLs are never written into service
definitions.

## Upgrade and removal

Run `service install` again from a newly extracted release to upgrade. It stops
and unregisters the old service, atomically replaces the managed binary and
official `base/`, preserves `pref.*`, `profiles/`, `scripts/`, `logs/`, and
other data, then registers and starts the service again. `--no-start` leaves
the upgraded service stopped.

`service uninstall` stops and unregisters the service. It deliberately
preserves the managed program, service account, and all data so a configuration
can be recovered or a later release can be installed. Data deletion is a
separate, explicit administrator operation.

## Shutdown and logs

SIGINT, SIGTERM, Windows Stop, Shutdown, and Preshutdown all trigger the same
graceful path. The HTTP listener stops accepting connections, in-flight
requests and cron/background tasks are drained, and the process exits within
30 seconds.

- Windows writes daily files under `<data>\logs` and retains seven files.
- Linux writes stdout/stderr to journald. Use
  `journalctl -u subconverter-rs.service`.
- macOS writes `subconverter-server.out.log` and
  `subconverter-server.err.log` under `<data>/logs`.

## Release integrity

Tag builds publish native x64 and ARM64 archives for Windows, Linux, and macOS.
Each archive includes the server, `base/`, `LICENSE`, README, and service
documentation. Verify it against the published `SHA256SUMS` before
installation. These archives are not currently code-signed, notarized, or
packaged as MSI, deb/rpm, or pkg installers.
