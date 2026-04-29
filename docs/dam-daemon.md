# dam-daemon

`dam-daemon` owns the first background lifecycle slice for local DAM.

It is not a protection engine. The daemon opens the same `dam-proxy` app used by the launcher, writes local process state, waits for shutdown, and removes its state file when it exits cleanly.

## UX Surface

The intended user-facing commands live on `dam`:

```bash
dam connect
dam status
dam disconnect
```

`dam connect` starts a background daemon process by re-running the current `dam` executable through an internal `daemon-run` command. This keeps `cargo run -p dam -- connect` and installed `dam connect` on the same path.

The standalone service entry point also exists:

```bash
cargo run -p dam-daemon -- run
```

## Defaults

`dam connect` defaults to an OpenAI-compatible local endpoint:

```text
listen: 127.0.0.1:7828
target: openai
provider: openai-compatible
upstream: https://api.openai.com
local base URL for OpenAI-compatible harnesses: http://127.0.0.1:7828/v1
```

Use the Anthropic preset when the harness expects Anthropic-compatible traffic:

```bash
dam connect --anthropic
```

That starts the same daemon/proxy lifecycle with:

```text
target: anthropic
provider: anthropic
upstream: https://api.anthropic.com
local base URL for Anthropic-compatible harnesses: http://127.0.0.1:7828
```

Both presets use caller-owned provider auth headers by default. DAM does not store provider API keys for local daemon mode.

## State File

The daemon writes a JSON state file at:

```text
$DAM_STATE_DIR/daemon.json
```

When `DAM_STATE_DIR` is unset, the fallback is:

```text
$HOME/.dam/daemon.json
```

The state file contains non-sensitive local lifecycle information:

- daemon PID;
- listen address and proxy URL;
- config path when one was supplied;
- local vault/log/consent SQLite paths;
- inbound reference resolution setting;
- target name, provider, and upstream URL;
- daemon start time as a Unix timestamp.

It must not contain raw sensitive values, vault values, provider API keys, or auth headers.

## Commands

```bash
dam connect [--openai|--anthropic] [DAM_OPTIONS]
dam connect --profile <profile> [--apply]
dam connect --apply
dam status [--json]
dam disconnect
```

Daemon options:

```text
--profile <id>       Apply integration profile daemon defaults
--apply              Apply the selected or active integration profile before connecting
--openai             Use the OpenAI-compatible preset (default)
--anthropic          Use the Anthropic preset
--config <path>      Load DAM config before daemon overrides
--listen <addr>      Local proxy listen address
--target-name <name> Proxy target name
--provider <name>    Provider adapter: openai-compatible or anthropic
--upstream <url>     Provider upstream URL
--db <path>          Local SQLite vault path
--log <path>         Local SQLite log path
--consent-db <path>  Local SQLite consent path
--no-log             Disable log writes
--no-resolve-inbound Leave DAM references unresolved in inbound responses
--resolve-inbound    Restore DAM references in inbound responses
```

`dam status --json` emits a local status envelope containing daemon state and, when reachable, the `dam-api` `ProxyReport` returned by `/health`.

`damctl daemon inspect` is the read-only support/debug view over the same state file. It reports `connected`, `stale`, or `disconnected`, state file paths, process status, selected proxy target, local database paths, and inbound resolution settings without starting or stopping the daemon.

## Current Limits

- The daemon runs one proxy target at a time.
- It does not install system proxy settings, mutate harness configs, start at login, or expose a tray/menu-bar UI yet.
- It does not add VPN/TUN routing, TLS interception, or WebSocket handling.
- `dam disconnect` terminates the daemon process by PID and removes stale state when the process is no longer running.
