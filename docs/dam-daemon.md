# dam-daemon

`dam-daemon` owns the first background lifecycle slice for local DAM.

It is not a protection engine. The daemon opens `dam-proxy`, writes local process state, tracks pause/resume protection state, waits for shutdown, and removes its state file when it exits cleanly. In `explicit_proxy` mode it serves the normal app-layer endpoint and HTTP(S) proxy. In transparent modes it supplies the routing/trust/consent state that allows `dam-proxy` to activate its guarded CONNECT/TLS runtime.

## UX Surface

The intended user-facing commands live on `dam`:

```bash
dam connect
dam status
dam disconnect
```

`dam connect` starts a background daemon process by re-running the current `dam` executable through an internal `daemon-run` command. This keeps `cargo run -p dam -- connect` and installed `dam connect` on the same path. If protection was paused with `dam disconnect`, `dam connect` resumes the existing daemon and leaves its installed routing/trust setup unchanged. A default `dam connect` or Resume click is not treated as a request to migrate away from the current daemon's routing/trust mode; only explicit mismatched `--network-mode` or `--trust-mode` flags require `dam disconnect --stop` first. If the recorded daemon executable path or SHA-256 fingerprint is missing or differs from the current `dam` executable, `dam connect` preserves the existing routing/trust/target setup, stops the old daemon, and starts a fresh daemon from the current executable. This keeps source builds and app updates from leaving traffic on stale in-memory proxy code. Profile selection is the other restart path: if the currently running daemon target set or transparent route scope does not match the selected traffic profile targets, `dam connect` preflights setup, restarts the daemon, and resumes protection with the expanded target set. Runtime traffic app selection crosses the `dam connect` to `daemon-run` boundary through `--traffic-app <id>` flags; an explicit empty app scope is serialized as the internal `--no-traffic-apps` flag so "no apps enabled" does not collapse back to bundled defaults.

The standalone service entry point also exists:

```bash
cargo run -p dam-daemon -- run
```

## Defaults

`dam connect` defaults to an OpenAI-compatible proxy target:

```text
listen: 127.0.0.1:7828
target: openai
provider: openai-compatible
upstream: https://api.openai.com
local proxy URL for proxy-aware harnesses: http://127.0.0.1:7828
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
local proxy URL for proxy-aware harnesses: http://127.0.0.1:7828
```

Both presets use caller-owned provider auth headers by default. DAM does not store provider API keys for local daemon mode.

## State File

The daemon writes a JSON state file atomically at:

```text
$DAM_STATE_DIR/daemon.json
```

When `DAM_STATE_DIR` is unset, the fallback is:

```text
$HOME/.dam/daemon.json
```

The state file contains non-sensitive local lifecycle information:

- daemon PID;
- current daemon executable path and SHA-256 fingerprint;
- listen address and proxy URL;
- config path when one was supplied;
- local vault/log/consent SQLite paths;
- inbound reference resolution setting;
- first target name, provider, and upstream URL;
- sanitized proxy target set: target name, provider, and upstream URL for each configured proxy target;
- network mode (`explicit_proxy`, `system_proxy`, or `tun`);
- active traffic-profile-derived routes from `dam-net`;
- per-route transparent AI routing readiness from `dam-net`;
- trust mode and non-sensitive `dam-trust` readiness metadata;
- per-route transparent AI trust readiness for active traffic profile routes;
- per-route guarded TLS interception readiness from `dam-intercept`;
- whether protection is currently enabled or paused;
- when protection last became enabled, when known;
- daemon start time as a Unix timestamp.

It must not contain raw sensitive values, vault values, provider API keys, or auth headers.

## Commands

```bash
dam connect [--openai|--anthropic] [DAM_OPTIONS]
dam connect --profile <profile> [--apply]
dam connect --apply
dam status [--json]
dam disconnect [--stop]
```

Daemon options:

```text
--openai             Use the OpenAI-compatible preset (default)
--anthropic          Use the Anthropic preset
--config <path>      Load DAM config before daemon overrides
--listen <addr>      Local proxy listen address
--network-mode <mode> Control-plane network mode: explicit_proxy, system_proxy, or tun
--trust-mode <mode>  Control-plane trust mode: disabled or local_ca
--target-name <name> Proxy target name
--provider <name>    Provider adapter: openai-compatible or anthropic
--upstream <url>     Provider upstream URL
--target <spec>      Internal repeated target spec: name|provider|upstream
--db <path>          Local SQLite vault path
--log <path>         Local SQLite log path
--consent-db <path>  Local SQLite consent path
--no-log             Disable log writes
--no-resolve-inbound Leave DAM references unresolved in inbound responses
--resolve-inbound    Restore DAM references in inbound responses
```

`--profile` and `--apply` are `dam connect` front-end options. They are resolved before daemon startup and are not accepted by the standalone `dam-daemon run` parser. The selected or enabled profile controls the first daemon target for direct app-layer requests and supplies runtime `traffic.enabled_apps` filtering. The daemon expands the runtime target set with every active traffic profile route, so one daemon can match OpenAI-compatible, Anthropic, Codex ChatGPT-login, xAI, and custom profile-defined transparent routes at the same local endpoint. `--apply` additionally writes reversible app profile setup when explicitly requested.

`dam connect` preflights transparent setup before daemon startup. `system_proxy` mode requires DAM-managed macOS PAC routing to already be installed. `tun` mode requires macOS Network Extension capture to be active. `local_ca` trust mode requires local CA trust readiness. Missing prerequisites are reported with the next explicit `dam network ...` or `dam trust ...` command instead of starting a partially transparent daemon.

`dam status --json` emits a local status envelope containing daemon state and, when reachable, the `dam-api` `ProxyReport` returned by `/health`.

`network_mode` records the routing mode. `explicit_proxy` serves the normal app-layer endpoint and HTTP(S) proxy for configured clients. `system_proxy` can report macOS PAC routing installed by `dam-net-macos` and uses the transparent CONNECT/TLS runtime only when route capture, local CA trust, and consent are all ready. `tun` can report macOS Network Extension capture installed by `dam-net-macos`; source builds need `DAM_MACOS_NE_HELPER` or a signed app bundle before that state becomes active. Unknown hosts pass through DAM untouched.

`dam disconnect` pauses protection and leaves the daemon running so existing clients keep network connectivity through DAM pass-through. `dam connect` resumes protection and removes stale daemon state before starting a fresh daemon when the recorded PID is no longer running. It also restarts a live daemon when the state file was written by a missing or different executable fingerprint, while keeping the recorded routing/trust/target setup. Pause/resume state is recorded in `$DAM_STATE_DIR/protection.state` with the current enabled flag and the Unix time when that flag last changed, so Connect can show how long protection has actually been on. When protection resumes, selected-AI pass-through tunnels opened while paused are closed so clients reconnect through the protected CONNECT/TLS path; unknown/non-AI pass-through can continue. `dam disconnect --stop` terminates the daemon and is intended for explicit restore/stop flows after routing or app profile setup has been restored.

`trust_mode` is a control-plane/status field and a transparent-runtime gate. `disabled` is the default. `local_ca` records the intended TLS trust mode and may report local CA artifact metadata and macOS installation state. It does not itself install a local CA or change OS trust settings; those actions remain explicit `dam trust ... --yes` commands.

`dam-intercept` readiness is recorded for the merged AI route registry. It only reports `ready` when routing, explicit consent, local TLS trust, and the TLS adapter runtime are all ready. The daemon reports the adapter as available because the first HTTP/1.1 CONNECT runtime exists; readiness still fails closed when route capture or trust is incomplete.

`damctl daemon inspect` is the read-only support/debug view over the same state file. It reports `connected`, `stale`, or `disconnected`, state file paths, process status, selected proxy target, local database paths, inbound resolution settings, and trust readiness without starting or stopping the daemon.

## Current Limits

- The daemon runs one local proxy endpoint and can expose multiple configured provider targets from enabled app profiles plus active traffic profile apps.
- New mediated services, including private OpenAI-compatible and Anthropic-compatible endpoints, are traffic profile JSON app entries. Active profile routes add non-secret proxy targets for route matching. The first selected proxy target still determines the default app-layer provider/upstream for direct requests.
- It does not install system proxy settings, mutate harness configs, or start at login. The first tray/menu-bar shell lives in `dam-tray` and hosts `dam-web /connect`; it does not change daemon lifecycle behavior.
- It records `system_proxy` and `tun` modes and routing readiness. macOS PAC and Network Extension routing are installed/removed by `dam network`; the daemon reports and consumes their state.
- Transparent interception is HTTP/1.1 CONNECT/TLS for active traffic profile hosts, configured OpenAI-compatible and Anthropic targets, no HTTP/2, and no chunked request bodies. Intercepted JSON and `text/event-stream` responses are transformed for inbound reference resolution when restoration is enabled, including provider-aware text-delta event streams for OpenAI-compatible and Anthropic targets.
- Codex ChatGPT-login WebSocket support protects unfragmented client text frames on `chatgpt.com`, logs warning events for fragmented/binary client frames that pass through without mutation, and currently passes server-to-client frames through without local reference resolution. Inbound, fragmented, or compressed frame protection remains unsupported.
- `dam disconnect --stop` terminates the daemon process by PID, escalates if the process ignores the first termination signal, and removes stale state when the process is no longer running.
