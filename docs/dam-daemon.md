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

`dam connect` starts a background daemon process by re-running the current `dam` executable through an internal `daemon-run` command. This keeps `cargo run -p dam -- connect` and installed `dam connect` on the same path. If protection was paused with `dam disconnect`, `dam connect` resumes the existing daemon and leaves its installed routing/trust setup unchanged; changing setup requires `dam disconnect --stop` first.

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
- listen address and proxy URL;
- config path when one was supplied;
- local vault/log/consent SQLite paths;
- inbound reference resolution setting;
- target name, provider, and upstream URL;
- network mode (`explicit_proxy`, `system_proxy`, or `tun`);
- transparent AI routes from `dam-net` defaults plus configured `[network.ai_routes]`;
- per-route transparent AI routing readiness from `dam-net`;
- trust mode and non-sensitive `dam-trust` readiness metadata;
- per-route transparent AI trust readiness for built-in and configured AI routes;
- per-route guarded TLS interception readiness from `dam-intercept`;
- whether protection is currently enabled or paused;
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

`--profile` and `--apply` are `dam connect` front-end options. They are resolved before daemon startup and are not accepted by the standalone `dam-daemon run` parser. When multiple app profiles are enabled, `dam connect` expands them to repeated daemon `--target name|provider|upstream` specs so one daemon can expose OpenAI-compatible and Anthropic provider routes at the same local endpoint. `--apply` additionally writes reversible app profile setup when explicitly requested.

`dam connect` preflights transparent setup before daemon startup. `system_proxy` mode requires DAM-managed macOS PAC routing to already be installed. `tun` mode requires macOS Network Extension capture to be active. `local_ca` trust mode requires local CA trust readiness. Missing prerequisites are reported with the next explicit `dam network ...` or `dam trust ...` command instead of starting a partially transparent daemon.

`dam status --json` emits a local status envelope containing daemon state and, when reachable, the `dam-api` `ProxyReport` returned by `/health`.

`network_mode` records the routing mode. `explicit_proxy` serves the normal app-layer endpoint and HTTP(S) proxy for configured clients. `system_proxy` can report macOS PAC routing installed by `dam-net-macos` and uses the transparent CONNECT/TLS runtime only when route capture, local CA trust, and consent are all ready. `tun` can report macOS Network Extension capture installed by `dam-net-macos`; source builds need `DAM_MACOS_NE_HELPER` or a signed app bundle before that state becomes active. Unknown hosts pass through DAM untouched.

`dam disconnect` pauses protection and leaves the daemon running so existing clients keep network connectivity through DAM pass-through. `dam connect` resumes protection. When protection resumes, selected-AI pass-through tunnels opened while paused are closed so clients reconnect through the protected CONNECT/TLS path; unknown/non-AI pass-through can continue. `dam disconnect --stop` terminates the daemon and is intended for explicit restore/stop flows after routing or app profile setup has been restored.

`trust_mode` is a control-plane/status field and a transparent-runtime gate. `disabled` is the default. `local_ca` records the intended TLS trust mode and may report local CA artifact metadata and macOS installation state. It does not itself install a local CA or change OS trust settings; those actions remain explicit `dam trust ... --yes` commands.

`dam-intercept` readiness is recorded for the merged AI route registry. It only reports `ready` when routing, explicit consent, local TLS trust, and the TLS adapter runtime are all ready. The daemon reports the adapter as available because the first HTTP/1.1 CONNECT runtime exists; readiness still fails closed when route capture or trust is incomplete.

`damctl daemon inspect` is the read-only support/debug view over the same state file. It reports `connected`, `stale`, or `disconnected`, state file paths, process status, selected proxy target, local database paths, inbound resolution settings, and trust readiness without starting or stopping the daemon.

## Current Limits

- The daemon runs one local proxy endpoint and can expose multiple configured provider targets from enabled app profiles.
- Configured `[network.ai_routes]` extend transparent AI host recognition; they do not add extra active proxy targets. The selected proxy target still determines which provider adapter/upstream receives protected traffic.
- It does not install system proxy settings, mutate harness configs, or start at login. The first tray/menu-bar shell lives in `dam-tray` and hosts `dam-web /connect`; it does not change daemon lifecycle behavior.
- It records `system_proxy` and `tun` modes and routing readiness. macOS PAC and Network Extension routing are installed/removed by `dam network`; the daemon reports and consumes their state.
- Transparent interception is HTTP/1.1 CONNECT/TLS for built-in and configured AI hosts, configured OpenAI-compatible and Anthropic targets, no HTTP/2, and no chunked request bodies. Intercepted `text/event-stream` responses are transformed chunk by chunk for inbound reference resolution when restoration is enabled.
- Codex ChatGPT-login WebSocket support protects unfragmented client text frames on `chatgpt.com` and forwards non-text frames unchanged. Fragmented/compressed frames remain unsupported and fail closed.
- `dam disconnect --stop` terminates the daemon process by PID, escalates if the process ignores the first termination signal, and removes stale state when the process is no longer running.
