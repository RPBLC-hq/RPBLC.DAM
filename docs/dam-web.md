# dam-web

`dam-web` is the local web UI.

It is for development inspection of local SQLite vault, consent, and log databases, and it hosts the visual Connect surface used directly in a browser or through `dam-tray`.

## Routes

```text
/connect   local protection surface for enabled apps, setup, connect, and disconnect
/settings  app/profile configuration surface for enabling/disabling protected harnesses
/          smart landing route: Connect when disconnected, Vault when connected
/vault     protected values with row-level allow/protect actions
/vault/detail/:key  value metadata and audit detail view
/allowed   values allowed through DAM protection
/consents  compatibility alias for /allowed
/logs      operational log events
/doctor    local readiness checks shared with damctl doctor
/diagnostics  damctl-style config and proxy checks
/health    health check
```

Vault-row Allowed state is exact-value based. If duplicate vault rows hold the same value, an active consent grant from one row appears as allowed on every matching row, and protecting it again stops passthrough for that exact value.

The vault and logs tables support column ordering through header buttons. Vault defaults to most recently seen first. They use query parameters:

```text
/vault?sort=value&dir=asc
/logs?sort=time&dir=desc
```

`/connect` uses the enabled integration state managed by `dam-integrations`. It can enable or disable known app profiles, apply safe profile setup for every enabled app, roll back when rollback records are available, start DAM, and disconnect the running daemon. The primary Connect action consumes the shared `dam-diagnostics` setup plan and advances setup in order: profile apply, macOS system-proxy routing, local CA trust, then daemon connect. Profile apply is automatic; routing and trust changes require a short confirmation before the web UI shells out to `dam network ... --yes` or `dam trust ... --yes`. The final daemon start uses `dam connect --apply --network-mode system_proxy --trust-mode local_ca` when any app is enabled. Disconnect restores DAM-managed macOS system-proxy routing and rolls back enabled profile setup before stopping the daemon so disconnected AI traffic is not left pointing at a dead local port.

Without enabled apps, the visible default is Protect Everything and Connect uses the default OpenAI-compatible target. With one or more enabled apps, the same Connect action applies each app profile before connecting and `dam connect --apply` starts one daemon with the required provider targets. The Apps toggle shows enabled apps inline, with the chevron at the far right. App profiles are shown as compact two-line rows with an ellipsis details control for settings and inspection status. `/settings` exposes the same app enable/disable controls in a dedicated configuration view. `dam-tray` hosts this route in a native desktop shell.

When `DAM_WEB_SHELL=tray`, `dam-web` renders a compact tray shell with a navbar power-icon Quit DAM button and routes the `[R:]` brand link through the native tray bridge so `https://rpblc.com` opens in the default browser. The tray-hosted Connect button is routed through native IPC so system trust prompts originate from `dam-tray`, not from the hosted web child. If `DAM_WEB_TRAY_POST_TOKEN` is set, tray-mode pages attach that token to same-origin POST form actions so embedded WebView submits do not depend on `Origin` / `Referer` headers. Browser mode remains the default and keeps the normal local-origin POST guard.

The Connect action shells out to the local `dam` binary from `PATH`. Set `DAM_BIN=/path/to/dam` for source-tree runs or custom installs.

## Usage

```bash
cargo run -p dam-web -- --config dam.example.toml
```

With explicit paths:

```bash
cargo run -p dam-web -- \
  --db vault.db \
  --log log.db \
  --addr 127.0.0.1:2896
```

Default address:

```text
127.0.0.1:2896
```

`--addr` must be loopback in the current local build.

## Config Requirements

`dam-web` currently requires:

- `vault.backend = "sqlite"`
- `consent.backend = "sqlite"` when consent is enabled
- `log.backend = "sqlite"`

Remote vault/consent/log views are not implemented yet.

## Diagnostics

`/doctor` shows the shared `dam-diagnostics` readiness report used by `damctl doctor`, with local SQLite paths redacted for the web surface.

`/diagnostics` shows:

- config health using the same `dam-api` `HealthReport` shape used by `damctl config check`;
- proxy protection state from `dam-proxy /health` using `dam-api` `ProxyReport`;
- local warnings such as disabled proxy, missing proxy API key env vars, unsupported providers, and unreachable proxy.

## Security Posture

This UI displays vault values in clear text and can allow/protect exact values. Treat it as a local development/admin tool, not a public-facing service.

Connect/settings mutation routes are POST-only and use the same local Host and Origin/Referer guardrails as consent mutation routes.

## Branding

The UI follows the RPBLC public site direction:

- Dark background.
- Warm gold accent.
- `[R:]` brand mark.
- Top-clipped navigation with RPBLC.Public-compatible brand hover behavior.
- Primary nav shows Connect, Settings, Vault, and Allowed; diagnostic/activity views live under an icon-only chevron menu.
- `/favicon.svg` served from the same SVG as `RPBLC.public/public/favicon.svg`.
- External link to `https://rpblc.com`.

## Tests

```bash
cargo test -p dam-web
```
