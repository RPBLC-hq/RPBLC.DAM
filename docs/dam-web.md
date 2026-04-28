# dam-web

`dam-web` is the local web UI.

It is for development inspection of local SQLite vault, consent, and log databases.

## Routes

```text
/          vault entries and row-level consent grant/revoke actions
/consents  consent entries and revoke actions
/logs      operational log events
/diagnostics  damctl-style config and proxy checks
/health    health check
```

Vault-row consent state is exact-value based. If duplicate vault rows hold the same value, an active consent granted from one row appears as active on every matching row, and revoking it stops passthrough for that exact value.

The vault and logs tables support column ordering through header buttons. They use query parameters:

```text
/?sort=key&dir=asc
/logs?sort=time&dir=desc
```

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

## Config Requirements

`dam-web` currently requires:

- `vault.backend = "sqlite"`
- `consent.backend = "sqlite"` when consent is enabled
- `log.backend = "sqlite"`

Remote vault/consent/log views are not implemented yet.

## Diagnostics

`/diagnostics` shows:

- config health using the same `dam-api` `HealthReport` shape used by `damctl config check`;
- proxy protection state from `dam-proxy /health` using `dam-api` `ProxyReport`;
- local warnings such as disabled proxy, missing proxy API key env vars, unsupported providers, and unreachable proxy.

## Security Posture

This UI displays vault values in clear text and can grant/revoke passthrough consent. Treat it as a local development/admin tool, not a public-facing service.

## Branding

The UI follows the RPBLC public site direction:

- Dark background.
- Warm gold accent.
- `[R:]` brand mark.
- Embedded SVG favicon derived from `RPBLC.public/public/favicon.svg`.
- External link to `https://rpblc.com`.

## Tests

```bash
cargo test -p dam-web
```
