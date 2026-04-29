# dam-diagnostics

Status: implemented first extraction.

`dam-diagnostics` owns shared local readiness checks for user-facing status surfaces. It exists so `damctl doctor` and `dam-web /doctor` do not invent separate interpretations of whether DAM is ready to protect local AI traffic.

## Responsibilities

`config_report` emits a side-effect-free `dam-api::HealthReport` for config shape and current implementation compatibility.

`doctor_report` emits a fuller `dam-api::HealthReport` for local readiness. It includes:

- config loading state;
- vault, consent, and log backend compatibility;
- SQLite runtime open checks for local vault, consent, and log stores;
- router target/provider/auth/failure-mode decisions;
- proxy runtime `/health` reachability when proxy is enabled;
- launcher readiness notes for `dam claude`, `dam codex --api`, and fail-closed Codex ChatGPT-login mode.

## Boundaries

The crate does not:

- start or stop `dam-proxy`;
- mutate policy, vault entries, log entries, or consent grants;
- call real model providers;
- inspect request bodies;
- own CLI or HTML rendering.

Those concerns stay in `damctl`, `dam-web`, `dam-proxy`, and future daemon/integration modules.

## Current Consumers

- `damctl config check`
- `damctl doctor`
- `dam-web /doctor`

## Testing

Run:

```bash
cargo test -p dam-diagnostics
```
