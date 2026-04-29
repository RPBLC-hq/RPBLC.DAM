# dam-api

`dam-api` is the shared public contract crate for DAM reports and health/status payloads.

It does not detect, redact, store, resolve, proxy, log, or read config. It only defines serializable DTOs that other modules can emit or consume.

## Current Scope

- Filter report DTOs for detections, policy decisions, replacements, vault-write failures, blocked detections, and summary counts.
- Resolve report DTOs for references found, resolved references, missing references, read failures, strict-mode status, and summary counts.
- Proxy status DTOs for `protected`, `bypassing`, `blocked`, `provider_down`, `config_required`, and `dam_down`.
- Health DTOs for `damctl`, `dam-daemon`, web UI status, and future installer diagnostics.
- Diagnostic DTOs for non-sensitive warnings and errors.

## Privacy Rule

`dam-api` report structs must not contain raw sensitive values.

Allowed:

- byte spans;
- kind tags;
- token references;
- summary counts;
- non-sensitive diagnostics.

Not allowed:

- detected raw values;
- resolved raw values;
- vault value previews in JSON reports;
- backend vault error text;
- secret material.

Text reports in some local CLIs may still include short value previews for manual debugging. The standardized JSON reports should not.

## CLI Use

`dam-filter` and `dam-resolve` expose report payloads through:

```bash
--json-report
```

The JSON report is written to stderr so stdout remains safe for piping protected/restored payloads.

If both `--report` and `--json-report` are provided, JSON wins.

Vault failure `error` fields use stable codes such as `vault_write_failed` and `vault_read_failed`; they do not include backend error text.

`dam-proxy` emits `ProxyReport` JSON for DAM-owned status responses:

- `GET /health`
- `config_required`
- `blocked`
- `provider_down`

Forwarded upstream responses are not wrapped in `dam-api`; they remain provider responses, with DAM references resolved before returning to the local client when possible.

`damctl` consumes `ProxyReport` from `dam-proxy /health` and emits `HealthReport` for `config check`.

`dam-web /diagnostics` displays the same status vocabulary for local web inspection.

## Tests

```bash
cargo test -p dam-api
```

Coverage should include privacy-sensitive serialization cases, especially that raw values and vault previews do not appear in JSON report payloads.
