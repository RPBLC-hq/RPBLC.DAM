# dam-consent

`dam-consent` stores exact-value passthrough grants.

A consent lets a detected value pass through unredacted until its TTL expires or it is revoked. Consent overrides `tokenize` and `redact` policy decisions. It does not override `block`.

Consent records do not store raw sensitive values. Matching uses:

```text
kind + value_fingerprint
```

When a consent is granted from the vault UI or MCP server, the caller provides the stable vault key, for example:

```text
email:ANJFsZtLfEA9WeP3bZS8Nw
```

The stable vault key is preferred over bracket display references because inbound reference resolution may turn `[email:...]` back into the local value before an agent sees it.

## Config

```toml
[consent]
enabled = true
backend = "sqlite"
path = "consent.db"
default_ttl_seconds = 86400
mcp_write_enabled = true
```

Supported env keys:

```text
DAM_CONSENT_ENABLED
DAM_CONSENT_BACKEND
DAM_CONSENT_PATH
DAM_CONSENT_SQLITE_PATH
DAM_CONSENT_DEFAULT_TTL_SECONDS
DAM_CONSENT_MCP_WRITE_ENABLED
```

## Behavior

- Active consent changes matching detections to `allow`.
- Expired or revoked consent does not affect policy.
- Revoking a consent id revokes all unrevoked grants for the same `kind + value_fingerprint + scope`, so duplicate vault rows for the same exact value cannot keep passthrough alive.
- Consent emits a non-sensitive `consent` log event when it allows a value.
- The SQLite store keeps `id`, `kind`, `value_fingerprint`, optional `vault_key`, TTL timestamps, source, and optional reason.

## Tests

```bash
cargo test -p dam-consent
```
