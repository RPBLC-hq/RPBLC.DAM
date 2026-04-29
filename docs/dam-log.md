# dam-log

`dam-log` is the local SQLite operational log implementation.

It implements `dam-core::EventSink`.

## Responsibility

Persist non-sensitive operational events.

Current event types:

- `detection`
- `policy_decision`
- `vault_write`
- `vault_write_failed`
- `vault_read`
- `vault_read_failed`
- `redaction`
- `resolve`
- `proxy_forward`
- `proxy_bypass`
- `proxy_failure`

## SQLite Schema

```sql
CREATE TABLE IF NOT EXISTS log_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp INTEGER NOT NULL,
    operation_id TEXT NOT NULL,
    level TEXT NOT NULL,
    event_type TEXT NOT NULL,
    kind TEXT,
    reference TEXT,
    action TEXT,
    message TEXT NOT NULL
);
```

Existing local databases with older `log_events` schemas are migrated in place. Additive legacy schemas receive missing non-sensitive columns. Legacy schemas that contain `value_preview` are backed up to `log.db.pre-migration-<timestamp>.bak`, rebuilt without raw preview columns, and marked with SQLite `PRAGMA user_version = 2`.

Legacy `data_type`, `module_name`, `destination`, and `action` context is preserved where available. `value_preview` is never copied into the current schema, `LogEntry`, or current log views.

## Privacy Rules

Allowed:

- Sensitive kind.
- Operation ID.
- Generated reference after a successful vault write.
- Policy action.
- Non-sensitive message.

Forbidden:

- Raw detected value.
- Value preview.
- Backend error text that echoes sensitive values.

## Failure Behavior

Current `dam-filter` and `dam-proxy` behavior: log write failure warns/continues or disables logging when configured for non-strict behavior.

Strict audit/fail-closed remains parked.

## Tests

```bash
cargo test -p dam-log
```
