# dam-vault

`dam-vault` is the local SQLite vault implementation.

It implements `dam-core::VaultWriter` and `dam-core::VaultReader`.

## Responsibility

Persist mappings:

```text
reference key -> original value
```

Example key:

```text
email:7B2HkqFn9xR4mWpD3nYvKt
```

## SQLite Schema

```sql
CREATE TABLE IF NOT EXISTS vault_entries (
    key TEXT PRIMARY KEY NOT NULL,
    value TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
```

## Public Operations

- `put(key, value)`
- `get(key)`
- `delete(key)`
- `list()`
- `count()`

## Architecture Rules

- The vault does not generate reference IDs.
- The vault does not redact text.
- The vault does not decide policy.
- The vault can be replaced by a remote implementation if it implements `VaultWriter` and `VaultReader`.

## Tests

```bash
cargo test -p dam-vault
```
