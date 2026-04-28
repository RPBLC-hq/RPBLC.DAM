# dam-resolve

`dam-resolve` is the current CLI reverse-token pipeline.

It restores tokenized references created by `dam-filter` or `dam-proxy` when the referenced value exists in the configured vault.

## Pipeline

```text
input
  -> dam-core reference parser
  -> dam-vault through VaultReader
  -> dam-core resolve plan
  -> stdout

dam-core resolve log events
  -> dam-log when enabled
```

## Usage

```bash
echo "email [email:7B2HkqFn9xR4mWpD3nYvKt]" \
  | cargo run -p dam-resolve -- --db vault.db --report
```

CLI overrides:

```text
--config <path>
--db <path>
--log <path>
--no-log
--report
--json-report
--strict
[FILE]
```

## Behavior

- Valid `[kind:id]` references are looked up through `VaultReader`.
- Found values replace the reference in output.
- Missing references stay unchanged by default.
- `--strict` exits non-zero and writes no stdout if any reference is missing or unreadable.
- Redact-only placeholders such as `[email]` cannot be resolved and are ignored.
- Malformed references and unknown kinds are ignored.

## Report Output

`--report` writes non-sensitive diagnostic metadata to stderr:

```text
operation_id: ...
references: 2
resolved: 1
missing: 1
read_failures: 1
resolved email 6..35 email:7B2HkqFn9xR4mWpD3nYvKt
missing ssn 44..71 ssn:...
read_error phone 80..109 phone:... vault_read_failed
```

Reports and persisted logs do not include resolved raw values. Read failures use the stable `vault_read_failed` code and intentionally omit backend error text because backend errors may echo sensitive values.

`--json-report` writes the standardized `dam-api` resolve report JSON to stderr. Stdout remains the restored payload, or empty on strict failure. If both `--report` and `--json-report` are provided, JSON wins.

## Tests

```bash
cargo test -p dam-resolve
```
