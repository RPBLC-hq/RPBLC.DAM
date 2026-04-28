# dam-pipeline

Status: implemented first extraction.

`dam-pipeline` owns shared text-processing orchestration for proxy/API-style flows. It does not own HTTP serving, upstream target selection, provider auth, provider request forwarding, CLI argument parsing, or persistence backends.

## Responsibilities

Outbound protection:

```text
input text
  -> dam-detect
  -> dam-policy
  -> dam-consent active exact-value overrides
  -> dam-core replacement plan
  -> VaultWriter for tokenize decisions
  -> dam-redact
  -> protected text or blocked result
```

Inbound reference resolution:

```text
input text with [kind:id] references
  -> dam-core reference parser
  -> VaultReader
  -> dam-core resolve plan
  -> restored text when at least one reference resolves
```

`dam-pipeline` records non-sensitive filter, consent, vault, redaction, read, and resolve events through the `EventSink` contract when a sink is provided.

## Boundaries

The crate does not:

- parse provider-specific JSON or SSE shapes;
- decide proxy target, auth mode, or failure mode;
- open SQLite databases;
- create HTTP responses;
- scan or transform non-UTF-8 bytes;
- resolve streaming/SSE responses.

Those responsibilities stay with caller crates until the provider/router extractions exist.

## Current Consumers

- `dam-proxy` uses `dam-pipeline` for outbound request body protection and opt-in non-streaming inbound reference resolution.

`dam-filter` still owns its CLI-specific pipeline wiring because it also owns report emission, exit codes, and file/stdin handling.

## Testing

Run:

```bash
cargo test -p dam-pipeline
```
