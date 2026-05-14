# dam-pipeline

Status: implemented first extraction.

`dam-pipeline` owns shared text-processing orchestration for proxy/API-style flows. It does not own HTTP serving, upstream target selection, provider auth, provider request forwarding, CLI argument parsing, or persistence backends.

## Responsibilities

Outbound protection:

```text
input text
  -> expand actively allowed DAM references through VaultReader when provided
  -> dam-detect
  -> dam-policy
  -> dam-consent active canonical-value overrides
  -> dam-core replacement plan
  -> VaultWriter for tokenize decisions
  -> dam-redact
  -> protected text or blocked result
```

Inbound reference resolution:

```text
input text with [kind:id] or \[kind:id\] references
  -> dam-core reference parser
  -> VaultReader
  -> dam-core resolve plan
  -> restored text when at least one reference resolves
```

Before detection, callers may provide both a consent store and `VaultReader`. In that mode the pipeline expands previously tokenized `[kind:id]` references only when the reference resolves and the stored canonical value has active consent. Missing, unreadable, expired, or revoked references remain tokenized and continue through the normal protection path. Callers may also pass related domains derived from outbound email detections; those domains are detected as `domain` values even when the current text no longer contains the full email address. Email detection treats sentence punctuation after a normal domain as a boundary, so a prompt like `alice@example.com. What...` stores `alice@example.com` and keeps the derived-domain context usable.

`dam-pipeline` records non-sensitive filter, consent, vault, redaction, read, and resolve events through the `EventSink` contract when a sink is provided.

## Boundaries

The crate does not:

- parse provider-specific JSON or SSE shapes;
- decide proxy target, auth mode, or failure mode;
- open SQLite databases;
- create HTTP responses;
- scan or transform non-UTF-8 bytes;
- incrementally resolve streaming/SSE responses.

Those responsibilities stay with caller, provider, or router crates.

OpenAI-compatible forwarding lives in `dam-provider-openai`, Anthropic forwarding lives in `dam-provider-anthropic`, and proxy route decisions live in `dam-router`.

## Current Consumers

- `dam-proxy` uses `dam-pipeline` for outbound request body protection and default inbound reference resolution. Streaming/SSE bodies are passed to this pipeline by provider adapters after either raw tail-buffering or provider-aware text-delta reassembly, depending on the response shape.
- When a route explicitly enables raw inbound protection, `dam-proxy` reuses the outbound protection pipeline on inbound HTTP response text after reference resolution has no output, so raw provider-returned sensitive values are tokenized before local agent history records them. Resolved DAM references are still restored for the local client when inbound reference resolution is enabled.

`dam-filter` still owns its CLI-specific pipeline wiring because it also owns report emission, exit codes, and file/stdin handling.

## Testing

Run:

```bash
cargo test -p dam-pipeline
```
