# DAM Parking Lot

This file tracks important design work that is intentionally not treated as complete in the current rebuild.

Parking-lot items are not current product guarantees. Move an item out of this file only after the implementation, docs, and tests all agree on the shipped behavior.

## Security And Privacy Design Work

### Encrypted Vault And Key Management

Current state: `dam-vault` stores tokenized originals in local SQLite as plaintext values.

Parked work:

- Define the local encryption model: AEAD choice, nonce storage, key derivation, and record format.
- Define key custody for local development and install flows: OS keychain, environment-provided key, generated file, or user-managed secret.
- Add a migration path for existing plaintext vault rows.
- Add SQLite hygiene appropriate for sensitive local state, including secure delete and journal/WAL decisions.
- Update README and module docs only after the implementation is real.

### Streaming Response Protection

Current state: outbound requests are protected; inbound provider responses are not redetected. Non-streaming inbound responses can resolve known DAM references when `proxy.resolve_inbound` is enabled. `text/event-stream` responses pass through without inbound reference resolution.

Parked work:

- Add provider-aware SSE parsing for OpenAI Responses and Anthropic streaming formats.
- Decide whether streaming responses should support reference resolution only, full inbound detection/redaction, or both.
- Preserve streaming latency while enforcing bounded buffers per event/chunk.
- Cover `text/event-stream`, NDJSON, and chunked JSON behavior with E2E tests.

### Upstream Egress And SSRF Policy

Current state: configured proxy targets define the upstream; the proxy now disables redirects, strips hop-by-hop headers, blocks encoded request bodies, and applies a request timeout. It does not yet enforce an egress allowlist.

Parked work:

- Define a target allowlist model by scheme, host, and provider profile.
- Decide default behavior for loopback, RFC1918, link-local, and metadata-service addresses.
- Revalidate DNS/redirect behavior against the allowlist before any outbound request.
- Add diagnostics that explain blocked upstreams without leaking sensitive request details.

### Tamper-Evident Audit Log

Current state: `dam-log` records non-sensitive events in SQLite. It is mutable local state and strict audit/fail-closed behavior remains parked.

Parked work:

- Add append-only or tamper-evident semantics, such as hash chaining or signed log records.
- Decide how local operators rotate, export, and verify logs.
- Enforce configured log write failure behavior consistently on hot paths.
- Add tests for log DB unavailable, write failure, tamper detection, and recovery.

### Web And MCP Auth Story

Current state: `dam-web` is a local admin UI with cleartext vault access and consent mutation. It now rejects non-local Host headers and cross-site POST origins. `dam-mcp` runs over stdio and exposes consent tools according to config.

Parked work:

- Add an explicit local admin authentication model for `dam-web`, such as a startup token or local session secret.
- Decide whether `dam-web` should allow cleartext vault views by default or require an explicit unsafe/dev flag.
- Add a capability token or equivalent authorization model for MCP consent writes.
- Define default write-tool posture for installed MCP configs and enterprise deployments.
- Add tests for unauthorized web and MCP attempts, not just malformed requests.
