# DAM Parking Lot

This file tracks important design work that is intentionally not treated as complete in the current rebuild.

Parking-lot items are not current product guarantees. Move an item out of this file only after the implementation, docs, and tests all agree on the shipped behavior.

Platform rule: DAM must be designed for macOS, Linux, and Windows. Platform-specific implementations may be staged when they require platform-local development or testing, but partial, delayed, or unavailable platform behavior must remain visible in this file or a module parking-lot doc until implementation, docs, and tests agree on the shipped behavior.

## Security And Privacy Design Work

### Full-Device Routing And TLS Trust

Current state: local protection is app-layer routing for supported AI harnesses, explicit proxy paths, the macOS `system_proxy` fallback, and macOS Network Extension control-plane support for `tun`. `dam-net` defines capture-mode/backend vocabulary, protocol adapter readiness, routing readiness, and host-only AI traffic classification for the merged default/config AI route registry. `dam-tray` owns macOS System Extension activation from `DAM.app`, and `dam-net-macos` can install/remove macOS PAC routing for proxy-capable HTTP/HTTPS traffic with rollback and configure Network Extension capture through a signed helper/app bundle. `dam-proxy` passes unknown hosts through untouched and has a daemon-gated HTTP/1.1 CONNECT/TLS runtime plus Codex ChatGPT-login WebSocket text-frame protection for selected AI hosts when routing, trust, and consent are ready. `dam-daemon` tracks pause/resume protection state so `dam disconnect` can stop redaction without removing routing.

Parked work:

- Implement Windows/Linux system proxy routing and VPN/TUN or network-extension routing behind the shared capture backend contracts.
- Add true full-device capture for UDP and non-HTTP protocols.
- Replace the current CLI explicit-proxy fallback with process/network-level capture everywhere signed platform capture is available.
- Install and remove the local DAM CA on Windows/Linux, add CA rotation, and harden interrupted macOS trust mutation recovery.
- Extend transparent TLS interception beyond the current HTTP/1.1/WebSocket slice: HTTP/2, fragmented/compressed WebSocket payloads, multiple requests per tunnel, target-specific consent, certificate caching, and stronger platform coverage.
- Define degraded, bypass, and blocked states for transparent protection across system proxy and `tun` modes.
- Define a replacement one-shot interception launcher, if needed, that starts or reuses the daemon and routes traffic by proxy/system routing without provider base-url mutation.
- Add platform tests proving sensitive values do not leave before transparent protection is ready.

### Encrypted Vault And Key Management

Current state: `dam-vault` stores tokenized originals in local SQLite as plaintext values.

Parked work:

- Define the local encryption model: AEAD choice, nonce storage, key derivation, and record format.
- Define key custody for local development and install flows: OS keychain, environment-provided key, generated file, or user-managed secret.
- Add a migration path for existing plaintext vault rows.
- Add SQLite hygiene appropriate for sensitive local state, including secure delete and journal/WAL decisions.
- Update README and module docs only after the implementation is real.

### Streaming Response Protection

Current state: outbound requests are protected; inbound provider responses are not redetected. Inbound responses resolve known DAM references by default when `proxy.resolve_inbound` is enabled. `text/event-stream` responses are transformed chunk by chunk, preserving streaming transport but not yet handling references split across chunks or provider event boundaries.

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
