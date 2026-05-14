# DAM Module Docs

This folder documents the current DAM rebuild modules.

The architecture rule is: modules stay replaceable, and cross-module coordination goes through spine-owned contracts in `dam-core`.

Deferred security and product-design work is tracked in [parking-lot.md](parking-lot.md). Parking-lot items are not current product guarantees.

DAM is designed for macOS, Linux, and Windows. Platform-specific routing, trust, tray, and packaging implementations may land in staged slices, but partial or delayed platform behavior must be tracked in [parking-lot.md](parking-lot.md) or the relevant module parking-lot doc.

## Modules

- [dam-core](dam-core.md): shared contracts, reference generation, replacement planning, policy actions, log event shape.
- [dam](dam.md): local UX entry point for `connect/status/logs/disconnect`, integration profiles, and the npm wrapper.
- [dam-api](dam-api.md): shared JSON/report/status DTOs for CLIs, proxy status, health, and future automation.
- [dam-config](dam-config.md): layered runtime config for defaults, TOML, env, and CLI overrides.
- [dam-consent](dam-consent.md): canonical-value passthrough grants with TTL and revocation.
- [dam-daemon](dam-daemon.md): background local proxy lifecycle, pause/resume protection state, state file, and `dam connect/status/disconnect` support.
- [dam-diagnostics](dam-diagnostics.md): shared local readiness checks for `damctl doctor` and `dam-web /doctor`.
- [dam-intercept](dam-intercept.md): guarded TLS interception activation contract for transparent AI routes.
- [dam-integrations](dam-integrations.md): JSON local harness profiles, enabled app state, and legacy active profile state for `dam integrations`, `dam profile`, and `dam connect --profile`.
- [damctl](damctl.md): local status and config diagnostics CLI.
- [dam-detect](dam-detect.md): pure rule-based sensitive value detection.
- [dam-e2e](dam-e2e.md): process-level end-to-end tests across the local binaries.
- [dam-policy](dam-policy.md): maps detections to `tokenize`, `redact`, `allow`, or `block`.
- [dam-pipeline](dam-pipeline.md): shared text processing orchestration for detect, policy, consent, vault/log events, redaction, and inbound reference resolution.
- [dam-provider-common](dam-provider-common.md): shared provider adapter utilities for JSON/JSON-lines string-value, raw stream, and provider-aware SSE text-delta transforms.
- [dam-provider-anthropic](dam-provider-anthropic.md): Anthropic upstream forwarding, `x-api-key` auth/header handling, JSON/JSON-lines response transforms, and SSE text-delta response transforms for proxy flows.
- [dam-provider-openai](dam-provider-openai.md): OpenAI-compatible upstream forwarding, auth/header handling, JSON/JSON-lines response transforms, and SSE text-delta response transforms for proxy flows.
- [dam-router](dam-router.md): proxy target selection, provider classification, auth mode, and failure-mode decisions.
- [dam-vault](dam-vault.md): local SQLite `VaultWriter` and `VaultReader` implementation.
- [dam-log](dam-log.md): local SQLite `EventSink` implementation.
- [dam-net](dam-net.md): network capture-mode vocabulary, generic traffic profile contracts, routing readiness, capture backend status, protocol adapter status, and profile-derived host classification.
- [dam-net-macos](dam-net-macos.md): macOS PAC system-proxy install/remove plus Network Extension capture planning/status for `tun`.
- [dam-trust](dam-trust.md): TLS trust-mode vocabulary, local CA artifacts, leaf issuance, macOS trust install/remove, readiness contracts, and trusted AI host scope for transparent protection.
- [dam-redact](dam-redact.md): pure replacement application.
- [dam-filter](dam-filter.md): CLI pipeline wiring detection, policy, vault, logs, and redaction.
- [dam-resolve](dam-resolve.md): CLI pipeline for resolving `[kind:id]` references through `VaultReader`.
- [dam-proxy](dam-proxy.md): generic mediation runtime with MVP LLM HTTP/WebSocket adapters plus daemon-gated HTTP/1.1 CONNECT/TLS for ready profile routes.
- [dam-web](dam-web.md): local web UI for setup-plan-driven Connect/app controls, Settings, protected values, Allowed values, log events, and diagnostics.
- [dam-tray](dam-tray.md): native desktop shell that hosts the Connect surface from the local web UI.
- [dam-mcp](dam-mcp.md): MCP tools for agent-managed consent operations.

## Current Pipeline

```text
input text
  -> dam-pipeline expands actively allowed DAM references when VaultReader is available
  -> dam-detect
  -> dam-policy
  -> dam-consent active canonical-value overrides
  -> dam-core replacement plan
  -> dam-vault only for tokenize decisions
  -> dam-redact
  -> stdout

optional dam-api JSON report
  -> stderr

dam-core also builds non-sensitive log events
  -> dam-log when enabled
```

Replacement planning deduplicates repeated equal canonical values by default, and compatible vault writers reuse an existing canonical reference for the same stored value. Current email canonicalization removes detector-supported whitespace inside the address and lowercases the domain before storage/deduplication; domain canonicalization removes detector-supported whitespace around dots and lowercases the domain. Set `policy.deduplicate_replacements = false` to issue a distinct reference per occurrence when repeated-reference equality is too revealing.

## Resolve Pipeline

```text
input text with [kind:id] references
  -> dam-core reference parser
  -> dam-vault through VaultReader
  -> dam-core resolve plan
  -> stdout

optional dam-api JSON report
  -> stderr

dam-core also builds non-sensitive resolve log events
  -> dam-log when enabled
```

## Proxy Pipeline

```text
LLM request
  -> dam-proxy
  -> dam-router
  -> dam-pipeline
  -> dam-vault through VaultReader for actively allowed references
  -> dam-detect
  -> dam-policy
  -> dam-consent active canonical-value overrides
  -> dam-core replacement plan
  -> dam-vault only for tokenize decisions
  -> dam-redact
  -> dam-log
  -> dam-provider-openai or dam-provider-anthropic
  -> upstream provider

provider response
  -> dam-provider-openai or dam-provider-anthropic
  -> dam-pipeline
  -> dam-core reference parser
  -> dam-vault through VaultReader
  -> dam-core resolve plan
  -> dam-log
  -> LLM client
```

Proxy defaults are directional: outbound requests are redacted before the provider sees them. Active consent applies to canonical detected values and, in proxy flows with a vault reader, previously tokenized outbound DAM references for that same allowed value. Agent traffic apps leave known DAM references unresolved in inbound local transcripts, while raw inbound HTTP response redetection/tokenization is explicit per route through traffic profile `inbound.protect_sensitive_data`. JSON-shaped responses are transformed string-by-string, including newline-delimited JSON, when reference restoration or explicit raw inbound protection is active. `text/event-stream` responses are transformed under the same route policy; provider-aware SSE text-delta parsing handles references and opted-in raw values split across adjacent OpenAI-compatible or Anthropic JSON delta events with a bounded event window, while raw streams still use tail-buffered transformation. The Codex ChatGPT-login WebSocket MVP freezes protection state at connection start, strips WebSocket extension negotiation, and protects unfragmented client and server text frames on protected connections; fragmented, binary, or compressed WebSocket frames close the protected connection instead of passing through raw.

`dam-pipeline`, `dam-provider-common`, `dam-provider-openai`, `dam-provider-anthropic`, and `dam-router` have been extracted from the first compact proxy implementation.

## Control And Diagnostics

```text
dam connect
  -> background daemon process
  -> dam-proxy
  -> HTTP(S) proxy / transparent route for active traffic profile apps
  -> pass-through provider auth

dam status / dam disconnect
  -> daemon state file
  -> dam-proxy /health when connected

dam logs
  -> local dam-log SQLite store
  -> concise non-sensitive operation summaries or event timelines

dam profile
  -> enabled JSON app profile state and legacy active harness profile state

dam integrations list/show/apply/rollback
  -> dam-integrations JSON profile catalog
  -> local proxy URL and harness setup snippets

damctl status
  -> dam-proxy /health
  -> dam-api ProxyReport

damctl doctor
  -> dam-diagnostics
  -> dam-integrations apply-state summary
  -> dam-api HealthReport

damctl bypass status
  -> dam-config
  -> proxy/vault/log failure-mode report

damctl daemon inspect
  -> dam-daemon state file
  -> dam-net routing readiness
  -> dam-intercept guarded interception readiness

damctl network inspect
  -> dam-net-macos routing state
  -> dam-net route readiness

dam network install-system-proxy / remove-system-proxy
  -> dam-net-macos macOS all-proxyable HTTP/HTTPS PAC routing with rollback

dam network install-network-extension / remove-network-extension / status
  -> dam-net-macos macOS Network Extension capture state for tun mode

dam startup status / skip-open-at-login
  -> local startup setup choice for tray and scripted installs

damctl trust inspect
  -> dam-trust readiness and action plans

dam trust generate-local-ca / delete-local-ca / install-local-ca / remove-local-ca
  -> dam-trust local CA artifacts and explicit macOS system trust changes

damctl integrations check
  -> dam-integrations apply-state inspection

damctl config check
  -> dam-diagnostics
  -> dam-api HealthReport

dam-web /connect
  -> dam-integrations enabled profiles and apply-state inspection
  -> in-memory protected-state/request trigger for local Connect QA until dam-notify owns delivery
  -> dam connect/disconnect pause-resume control

dam-tray
  -> native desktop shell
  -> hosted dam-web /connect

dam-web /health
  -> dam-config
  -> dam-diagnostics
  -> dam-proxy /health when enabled
  -> dam-api HealthReport + ProxyReport
```

## Config Precedence

From lowest to highest priority:

1. Built-in defaults.
2. `dam.toml`, `--config <path>`, or `DAM_CONFIG`.
3. Environment variables.
4. CLI overrides.

Use [../dam.example.toml](../dam.example.toml) as the local starting point.

## Verification

```bash
scripts/dam-build.sh check
```

The build/release entrypoint in [build-release.md](build-release.md) wraps local verification, source builds, signed macOS app packaging, notarization, and local deploy steps so local and CI workflows use the same command surface.

Run only the E2E suite with:

```bash
cargo test -p dam-e2e
```
