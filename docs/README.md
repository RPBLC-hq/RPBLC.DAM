# DAM Module Docs

This folder documents the current DAM rebuild modules.

The architecture rule is: modules stay replaceable, and cross-module coordination goes through spine-owned contracts in `dam-core`.

Deferred security and product-design work is tracked in [parking-lot.md](parking-lot.md). Parking-lot items are not current product guarantees.

## Modules

- [dam-core](dam-core.md): shared contracts, reference generation, replacement planning, policy actions, log event shape.
- [dam](dam.md): local launcher and npm wrapper entry point for running Claude Code and explicit Codex API-key mode through an embedded DAM proxy. Codex ChatGPT-login mode is blocked until its current model transport can be protected.
- [dam-api](dam-api.md): shared JSON/report/status DTOs for CLIs, proxy status, health, and future automation.
- [dam-config](dam-config.md): layered runtime config for defaults, TOML, env, and CLI overrides.
- [dam-consent](dam-consent.md): exact-value passthrough grants with TTL and revocation.
- [damctl](damctl.md): local status and config diagnostics CLI.
- [dam-detect](dam-detect.md): pure rule-based sensitive value detection.
- [dam-e2e](dam-e2e.md): process-level end-to-end tests across the local binaries.
- [dam-policy](dam-policy.md): maps detections to `tokenize`, `redact`, `allow`, or `block`.
- [dam-pipeline](dam-pipeline.md): shared text processing orchestration for detect, policy, consent, vault/log events, redaction, and inbound reference resolution.
- [dam-provider-anthropic](dam-provider-anthropic.md): Anthropic upstream forwarding, `x-api-key` auth/header handling, and SSE passthrough for proxy flows.
- [dam-provider-openai](dam-provider-openai.md): OpenAI-compatible upstream forwarding, auth/header handling, and SSE passthrough for proxy flows.
- [dam-router](dam-router.md): proxy target selection, provider classification, auth mode, and failure-mode decisions.
- [dam-vault](dam-vault.md): local SQLite `VaultWriter` and `VaultReader` implementation.
- [dam-log](dam-log.md): local SQLite `EventSink` implementation.
- [dam-redact](dam-redact.md): pure replacement application.
- [dam-filter](dam-filter.md): CLI pipeline wiring detection, policy, vault, logs, and redaction.
- [dam-resolve](dam-resolve.md): CLI pipeline for resolving `[kind:id]` references through `VaultReader`.
- [dam-proxy](dam-proxy.md): first app-layer LLM proxy slice with OpenAI-compatible and Anthropic reverse proxy behavior.
- [dam-web](dam-web.md): local web UI for vault entries, consent grants, log events, and diagnostics.
- [dam-mcp](dam-mcp.md): MCP tools for agent-managed consent operations.

## Current Pipeline

```text
input text
  -> dam-detect
  -> dam-policy
  -> dam-consent active exact-value overrides
  -> dam-core replacement plan
  -> dam-vault only for tokenize decisions
  -> dam-redact
  -> stdout

optional dam-api JSON report
  -> stderr

dam-core also builds non-sensitive log events
  -> dam-log when enabled
```

Replacement planning deduplicates repeated equal values by default within one run/request. Set `policy.deduplicate_replacements = false` to issue a distinct reference per occurrence when repeated-reference equality is too revealing.

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
  -> dam-detect
  -> dam-policy
  -> dam-consent active exact-value overrides
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

Proxy defaults are directional: outbound requests are redacted before the provider sees them; inbound responses are not redacted. Inbound DAM reference resolution is disabled by default for non-streaming responses and can be enabled with `proxy.resolve_inbound = true` when the caller deliberately wants local restoration. `text/event-stream` responses pass through as streams without inbound reference resolution.

`dam-pipeline`, `dam-provider-openai`, `dam-provider-anthropic`, and `dam-router` have been extracted from the first compact proxy implementation.

## Control And Diagnostics

```text
dam claude
  -> embedded dam-proxy
  -> tool base URL override
  -> pass-through provider auth

npx @rpblc/dam claude
  -> npm wrapper trial mode
  -> temporary vault/log/consent stores
  -> embedded dam-proxy

dam codex --api
  -> embedded dam-proxy
  -> Codex custom provider override
  -> pass-through OPENAI_API_KEY auth
  -> Responses API HTTP/SSE path

damctl status
  -> dam-proxy /health
  -> dam-api ProxyReport

damctl config check
  -> dam-config
  -> dam-api HealthReport

dam-web /diagnostics
  -> dam-config
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
cargo fmt --all --check
cargo clippy --workspace -- -D warnings
cargo test --workspace
```

Run only the E2E suite with:

```bash
cargo test -p dam-e2e
```
