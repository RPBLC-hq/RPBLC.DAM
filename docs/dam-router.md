# dam-router

Status: implemented first extraction.

`dam-router` owns reusable proxy route decisions for the app-layer LLM proxy path. It does not serve HTTP, forward provider requests, run detection or policy, open backends, or build DAM-owned HTTP responses.

## Responsibilities

Current first slice:

```text
proxy config
  -> first configured target
  -> provider classification
  -> effective failure mode

request headers
  -> auth mode decision
  -> caller passthrough, target API key injection, or config_required
```

Supported provider IDs are:

- `openai-compatible`
- `anthropic`

The first implementation intentionally selects the first configured target to preserve existing `dam-proxy` semantics. Multi-target routing, host/path/profile matching, model discovery, and integration profile selection are future expansions on this boundary.

## Auth Decisions

`dam-router` returns one of three auth modes for a request:

- `CallerPassthrough`: DAM forwards provider auth from the local tool or harness.
- `TargetApiKey`: DAM injects the resolved target API key from config/env.
- `ConfigRequired`: the target names an API-key env var, no value resolved, and the request does not include provider-compatible caller auth.

For `openai-compatible`, caller auth means an `Authorization` header is present.

For `anthropic`, caller auth means `x-api-key` or `Authorization` is present. Anthropic provider forwarding still owns the provider-specific rule that injected target keys use `x-api-key` and drop inbound `Authorization`.

## Boundaries

The crate does not:

- parse or transform request bodies;
- inspect URLs or select among multiple targets yet;
- forward requests to providers;
- emit log events;
- construct `dam-api` reports;
- decide provider-down behavior after forwarding starts.

Those responsibilities stay in `dam-proxy`, `dam-pipeline`, and provider adapter crates.

## Current Consumer

- `dam-proxy` uses `dam-router` for startup provider validation, effective failure mode, health config-required checks, and per-request auth decisions.

## Testing

Run:

```bash
cargo test -p dam-router
```
