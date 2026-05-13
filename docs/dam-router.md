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

- `generic-http`
- `openai-compatible`
- `anthropic`

The route table supports multiple configured targets. It selects Anthropic or OpenAI-compatible targets from request path/header shape, and transparent traffic can select the target from the matched AI route. `generic-http` is selected by explicit target/profile route metadata and does not require a provider-specific auth header shape, but generic website profile creation/import is parked in the current app. Ambiguous direct app-layer requests still fall back to the first configured target.

Transparent host classification for system-proxy/TUN routing lives in `dam-net`, not in `dam-router`. `dam-router` still owns target/auth/failure decisions after `dam-proxy` has identified an active AI route from the transparent request authority.

## Auth Decisions

`dam-router` returns one of three auth modes for a request:

- `CallerPassthrough`: DAM forwards provider auth from the local tool or harness.
- `TargetApiKey`: DAM injects the resolved target API key from config/env.
- `ConfigRequired`: the target names an API-key env var, no value resolved, and the request does not include provider-compatible caller auth.

For `openai-compatible`, caller auth means an `Authorization` header is present.

For `anthropic`, caller auth means `x-api-key` or `Authorization` is present. Anthropic provider forwarding still owns the provider-specific rule that injected target keys use `x-api-key` and drop inbound `Authorization`.

For `generic-http`, caller auth is always considered pass-through. DAM must not require or inject a provider API key unless a future explicit generic credential contract is designed.

## Boundaries

The crate does not:

- parse or transform request bodies;
- classify transparent hosts or parse traffic profiles;
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
