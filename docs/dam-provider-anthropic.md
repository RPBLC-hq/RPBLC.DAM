# dam-provider-anthropic

Status: implemented first extraction.

`dam-provider-anthropic` owns Anthropic upstream forwarding for the app-layer proxy path. It is a provider adapter boundary, not a protection pipeline.

## Responsibilities

```text
protected HTTP request body
  -> build upstream URL from configured base and incoming URI
  -> strip hop-by-hop and Connection-listed request headers
  -> forward caller x-api-key auth or inject configured upstream x-api-key
  -> send to Anthropic upstream with redirects disabled and timeout bounded
  -> strip hop-by-hop and Connection-listed response headers
  -> stream text/event-stream responses through unchanged
  -> pass non-streaming response bytes to the caller for optional local transform
```

For local `dam claude` flows, DAM normally uses caller-owned provider auth. When a proxy target owns an upstream API key, this crate replaces inbound `x-api-key` and drops inbound `Authorization` before forwarding. This follows Anthropic's API auth model, which uses the `x-api-key` request header.

Non-streaming response bytes are handed back through a caller-provided transform hook. `dam-proxy` uses that hook only for opt-in DAM reference resolution through `dam-pipeline`.

## Boundaries

The crate does not:

- run detection, policy, consent, vault writes, redaction, or logging;
- choose proxy targets or failure modes;
- open local vault, consent, or log backends;
- parse Anthropic JSON request/response shapes into typed DTOs;
- parse SSE events or transform streaming responses;
- implement WebSocket, OpenAI, or arbitrary web adapters.

Those responsibilities stay in `dam-proxy`, `dam-pipeline`, or future provider/router modules.

## Current Consumer

- `dam-proxy` uses `dam-provider-anthropic` when a proxy target has `provider = "anthropic"`.

## Testing

Tests use fake local upstream servers and do not call real OpenAI, Anthropic, OpenRouter, or other provider endpoints.

Covered cases:

- base-path, request-path, and query preservation;
- non-streaming response body transform hook;
- caller `x-api-key` passthrough when DAM does not inject a target key;
- configured upstream API key replacing inbound `x-api-key` and dropping inbound `Authorization`;
- hop-by-hop and `Connection`-listed header stripping;
- `text/event-stream` passthrough without body transformation.

Run:

```bash
cargo test -p dam-provider-anthropic
```
