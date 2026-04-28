# dam-provider-openai

Status: implemented first extraction.

`dam-provider-openai` owns OpenAI-compatible upstream forwarding for the app-layer proxy path. It is a provider adapter boundary, not a protection pipeline.

## Responsibilities

```text
protected HTTP request body
  -> build upstream URL from configured base and incoming URI
  -> strip hop-by-hop and Connection-listed request headers
  -> forward caller auth headers or inject configured upstream bearer auth
  -> send to OpenAI-compatible upstream with redirects disabled and timeout bounded
  -> strip hop-by-hop and Connection-listed response headers
  -> stream text/event-stream responses through unchanged
  -> pass non-streaming response bytes to the caller for optional local transform
```

For local launcher flows, DAM normally uses caller-owned provider auth. When a proxy target owns an upstream API key, this crate replaces the inbound `Authorization` header with the configured upstream bearer token before forwarding.

Non-streaming response bytes are handed back through a caller-provided transform hook. `dam-proxy` uses that hook only for opt-in DAM reference resolution through `dam-pipeline`.

## Boundaries

The crate does not:

- run detection, policy, consent, vault writes, redaction, or logging;
- choose proxy targets or failure modes;
- open local vault, consent, or log backends;
- parse OpenAI JSON request/response shapes into typed DTOs;
- parse SSE events or transform streaming responses;
- implement WebSocket, Anthropic, or arbitrary web adapters.

Those responsibilities stay in `dam-proxy`, `dam-pipeline`, or future provider/router modules.

## Current Consumer

- `dam-proxy` uses `dam-provider-openai` for OpenAI-compatible request forwarding, response header filtering, configured bearer auth injection, and SSE passthrough.

## Testing

Tests use fake local upstream servers and do not call real OpenAI, Anthropic, OpenRouter, or other provider endpoints.

Covered cases:

- base-path, request-path, and query preservation;
- non-streaming response body transform hook;
- configured upstream API key replacing inbound `Authorization`;
- hop-by-hop and `Connection`-listed header stripping;
- `text/event-stream` passthrough without body transformation.

Run:

```bash
cargo test -p dam-provider-openai
```
