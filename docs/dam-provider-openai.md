# dam-provider-openai

Status: implemented first extraction.

`dam-provider-openai` owns OpenAI-compatible upstream forwarding for the app-layer proxy path. It is a provider adapter boundary, not a protection pipeline.

## Responsibilities

```text
protected HTTP request body
  -> build upstream URL from configured base and incoming URI
  -> strip hop-by-hop and Connection-listed request headers
  -> replace caller Accept-Encoding with identity for transformable response bytes
  -> forward caller auth headers or inject configured upstream bearer auth
  -> send to OpenAI-compatible upstream with redirects disabled and timeout bounded
  -> strip hop-by-hop and Connection-listed response headers
  -> stream text/event-stream responses through, optionally transforming provider text deltas
  -> transform non-streaming JSON or JSON-lines string values through the caller hook when possible
  -> pass other non-streaming response bytes to the caller for optional local transform
```

For local proxy/interception flows, DAM normally uses caller-owned provider auth. When a proxy target owns an upstream API key, this crate replaces the inbound `Authorization` header with the configured upstream bearer token before forwarding.

Response bytes are handed back through a caller-provided transform hook. `dam-proxy` uses that hook for default DAM reference resolution through `dam-pipeline`. Non-streaming JSON-shaped responses are parsed through `dam-provider-common` so references inside JSON string values resolve after provider escaping is removed, including newline-delimited JSON and vendor media types. Streaming responses use the same hook only when the caller enables streaming response transformation. The streaming path uses `dam-provider-common` provider-aware SSE text-delta transformation so references split across adjacent OpenAI-compatible chat/Responses text events or related message text fields can resolve without buffering to upstream completion.

The adapter does not forward caller `Accept-Encoding`. It sends `Accept-Encoding: identity` upstream so DAM can transform UTF-8 provider response bytes before returning them to the local client.

## Boundaries

The crate does not:

- run detection, policy, consent, vault writes, redaction, or logging;
- choose proxy targets or failure modes;
- open local vault, consent, or log backends;
- parse OpenAI JSON request/response shapes into typed DTOs;
- parse OpenAI-compatible request/response bodies into semantic DTOs beyond the shared JSON/JSON-lines string-value and SSE text-delta paths handled by `dam-provider-common`;
- implement WebSocket, Anthropic, or arbitrary web adapters. Anthropic forwarding lives in `dam-provider-anthropic`.

Those responsibilities stay in `dam-proxy`, `dam-pipeline`, or future provider/router modules.

## Current Consumer

- `dam-proxy` uses `dam-provider-openai` for OpenAI-compatible request forwarding, response header filtering, configured bearer auth injection, JSON/JSON-lines string-value response restoration, SSE passthrough when streaming transformation is disabled, and provider-aware SSE text-delta reference resolution when streaming transformation is enabled.

## Testing

Tests use fake local upstream servers and do not call real OpenAI, Anthropic, OpenRouter, or other provider endpoints.

Covered cases:

- base-path, request-path, and query preservation;
- response body transform hook;
- non-streaming JSON and JSON-lines string-value response transform;
- configured upstream API key replacing inbound `Authorization`;
- hop-by-hop, `Connection`-listed, and caller `Accept-Encoding` header handling;
- `text/event-stream` passthrough without body transformation when streaming transformation is disabled;
- provider-aware `text/event-stream` body transformation resolving references split across text-delta events.

Run:

```bash
cargo test -p dam-provider-openai
```
