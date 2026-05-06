# dam-proxy

Status: implemented first slice.

`dam-proxy` is the first hot-path proxy module. It is a generic mediation runtime with an MVP provider adapter set for selected OpenAI-compatible and Anthropic traffic. In daemon transparent mode, it also owns the guarded HTTP/1.1 `CONNECT` TLS interception runtime for active traffic-profile routes when routing, trust, and consent are all ready. It includes the MVP WebSocket adapter for Codex ChatGPT-login traffic on `chatgpt.com`. It does not install local CAs, install routes, create TUN devices, or rewrite arbitrary web traffic.

## Architecture

Current first slice:

```text
client or harness
  -> dam-proxy
  -> dam-router
  -> first configured proxy target
  -> provider HTTP request body
  -> dam-pipeline
  -> expand actively allowed DAM references through dam-vault when present
  -> dam-detect
  -> dam-policy
  -> dam-consent active canonical-value overrides
  -> dam-core replacement plan
  -> dam-vault for tokenize decisions
  -> dam-redact
  -> dam-log
  -> provider adapter
  -> upstream provider
  -> provider response body
  -> provider adapter
  -> dam-pipeline when proxy.resolve_inbound is enabled
  -> dam-core resolve plan for existing DAM references
  -> dam-vault through VaultReader
  -> dam-log
  -> client or harness
```

Outbound requests are the only direction that gets detection, policy, tokenization, and redaction by default. Inbound provider responses are not scanned or redacted. When `proxy.resolve_inbound` is enabled, which is the default, UTF-8 responses resolve known `[kind:id]` references that were created by outbound tokenization. Missing or unreadable references pass through unchanged.

JSON-shaped provider responses are transformed as JSON string values when inbound reference resolution is enabled, so references inside provider-escaped message fields can resolve without corrupting JSON. The provider adapters try whole-body JSON first, then newline-delimited JSON, regardless of the exact response media type. Provider responses with `Content-Type: text/event-stream` are transformed when inbound reference resolution is enabled so provider-native SSE framing stays intact. The provider adapters use bounded provider-aware SSE text-delta parsing for OpenAI-compatible and Anthropic streams, which lets known DAM references resolve even when a provider splits one reference across adjacent JSON text-delta events without buffering the whole response to EOF. The SSE parser also falls back to JSON string-value event transforms for unrecognized event shapes. With `--no-resolve-inbound`, event-stream responses pass through without local restoration. Preserving exact token-by-token latency for every provider-specific event shape remains future work.

Repeated equal outbound canonical values reuse one tokenized reference by default, and compatible vault writers reuse an existing canonical reference for the same stored value. Email canonicalization removes detector-supported whitespace inside the address and lowercases the domain before storage/deduplication. Disable that with `policy.deduplicate_replacements = false` or `DAM_POLICY_DEDUPLICATE_REPLACEMENTS=false` when preserving equality across repeated values is too revealing.

Active consent grants let canonical detected values pass through unredacted until expiry or revocation. Consent overrides `tokenize` and `redact`; it does not override `block`. If a later outbound request contains an old DAM reference for the same allowed value, `dam-proxy` passes its vault reader into `dam-pipeline` so that reference is expanded before detection and provider egress. References without active consent remain protected.

The current implementation keeps HTTP serving, backend opening, and DAM-owned status responses inside `dam-proxy`. Provider adapter storage/selection is isolated in `src/providers.rs`, non-sensitive proxy event helpers are isolated in `src/events.rs`, and WebSocket framing lives in `src/websocket.rs`. Shared text processing orchestration lives in `dam-pipeline`, OpenAI-compatible forwarding lives in `dam-provider-openai`, Anthropic forwarding lives in `dam-provider-anthropic`, and first-slice route decisions live in `dam-router`.

Transparent system-proxy traffic reaches DAM as HTTP `CONNECT`. The standalone app-layer `dam-proxy` path still fails closed for `CONNECT`. When `dam-daemon` starts `dam-proxy` in transparent mode, `dam-proxy` uses a raw TCP CONNECT loop instead of the Axum app-layer server. That loop must bind to loopback and activates only when `dam-net` routing readiness, `dam-trust` local CA readiness, explicit consent, and `dam-intercept` adapter readiness are all `ready`.

The first transparent runtime slice is intentionally narrow: HTTP/1.1 requests over CONNECT, active `inspect` apps from the effective traffic profile, configured OpenAI-compatible and Anthropic targets only, no chunked request bodies, no HTTP/2, and request bodies capped at 32 MiB before buffering. Intercepted JSON and `text/event-stream` responses are transformed for inbound reference resolution when restoration is enabled, including provider text-delta event streams for OpenAI-compatible and Anthropic targets. WebSocket upgrade traffic is supported for the Codex ChatGPT-login path: extension negotiation is stripped, unfragmented client text frames are protected, fragmented/binary client frames pass through with a warning event, and server-to-client frames currently pass through without local reference resolution. Unsupported or not-ready traffic fails closed rather than becoming an opaque tunnel.

Supported provider IDs are:

- `openai-compatible`: bearer `Authorization` auth replacement when DAM owns the upstream key.
- `anthropic`: `x-api-key` auth replacement when DAM owns the upstream key.

## Usage

With config:

```bash
cargo run -p dam-proxy -- --config dam.example.toml
```

Without a config file, pass an upstream explicitly:

```bash
cargo run -p dam-proxy -- \
  --listen 127.0.0.1:7828 \
  --upstream https://api.openai.com \
  --api-key-env OPENAI_API_KEY
```

For local fake-upstream tests or caller-owned auth, disable proxy-managed API key injection. DAM will forward the incoming `Authorization` or provider auth headers:

```bash
cargo run -p dam-proxy -- \
  --upstream http://127.0.0.1:9999 \
  --no-api-key-env
```

Local proxy/interception flows use this pass-through auth mode by default. The old `dam claude`, `dam codex`, and `dam codex --api` one-shot launchers were removed because DAM no longer protects by rewriting provider API base URLs or Codex provider config.

To leave DAM references unresolved on the inbound response path:

```bash
cargo run -p dam-proxy -- \
  --upstream http://127.0.0.1:9999 \
  --no-resolve-inbound \
  --no-api-key-env
```

Health:

```bash
curl http://127.0.0.1:7828/health
cargo run -p damctl -- status
```

`/health` returns the standardized `dam-api` `ProxyReport` JSON shape. DAM-owned failure responses such as `config_required`, `blocked`, and `provider_down` use the same shape. Successful upstream provider responses are forwarded as provider responses, not wrapped, after DAM reference resolution when applicable.

## Failure Behavior

- Protection precondition failures fail closed before provider egress. This includes unsupported content encodings, non-UTF-8 request bodies in the current text pipeline, consent backend errors, and invariant failures where the pipeline does not produce protected output.
- Transparent `CONNECT` requests fail closed unless the daemon supplied the transparent runtime config and routing, trust, consent, and adapter readiness are all ready.
- `bypass_on_error`: retained as a visible failure-mode state for reduced-protection configurations, but it is not allowed to forward request bytes that DAM failed to inspect/protect.
- `redact_only`: supported for vault failures. If a tokenized vault write fails, the value becomes `[kind]`.
- `block_on_error`: strict proxy/protection failure behavior. The proxy returns a clear `blocked` response instead of forwarding unprotected traffic.
- `config_required`: returned when a target requires an API key env var, the env var is missing, and the incoming request has no provider-compatible auth header.
- `provider_down`: returned when DAM is reachable but the upstream provider cannot be reached.

Bypass is not silent when logging is enabled. The persisted event type is `proxy_bypass`.

When logging is enabled, the proxy also records non-sensitive diagnostic checkpoints for mediated requests:

- `route_decision`: selected target/provider, protection state, inbound-resolution state, and request byte count.
- `request_protection`: detection/replacement counts and whether replacements were tokenized or blocked.
- `provider_forward_start`: provider adapter handoff and streaming-resolution intent.
- `provider_response`: provider status, content type, content encoding, and streaming classification.
- `resolve_attempt`: inbound reference count plus resolved, missing, and read-failure counts for each transformed response body segment.
- `resolve_disabled`: response body size when inbound restoration is configured off. This is recorded as proxy diagnostics, not as a `resolve` event.
- `intercepted_response_write`: transparent runtime response status/content type/streaming state immediately before writing back to the client.

These events must not include raw request bodies, raw response bodies, API keys, or resolved sensitive values. They exist to diagnose where a mediation path stopped without weakening the no-PII-in-logs rule.

Provider connection errors are reported as `provider_down` without echoing upstream URLs in user-visible messages.

DAM-owned status responses include `state`, `message`, `operation_id`, `target`, `upstream`, and non-sensitive `diagnostics` through `dam-api::ProxyReport`.

## Config

```toml
[proxy]
enabled = true
listen = "127.0.0.1:7828"
mode = "reverse_proxy"
default_failure_mode = "bypass_on_error"
resolve_inbound = true

[[proxy.targets]]
name = "openai"
provider = "openai-compatible"
upstream = "https://api.openai.com"
failure_mode = "bypass_on_error"
api_key_env = "OPENAI_API_KEY"
```

Anthropic target example:

```toml
[[proxy.targets]]
name = "anthropic"
provider = "anthropic"
upstream = "https://api.anthropic.com"
failure_mode = "bypass_on_error"
api_key_env = "ANTHROPIC_API_KEY"
```

Traffic profile selection example:

```toml
[traffic]
profile_path = "traffic-profile.json"
enabled_apps = ["openai-api", "anthropic-api", "chatgpt-codex"]
```

Legacy transparent route overlay example:

```toml
[[network.ai_routes]]
host = "api.enterprise-ai.example"
provider = "openai-compatible"
target_name = "enterprise-ai"
upstream = "https://api.enterprise-ai.example"
```

The traffic profile controls transparent host recognition and adapter intent. Legacy route overlays remain available for old configs. Active forwarding targets are configured separately through `[[proxy.targets]]`. The local proxy can host multiple targets in one process and selects the OpenAI-compatible or Anthropic route from request path/header shape or the transparent route match.

Secrets must be supplied through environment variables or deployment secret stores, not plaintext config files. For local proxy/interception flows, omit `api_key_env` so DAM forwards caller-owned auth headers instead of injecting a provider key.

## Testing

`dam-proxy` tests use fake upstream HTTP servers and do not call real OpenAI, Anthropic, or OpenRouter endpoints.

Covered cases:

- redacted request forwarding to fake upstream;
- inbound response resolution for DAM references in non-streaming responses, including JSON and JSON-lines string-value restoration;
- outbound expansion of previously tokenized references when the referenced value has active consent;
- `text/event-stream` response transformation with inbound reference resolution enabled, including references split across adjacent chunks and across Anthropic text-delta events without EOF buffering;
- disabled inbound response resolution leaving DAM references intact;
- vault writes and log writes during forwarding;
- bypass on invalid UTF-8 with `bypass_on_error`;
- block on invalid UTF-8 with `block_on_error`;
- policy `block` returning 403 without forwarding;
- missing API key producing `config_required`;
- configured upstream API key replacing inbound `Authorization`;
- Anthropic `x-api-key` passthrough and configured key replacement;
- transparent `CONNECT` requests failing closed without provider egress;
- transparent HTTP/1.1 CONNECT/TLS requests completing a local-CA TLS handshake and forwarding only protected request bodies to the fake upstream;
- transparent raw HTTP `text/event-stream` responses resolved before reaching the client when inbound resolution is enabled;
- non-sensitive proxy diagnostics around route selection, request protection, provider handoff/response, inbound resolution, and transparent response write boundaries;
- hop-by-hop and `Connection`-listed header stripping;
- upstream connection failure producing `provider_down`;
- `dam-api` `ProxyReport` JSON for health and DAM-owned failure responses;
- disabled proxy and unsupported provider startup failures.

Run:

```bash
cargo test -p dam-proxy
```

## Parked

- HTTP/2 and multi-request transparent tunnel handling.
- Local CA management and OS route installation.
- VPN/TUN/network-extension routing.
- binary/non-UTF-8 upload endpoints until a profile adapter defines safe parsing behavior.
- inbound, fragmented, or compressed WebSocket payload protection beyond the Codex MVP client text-frame adapter.
- Additional generic adapters for arbitrary web traffic beyond HTTP/WebSocket provider traffic.
- exact token-by-token provider-aware streaming/SSE response transforms and fresh inbound redetection.
