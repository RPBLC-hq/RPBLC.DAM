# dam-proxy

Status: implemented first slice.

`dam-proxy` is the first hot-path proxy module. It is an application-layer LLM endpoint / reverse proxy for selected OpenAI-compatible and Anthropic traffic. It does not do TLS interception, local CA installation, WebSockets, VPN/TUN routing, or arbitrary web traffic rewriting.

## Architecture

Current first slice:

```text
client or harness
  -> dam-proxy
  -> dam-router
  -> first configured proxy target
  -> provider HTTP request body
  -> dam-pipeline
  -> dam-detect
  -> dam-policy
  -> dam-consent active exact-value overrides
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

Outbound requests are the only direction that gets detection, policy, tokenization, and redaction by default. Inbound provider responses are not scanned or redacted. When `proxy.resolve_inbound` is enabled, which is opt-in, non-streaming UTF-8 responses only resolve known `[kind:id]` references that were created by outbound tokenization. Missing or unreadable references pass through unchanged.

Provider responses with `Content-Type: text/event-stream` are streamed through without inbound reference resolution. That keeps Codex Responses API and Anthropic HTTP streaming usable before provider adapters own SSE event parsing.

Repeated equal outbound values reuse one tokenized reference by default within a single request. Disable that with `policy.deduplicate_replacements = false` or `DAM_POLICY_DEDUPLICATE_REPLACEMENTS=false` when preserving equality across repeated values is too revealing.

Active consent grants let exact detected values pass through unredacted until expiry or revocation. Consent overrides `tokenize` and `redact`; it does not override `block`.

The current implementation keeps HTTP serving, backend opening, provider adapter dispatch, and DAM-owned status responses inside `dam-proxy`. Shared text processing orchestration lives in `dam-pipeline`, OpenAI-compatible forwarding lives in `dam-provider-openai`, Anthropic forwarding lives in `dam-provider-anthropic`, and first-slice route decisions live in `dam-router`.

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

The local `dam claude` launcher uses this pass-through auth mode by default. `dam codex --api` also uses pass-through auth from Codex's `OPENAI_API_KEY` custom provider mode. `dam codex` without `--api` fails closed until Codex's current ChatGPT-login model transport can be protected.

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
- `bypass_on_error`: retained as a visible failure-mode state for reduced-protection configurations, but it is not allowed to forward request bytes that DAM failed to inspect/protect.
- `redact_only`: supported for vault failures. If a tokenized vault write fails, the value becomes `[kind]`.
- `block_on_error`: strict proxy/protection failure behavior. The proxy returns a clear `blocked` response instead of forwarding unprotected traffic.
- `config_required`: returned when a target requires an API key env var, the env var is missing, and the incoming request has no provider-compatible auth header.
- `provider_down`: returned when DAM is reachable but the upstream provider cannot be reached.

Bypass is not silent when logging is enabled. The persisted event type is `proxy_bypass`.

Provider connection errors are reported as `provider_down` without echoing upstream URLs in user-visible messages.

DAM-owned status responses include `state`, `message`, `operation_id`, `target`, `upstream`, and non-sensitive `diagnostics` through `dam-api::ProxyReport`.

## Config

```toml
[proxy]
enabled = true
listen = "127.0.0.1:7828"
mode = "reverse_proxy"
default_failure_mode = "bypass_on_error"
resolve_inbound = false

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

Secrets must be supplied through environment variables or deployment secret stores, not plaintext config files. For local launcher flows, omit `api_key_env` so DAM forwards caller-owned auth headers instead of injecting a provider key.

## Testing

`dam-proxy` tests use fake upstream HTTP servers and do not call real OpenAI, Anthropic, or OpenRouter endpoints.

Covered cases:

- redacted request forwarding to fake upstream;
- inbound response resolution for DAM references in non-streaming responses;
- `text/event-stream` response pass-through without inbound resolution;
- disabled inbound response resolution leaving DAM references intact;
- vault writes and log writes during forwarding;
- bypass on invalid UTF-8 with `bypass_on_error`;
- block on invalid UTF-8 with `block_on_error`;
- policy `block` returning 403 without forwarding;
- missing API key producing `config_required`;
- configured upstream API key replacing inbound `Authorization`;
- Anthropic `x-api-key` passthrough and configured key replacement;
- hop-by-hop and `Connection`-listed header stripping;
- upstream connection failure producing `provider_down`;
- `dam-api` `ProxyReport` JSON for health and DAM-owned failure responses;
- disabled proxy and unsupported provider startup failures.

Run:

```bash
cargo test -p dam-proxy
```

## Parked

- TLS interception and local CA management.
- VPN/TUN/network-extension routing.
- WebSocket adapters.
- Arbitrary web traffic adapters.
- Streaming/SSE response reference resolution.
