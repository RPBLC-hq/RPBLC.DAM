# dam-config

`dam-config` loads typed runtime configuration.

It describes topology and module selection. It does not create vaults, logs, policies, or proxies directly.

## Source Precedence

From lowest to highest:

1. Built-in defaults.
2. `dam.toml`, explicit `--config`, or `DAM_CONFIG`.
3. Environment variables.
4. CLI overrides.

Missing default `dam.toml` is allowed. Missing explicit config file is an error.

## Current Config Shape

```toml
[vault]
backend = "sqlite"
path = "vault.db"
token_env = "DAM_VAULT_TOKEN"
timeout_ms = 2000

[log]
enabled = true
backend = "sqlite"
path = "log.db"
token_env = "DAM_LOG_TOKEN"
timeout_ms = 2000

[consent]
enabled = true
backend = "sqlite"
path = "consent.db"
default_ttl_seconds = 86400
mcp_write_enabled = true

[policy]
default_action = "tokenize"
deduplicate_replacements = true

[policy.kind.ssn]
action = "tokenize"

[failure]
vault_write = "redact_only"
log_write = "warn_continue"

[web]
addr = "127.0.0.1:2896"

[proxy]
enabled = false
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

Supported first-slice provider values are `openai-compatible` and `anthropic`. The current local proxy slice accepts exactly one configured target; multi-target routing is parked until target selection has a user-facing model.

`web.addr` and `proxy.listen` must be loopback socket addresses in this local build, for example `127.0.0.1:2896` and `127.0.0.1:7828`.

## Environment Overrides

Common deployment overrides:

```bash
export DAM_CONFIG=/etc/dam/dam.toml
export DAM_VAULT_BACKEND=sqlite
export DAM_VAULT_PATH=/var/lib/dam/vault.db
export DAM_VAULT_TOKEN_ENV=DAM_VAULT_TOKEN
export DAM_LOG_ENABLED=true
export DAM_LOG_BACKEND=sqlite
export DAM_LOG_PATH=/var/lib/dam/log.db
export DAM_LOG_TOKEN_ENV=DAM_LOG_TOKEN
export DAM_CONSENT_ENABLED=true
export DAM_CONSENT_PATH=/var/lib/dam/consent.db
export DAM_CONSENT_DEFAULT_TTL_SECONDS=86400
export DAM_CONSENT_MCP_WRITE_ENABLED=true
export DAM_POLICY_DEFAULT_ACTION=tokenize
export DAM_POLICY_DEDUPLICATE_REPLACEMENTS=true
export DAM_POLICY_SSN_ACTION=redact
export DAM_FAILURE_VAULT_WRITE=redact_only
export DAM_FAILURE_LOG_WRITE=warn_continue
export DAM_WEB_ADDR=127.0.0.1:2896
export DAM_PROXY_ENABLED=true
export DAM_PROXY_LISTEN=127.0.0.1:7828
export DAM_PROXY_DEFAULT_FAILURE_MODE=bypass_on_error
export DAM_PROXY_RESOLVE_INBOUND=false
export DAM_PROXY_TARGET_UPSTREAM=https://api.openai.com
export DAM_PROXY_TARGET_API_KEY_ENV=OPENAI_API_KEY
```

Supported policy env keys:

```text
DAM_POLICY_DEFAULT_ACTION
DAM_POLICY_DEDUPLICATE_REPLACEMENTS
DAM_POLICY_EMAIL_ACTION
DAM_POLICY_PHONE_ACTION
DAM_POLICY_SSN_ACTION
DAM_POLICY_CC_ACTION
DAM_POLICY_CREDIT_CARD_ACTION
```

Supported consent env keys:

```text
DAM_CONSENT_ENABLED
DAM_CONSENT_BACKEND
DAM_CONSENT_PATH
DAM_CONSENT_SQLITE_PATH
DAM_CONSENT_DEFAULT_TTL_SECONDS
DAM_CONSENT_MCP_WRITE_ENABLED
```

Supported vault env keys:

```text
DAM_VAULT_BACKEND
DAM_VAULT_PATH
DAM_VAULT_SQLITE_PATH
DAM_VAULT_URL
DAM_VAULT_TOKEN_ENV
DAM_VAULT_TIMEOUT_MS
DAM_VAULT_TOKEN
```

Supported log env keys:

```text
DAM_LOG_ENABLED
DAM_LOG_BACKEND
DAM_LOG_PATH
DAM_LOG_SQLITE_PATH
DAM_LOG_URL
DAM_LOG_TOKEN_ENV
DAM_LOG_TIMEOUT_MS
DAM_LOG_TOKEN
```

Supported failure env keys:

```text
DAM_FAILURE_VAULT_WRITE
DAM_FAILURE_LOG_WRITE
```

Supported proxy env keys:

```text
DAM_PROXY_ENABLED
DAM_PROXY_LISTEN
DAM_PROXY_MODE
DAM_PROXY_DEFAULT_FAILURE_MODE
DAM_PROXY_RESOLVE_INBOUND
DAM_PROXY_TARGET_NAME
DAM_PROXY_TARGET_PROVIDER
DAM_PROXY_TARGET_UPSTREAM
DAM_PROXY_TARGET_FAILURE_MODE
DAM_PROXY_TARGET_API_KEY_ENV
```

## Secrets

Config files may name secret env vars but should not contain secret values.

```toml
[vault]
backend = "remote"
url = "https://vault.internal"
token_env = "DAM_VAULT_TOKEN"
```

Current binaries validate remote settings but do not implement remote backends yet.

`policy.deduplicate_replacements` defaults to `true`. Set it to `false` when each occurrence should receive an independent token reference to reduce equality leakage.

Proxy target API keys are also secret refs:

```toml
[[proxy.targets]]
name = "openai"
provider = "openai-compatible"
upstream = "https://api.openai.com"
api_key_env = "OPENAI_API_KEY"
```

`dam-proxy` uses the resolved key if present. If `api_key_env` is configured but missing and the request does not provide provider auth, the proxy returns `config_required`. For `openai-compatible`, provider auth is `Authorization`. For `anthropic`, provider auth is `x-api-key`; `Authorization` is also accepted as caller auth for compatibility but is dropped when DAM injects an Anthropic target key.

## Tests

```bash
cargo test -p dam-config
```
