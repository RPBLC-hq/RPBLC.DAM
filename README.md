<div align="center">
  <h1>DAM</h1>
  <h3>Data Access Mediator</h3>
  <p><strong>A local privacy firewall for coding agents.</strong></p>
</div>

<p align="center">
  <a href="https://opensource.org/licenses/Apache-2.0"><img src="https://img.shields.io/badge/license-Apache_2.0-blue.svg" alt="License: Apache-2.0"></a>
  <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/rust-1.94%2B-orange.svg" alt="Rust 1.94+"></a>
  <a href="https://nodejs.org/"><img src="https://img.shields.io/badge/node-%3E%3D18-43853d.svg" alt="Node >=18"></a>
  <img src="https://img.shields.io/badge/npm-%40rpblc%2Fdam-cb3837.svg" alt="npm: @rpblc/dam">
  <img src="https://img.shields.io/badge/checks-fmt%20%7C%20clippy%20%7C%20test-2ea44f.svg" alt="Checks: fmt, clippy, test">
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> &middot;
  <a href="#how-it-works">How It Works</a> &middot;
  <a href="#consent">Consent</a> &middot;
  <a href="#web-ui">Web UI</a> &middot;
  <a href="#commands">Commands</a> &middot;
  <a href="#v1-limits">V1 Limits</a> &middot;
  <a href="#what-to-do-next">What To Do Next</a>
</p>

---

DAM runs on your machine between a coding agent and its model provider. It detects sensitive values in outbound prompts, applies local policy and consent, replaces protected values with stable references, and stores originals in a local vault so the provider only sees what you meant to share.

V1 is focused on the local AI paths that matter most right now:

- **Harnesses and agents** through `dam connect`, which starts a local protected endpoint.
- **Claude Code** through `ANTHROPIC_BASE_URL`.
- **Codex API-key mode** through an injected OpenAI provider config.

Codex ChatGPT-login mode is deliberately blocked until that transport can be protected.

```text
You type:

  "Email banana@banana.com and include card 4111-1111-1111-1111"

DAM sends upstream:

  "Email [email:BhjEUc1EX1JHLbeT7JUS6g]
   and include card [cc:7j21sVjW3aN4xFqP9L6MRA]"

Provider can reason over:

  "there is an email"     "there is a card"

Provider does not need:

  banana@banana.com       4111-1111-1111-1111
```

## Quick Start

Use the one-shot npm trial when you want to try DAM without creating persistent local databases:

```bash
npx @rpblc/dam claude
```

For Codex, use API-key mode:

```bash
OPENAI_API_KEY=sk-... npx @rpblc/dam codex --api
```

Trial mode creates temporary vault, log, and consent databases, starts the protected agent, then removes those databases when the session exits.

```text
DAM trial mode
Vault:    /tmp/dam-trial-.../vault.db
Log:      /tmp/dam-trial-.../log.db
Consents: /tmp/dam-trial-.../consent.db
```

Keep the trial databases for inspection:

```bash
npx @rpblc/dam claude --keep
```

Install globally for normal persistent local state:

```bash
npm install -g @rpblc/dam
dam connect
dam status
dam integrations list
dam claude
dam codex --api
```

With `npx`, `--persist` bypasses one-shot trial mode and uses configured/default database paths:

```bash
npx @rpblc/dam claude --persist
```

From a source checkout:

```bash
cargo run -p dam -- connect
cargo run -p dam -- integrations list
cargo run -p dam -- claude
cargo run -p dam -- codex --api
```

## How It Works

```text
              local machine                                      provider

  prompt ──► dam launcher/daemon ──► dam-proxy ────────────────► model API
              │                 │                                    │
              │                 ├─ detect sensitive values           │
              │                 ├─ apply policy                      │
              │                 ├─ apply active consents             │
              │                 ├─ write tokenized values to vault   │
              │                 ├─ redact outbound request           │
              │                 └─ write non-sensitive log events    │
              │                                                      │
              ◄──────────────── response with DAM references ◄───────┘

  vault.db       raw originals for tokenized values, local SQLite
  consent.db     exact-value passthrough grants with TTL
  log.db         event metadata, not raw detected values
```

The outbound pipeline is the same shape across the proxy and `dam-filter`:

```text
input
  -> dam-detect
  -> dam-policy
  -> dam-consent active exact-value overrides
  -> dam-core replacement plan
  -> dam-vault for tokenized values
  -> dam-redact
  -> output
```

Repeated equal values reuse the same reference by default inside one request/run:

```toml
[policy]
deduplicate_replacements = true
```

Set it to `false` if reusing the same reference leaks too much equality information for your use case.

## Consent

Consent lets a specific detected value pass through unredacted until its TTL expires or the grant is revoked. It overrides `tokenize` and `redact`; it does not override `block`.

Consents are exact-value grants keyed by:

```text
kind + value_fingerprint + scope
```

They do not store the raw sensitive value. A grant created from the vault UI or MCP server uses a stable vault key such as:

```text
email:ANJFsZtLfEA9WeP3bZS8Nw
```

That stable key matters because inbound reference resolution can turn bracket references back into local values before an agent sees them.

Default consent config:

```toml
[consent]
enabled = true
backend = "sqlite"
path = "consent.db"
default_ttl_seconds = 86400
mcp_write_enabled = true
```

Revoking a consent revokes every active grant for the same exact value and scope, so duplicate vault rows cannot keep passthrough alive after revoke.

## Web UI

`dam-web` is the local admin UI for development and operator inspection:

```bash
dam web --config dam.example.toml
cargo run -p dam-web -- --config dam.example.toml
```

It provides:

- `/` for vault rows, cleartext values, and row-level grant/revoke actions.
- `/consents` for active and historical consent records.
- `/logs` for non-sensitive detection, redaction, consent, and resolve events.
- `/doctor` for local readiness checks shared with `damctl doctor`.
- `/diagnostics` for config and proxy health checks.

The web UI displays vault values in clear text. Treat it as a local admin surface, not a public web app.

## MCP

DAM ships an MCP server so an agent can manage consent when enabled:

```bash
cargo run -p damctl -- mcp config
cargo run -p dam-mcp -- --config dam.example.toml
```

Current tools:

- `dam_consent_list`
- `dam_consent_grant`
- `dam_consent_revoke`

`dam_consent_request` is intentionally parked until the notification flow exists.

## Commands

Background local endpoint:

```bash
dam connect [--openai|--anthropic] [DAM_OPTIONS]
dam connect --profile <profile> [DAM_OPTIONS]
dam status [--json]
dam disconnect
dam integrations list [--json]
dam integrations show <profile> [--json]
dam integrations apply <profile> [--dry-run]
dam integrations rollback <profile>
```

Protected agent launchers:

```bash
dam claude [DAM_OPTIONS] [-- CLAUDE_ARGS...]
dam codex --api [DAM_OPTIONS] [-- CODEX_ARGS...]
```

DAM options:

```text
--profile <id>        Apply integration profile daemon defaults
--openai              Use the OpenAI-compatible daemon preset
--anthropic           Use the Anthropic daemon preset
--api                 Use Codex API-key mode through DAM
--config <path>       Load DAM config before launcher overrides
--listen <addr>       Local proxy listen address, default 127.0.0.1:7828
--target-name <name>  Proxy target name for daemon mode
--provider <name>     Provider adapter for daemon mode
--upstream <url>      Provider upstream
--db <path>           Vault SQLite path, default vault.db
--log <path>          Log SQLite path, default log.db
--consent-db <path>   Consent SQLite path, default consent.db
--no-log              Disable DAM log writes
--no-resolve-inbound  Leave DAM references unresolved in inbound responses
--resolve-inbound     Restore known DAM references in inbound responses
```

Auxiliary binaries are available from a source build and native distributions:

```bash
cargo run -p dam-filter -- --config dam.example.toml session.txt > clean.txt
cargo run -p dam-filter -- --config dam.example.toml --report session.txt > clean.txt 2> report.txt
```

Control and diagnostics:

```bash
cargo run -p damctl -- status
cargo run -p damctl -- doctor --config dam.example.toml
cargo run -p damctl -- daemon inspect
cargo run -p damctl -- integrations check
cargo run -p damctl -- config check --config dam.example.toml
cargo run -p damctl -- mcp config --config dam.example.toml
```

## Detection

The current detector is rule-based and intentionally narrow:

- email addresses, including common whitespace separator variants
- NANP phone numbers in dashed form
- US SSNs with basic invalid-area rejection
- credit cards with Luhn validation

Policy maps detections to `tokenize`, `redact`, `allow`, or `block`. The default policy tokenizes supported kinds.

## V1 Limits

- DAM is explicit base-URL routing, not transparent HTTPS interception, VPN/TUN routing, or TLS MITM.
- `dam connect` starts a local endpoint, and `dam integrations` shows harness setup profiles. `dam integrations apply codex-api` can edit Codex config with a backup; other profiles currently write DAM-managed environment files.
- Codex ChatGPT-login mode is blocked because its current model transport is not protected by the base-URL launcher.
- Inbound provider responses are not redetected. Known DAM references can be resolved locally with `--resolve-inbound`, but this is off by default.
- The current vault/log/consent stores are local SQLite implementations.
- The detector does not yet cover names, addresses, organizations, private keys, JWTs, API keys, IBANs, or IP addresses.
- The npm package is a Node entry point around native DAM binaries; release packaging must include the platform binaries under `npm/native`.

## What To Do Next

Recommended order for the next engineering sessions:

1. Smoke test `dam connect`, `dam claude`, and `dam codex --api` against fake or real provider paths, then inspect the vault and log SQLite databases.
2. Expand profile apply support beyond Codex where harness config files can be changed safely.
3. Expand `damctl` beyond doctor with richer service/install checks.
4. Add login/startup UX for the daemon after profile apply is stable.

Do not spend the next session on these until their prerequisite slice exists:

- Codex ChatGPT-login protection, unless the work is specifically the WebSocket/`backend-api/codex/responses` transport plan or adapter.
- TLS interception, local CA management, VPN/TUN, or arbitrary web traffic rewriting.
- Streaming/SSE response resolution before provider streaming semantics are designed and fixture-tested.
- Remote vault/log backends before the local router and pipeline contracts prove stable.

Implemented extraction modules:

- `dam-pipeline`: shared request processing orchestration for proxy/API-style flows.
- `dam-provider-openai`: OpenAI-compatible adapter with fixture-first tests and no real provider calls in automated tests.
- `dam-provider-anthropic`: Anthropic-compatible adapter with fixture-first tests and no real provider calls in automated tests.
- `dam-router`: reusable first-target selection, provider classification, auth mode, and failure-mode decisions.
- `dam-diagnostics`: shared local readiness checks for `damctl doctor` and `dam-web /doctor`.
- `dam-daemon`: background local proxy lifecycle and state file for `dam connect/status/disconnect`.
- `dam-integrations`: known local harness profiles for `dam integrations` and `dam connect --profile`.

Near-term product slices still to build:

- broader integration profile apply/install support with safe rollback where harness config files can be changed reliably.
- login/startup UX for the local daemon after profile apply is stable.

Backend replacement modules:

- `dam-vault-remote`: remote `VaultWriter` and `VaultReader` implementation using `vault.backend = "remote"`.
- `dam-log-remote`: remote `EventSink` implementation using `log.backend = "remote"`.

Parked modules:

- `dam-outbox`: durable queue for failed async remote vault/log writes.
- `dam-detect-pipeline`: orchestration for multiple detectors, including sequential, parallel, and nested detector suites.
- `dam-auth`: auth/token handling for remote vault/log/proxy deployments.
- `dam-net`: future VPN/TUN/network-extension layer for selected or full-device routing.
- `dam-trust`: future TLS interception/local CA management, if validated later.
- `dam-websocket`: future WebSocket adapter after HTTP and SSE paths are stable. Needed before `dam codex` can protect Codex's ChatGPT-login `backend-api/codex/responses` transport.
- `dam-notify`: notification module for user-visible attention events, for example consent requests or critical errors.

## Build

```bash
cargo fmt --all --check
cargo clippy --workspace -- -D warnings
cargo test --workspace
npm pack --dry-run
```

## License

Apache-2.0.
