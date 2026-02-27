<div align="center">
  <h1>DAM</h1>
  <h3>Data Access Mediator</h3>
  <p><strong>The PII firewall for AI agents.</strong></p>
  <p>Your data never leaves your machine. The LLM never sees it. Every access is logged.</p>
</div>

<p align="center">
  <a href="https://github.com/RPBLC-hq/RPBLC.DAM/actions/workflows/ci.yml"><img src="https://github.com/RPBLC-hq/RPBLC.DAM/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://opensource.org/licenses/Apache-2.0"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License: Apache-2.0"></a>
  <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/rust-1.88%2B-orange.svg" alt="Rust 1.88+"></a>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> &middot;
  <a href="#how-it-works">How It Works</a> &middot;
  <a href="#integration">Integration</a> &middot;
  <a href="docs/">Docs</a>
</p>

---

Every time an AI agent processes a customer email, a phone number, or an SSN, that data flows through third-party servers, training pipelines, and context windows you don't control. Most enterprises have responded by restricting or outright banning LLM usage. That's a reasonable reaction, but it's also expensive.

**DAM** is a different approach. It sits between your application and the LLM provider as a local proxy, intercepts personal data before it leaves your machine, and replaces it with typed references like `[email:a3f71bc9]`. Originals stay encrypted in a local vault. When the LLM responds with references, DAM resolves them back to real values — so the user sees the original data but the LLM never does.

The LLM reasons about data types. It never touches data values.

## Who Is This For?

**Developers building AI agents** — if your agent handles customer emails, phone numbers, or payment info, DAM ensures none of it reaches the LLM. Drop in a local proxy, keep your existing code.

**Security and compliance teams** — evaluating LLM deployments for SOC 2, GDPR, or HIPAA? DAM provides AES-256 encryption, granular consent controls, and a tamper-evident audit trail you can point auditors at.

**Solo developers** — want PII protection without signing up for a cloud vendor? One binary, zero dependencies, runs entirely on your machine.

```
  "Send the contract to john@acme.com        "Send the contract to [email:a3f71bc9]
   and CC sarah@corp.io,                       and CC [email:d4f82c19],
   charge card 4111-1111-1111-1111"  ──DAM──►  charge card [cc:b7e31a02]"

        What the user types                       What the LLM sees
```

## How It Works

```
                 YOUR MACHINE                            CLOUD
  ┌─────────────────────────────────────────┐    ┌──────────────────┐
  │                                         │    │                  │
  │  ┌───────────┐      ┌──────────────┐    │    │                  │
  │  │ User /    │      │  DAM         │    │    │    LLM           │
  │  │ App       │─────►│  Proxy       │────┼───►│    Provider      │
  │  │           │      │              │    │    │                  │
  │  │ "john@    │      │  1. Detect   │    │    │  Only sees:      │
  │  │  acme.com │      │  2. Encrypt  │    │    │  [email:a3f71bc9]│
  │  │  at 555-  │      │  3. Replace  │    │    │                  │
  │  │  1234"    │      └──────┬───────┘    │    └────────┬─────────┘
  │  │           │             │            │             │
  │  │           │      ┌──────▼───────┐    │    ┌────────▼─────────┐
  │  │  sees     │      │  Encrypted   │    │    │ LLM responds     │
  │  │  real     │      │  Vault       │    │    │ with references: │
  │  │  values   │◄─────│  (SQLite +   │◄───┼────┤                  │
  │  │           │      │   AES-256)   │    │    │ "Send to         │
  │  └───────────┘      └──────┬───────┘    │    │ [email:a3f71bc9]"│
  │                            │            │    └──────────────────┘
  │                     ┌──────▼───────┐    │
  │                     │ Consent +    │    │     Only resolved with
  │                     │ Audit Log    │    │     explicit consent
  │                     │ (hash chain) │    │
  │                     └──────────────┘    │
  │                                         │
  └─────────────────────────────────────────┘
         Everything stays here.
```

No code changes needed. Point your API client at DAM instead of the provider, and PII is intercepted automatically.

### The pipeline

| Stage | What happens |
|-------|-------------|
| **Detect** | Regex pipeline with 37 built-in types — credentials (JWT, AWS, GitHub, Stripe, API keys, private keys), personal data (email, SSN, phone, NHS, passport), financial (credit card, IBAN, crypto), and more across 7 locales |
| **Encrypt** | Each value gets its own AES-256-GCM key (envelope encryption). The master key lives in your OS keychain — never on disk |
| **Replace** | Values become typed references: `[email:a3f71bc9]`. The LLM knows the *type* but never the *value* |
| **Resolve** | When the LLM responds with references, DAM replaces them with real values before returning to the client. The user sees real data; the LLM never did |
| **Audit** | Every operation is logged in a SHA-256 hash-chained trail. Tampered rows are detectable. Full compliance visibility |

## Quick Start

### Install

**npm** (recommended — prebuilt binaries, no compiler needed):

```bash
npm install -g @rpblc/dam
```

**From source** (requires Rust 1.88+):

```bash
git clone https://github.com/alexyboyer/RPBLC.DAM.git
cd RPBLC.DAM
cargo install --path crates/dam-cli
```

Single binary. ~6 MB. No runtime dependencies.

### Start the proxy

```bash
dam serve                                           # listen on 127.0.0.1:7828
export OPENAI_BASE_URL=http://127.0.0.1:7828/v1     # OpenAI, OpenRouter, xAI, etc.
export ANTHROPIC_BASE_URL=http://127.0.0.1:7828      # Anthropic
```

That's it — no `dam init` needed. On first run, DAM auto-creates config, vault, and encryption keys. All messages now flow through DAM. User messages are scanned and redacted before reaching the LLM. Responses are resolved back to real values before reaching you.

### Run as a background service

```bash
dam daemon install       # register as OS service + start + verify health
```

DAM will auto-start on login and restart on crash. See `dam daemon --help` for `start`, `stop`, `status`, and `uninstall`.

### Customize (optional)

```bash
dam init                 # interactive setup: select locales, review config
```

> **Multiple providers?** If you use providers that share the same API format (e.g. xAI and OpenAI both use `/v1/chat/completions`), add the `X-DAM-Upstream` header to route per-request. See [Upstream Routing](#upstream-routing) below.

### Try it with curl

```bash
# OpenAI
curl http://127.0.0.1:7828/v1/chat/completions \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -H "content-type: application/json" \
  -d '{
    "model": "gpt-4o",
    "messages": [{"role": "user", "content": "Email john@acme.com about the meeting"}]
  }'

# Anthropic
curl http://127.0.0.1:7828/v1/messages \
  -H "x-api-key: $ANTHROPIC_API_KEY" \
  -H "anthropic-version: 2023-06-01" \
  -H "content-type: application/json" \
  -d '{
    "model": "claude-sonnet-4-5-20250514",
    "max_tokens": 1024,
    "messages": [{"role": "user", "content": "Email john@acme.com about the meeting"}]
  }'
# The LLM sees: "Email [email:a3f71bc9] about the meeting"
# You see the response with real values restored
```

### Scan text manually

```bash
dam scan "Email john@acme.com, SSN 123-45-6789"
```

```
Redacted text:
Email [email:a3f71bc9], SSN [ssn:b2c81e4f]

Detections (2):
  [email:a3f71bc9] -> email (confidence: 95%)
  [ssn:b2c81e4f]   -> ssn   (confidence: 98%)
```

Works with stdin too:

```bash
echo "Call 555-867-5309" | dam scan
```

### Manage the vault

```bash
dam vault list                    # all entries (metadata only)
dam vault list --type email       # filter by type
dam vault show email:a3f71bc9     # decrypt and display
dam vault delete email:a3f71bc9   # remove permanently
```

### Control consent

```bash
dam consent grant email:a3f71bc9 claude send_email --ttl 1h   # specific, 1 hour
dam consent grant email:a3f71bc9 "*" "*" --ttl 24h            # blanket, 24 hours
dam consent revoke email:a3f71bc9 claude send_email   # revoke
dam consent list                                      # view all rules
```

### Audit

```bash
dam audit                          # last 50 entries
dam audit --ref email:a3f71bc9     # filter by reference
```

## Integration

Use DAM primarily as an HTTP proxy (`dam serve`) for the strongest boundary.

### Routes and defaults

| Route | Format | Default upstream |
|-------|--------|-----------------|
| `POST /v1/messages` | Anthropic Messages | `https://api.anthropic.com` |
| `POST /v1/chat/completions` | OpenAI Chat | `https://api.openai.com` |
| `POST /v1/responses` | OpenAI Responses | `https://api.openai.com` |
| `POST /codex/responses` | Codex | `https://chatgpt.com/backend-api` |

Also exposed for ops:
- `GET /healthz`
- `GET /readyz`

### Automation-first CLI

For agent/CI use, prefer non-interactive commands with `--json` where available.
Roadmap: [`docs/cli-roadmap.md`](docs/cli-roadmap.md).

### Advanced docs

- Proxy data-flow walkthrough: [`docs/proxy-walkthrough.md`](docs/proxy-walkthrough.md)
- Detailed client integrations: [`docs/integrations.md`](docs/integrations.md)
- Upstream routing (`X-DAM-Upstream`): [`docs/routing.md`](docs/routing.md)
- Security model details: [`docs/security-model.md`](docs/security-model.md)
- Troubleshooting: [`docs/troubleshooting.md`](docs/troubleshooting.md)

## Security Model

### Encryption

- **Envelope encryption** — each PII value encrypted with its own DEK (AES-256-GCM), DEK wrapped by a KEK stored in your OS keychain
- KEK never written to disk. DEKs zeroized from memory after use
- Same value + same type = same reference (deduplication without storing duplicates)

### Consent

- **Default-denied** — no tool can resolve PII without explicit consent
- **Time-limited** — all consent grants require a TTL (`30m`, `1h`, `24h`, `7d`); no infinite consent
- Granular: per-reference, per-accessor, per-purpose
- Wildcards supported for convenience (`"*"`)
- `dam_reveal` bypasses consent for emergencies — but always logs a reason

### Audit trail

- Every scan, resolve, reveal, consent change is logged
- SHA-256 hash chain: each entry includes the hash of the previous entry
- Tampered or deleted rows are detectable via chain verification
- Full compliance visibility for SOC 2, GDPR, HIPAA audit requirements

## PII Detection

### Commonly detected types

A sample of the most commonly leaked or highest-impact types:

| Type | Tag | Example | Why it matters |
|------|-----|---------|----------------|
| Email | `email` | `user@example.com` | Universal — appears in nearly every prompt |
| Credit Card | `cc` | `4111-1111-1111-1111` | Payment fraud; Luhn-validated |
| SSN | `ssn` | `123-45-6789` | US identity theft; highest regulatory risk |
| JWT Token | `jwt` | `eyJhbGci…` | Auth credential; grants account access |
| AWS Key | `aws_key` | `AKIAIOSFODNN7EXAMPLE` | Cloud credential; immediate infrastructure access |
| Private Key | `priv_key` | `-----BEGIN RSA PRIVATE KEY-----` | Cryptographic identity; highest severity |
| Credential URL | `cred_url` | `postgres://user:pass@host/db` | Database access embedded in connection strings |
| Stripe Key | `stripe_key` | `sk_live_…` | Payment processor; direct financial access |
| NHS Number | `nhs` | `943 476 5919` | UK health identifier; GDPR/DSP Toolkit |
| Crypto Wallet | `wallet` | `0x742d35Cc6634C053…` | Irreversible financial transactions |

**37 built-in types** across personal data, credentials, financial, national IDs, network, and documents — see [docs/pii-types.md](docs/pii-types.md) for the full reference.

Plus user-defined regex patterns via config. See [Configuration](#configuration).

### Reference format

```
[email:a3f71bc9]    — an email address
[phone:c2d81e4f]    — a phone number
[ssn:b7e31a02]      — a social security number
[cc:d4f82c19]       — a credit card number
```

- **Type tag**: lowercase identifier from the table above
- **Hex ID**: 8-character random hex (4-16 chars accepted)
- Same value + same type = same reference (deduplication)

## Configuration

Config location: `~/.dam/config.toml`

```toml
[vault]
path = "~/.dam/vault.db"
key_source = "os_keychain"    # "os_keychain" | "passphrase" | { env_var = { name = "DAM_KEK" } }

[detection]
sensitivity = "standard"      # "standard" | "elevated" | "maximum"
locales = ["global", "us"]    # which regional patterns to enable
excluded_types = []           # e.g. ["ip", "phone"]
whitelist = []                # terms to never flag

[server]
http_port = 7828
consent_passthrough = false  # strict default: keep PII redacted upstream
# anthropic_upstream_url = "https://api.anthropic.com"
# openai_upstream_url = "https://api.openai.com"
# codex_upstream_url = "https://chatgpt.com/backend-api"
```

### Key sources

| Source | Description |
|--------|-------------|
| `os_keychain` | KEK in OS keychain (DPAPI / Keychain / libsecret). Default. |
| `passphrase` | KEK derived from passphrase via Argon2id. Prompts every time. |
| `env_var` | KEK from environment variable. For CI/CD and containerized deployments. |

### Sensitivity levels

| Level | Detects |
|-------|---------|
| `standard` | Structured PII: email, phone, SSN, credit card, IP, IBAN |
| `elevated` | + names, dates, organizations, locations |
| `maximum` | + any noun phrase matching vault history |

### Custom rules

```toml
[detection.custom_rules.employee_id]
pattern = "EMP-\\d{6}"
pii_type = "custom"
description = "Internal employee ID"
```

## CLI Reference

Global automation flags (where supported): `--json`, `--verbose`.

```
dam init                                           Initialize vault, config, and KEK
dam serve [--port PORT]                            Start HTTP proxy (default: 7828)
          [--anthropic-upstream URL]
          [--openai-upstream URL]
          [--codex-upstream URL]
dam daemon install [--port PORT]                   Register + start as OS service
dam daemon uninstall                               Stop + remove service
dam daemon start                                   Start registered service
dam daemon stop                                    Stop running service
dam daemon status                                  Show service status
dam status [--json]                                Show local config + vault status
dam health [--port PORT] [--json]                  Probe /healthz and /readyz
dam mcp                                            Start MCP server (stdio)
dam scan [TEXT]                                    Scan text for PII (stdin if omitted)
dam vault list [--type TYPE]                       List vault entries
dam vault show REF                                 Decrypt and display entry
dam vault delete REF                               Delete entry
dam vault clear                                    Delete ALL entries (with confirmation)
dam consent list [--ref REF_ID]                    List consent rules
dam consent grant REF_ID ACCESSOR PURPOSE --ttl D  Grant consent (30m, 1h, 24h, 7d)
dam consent revoke REF_ID ACCESSOR PURPOSE         Revoke consent
dam audit [--ref REF_ID] [--limit N]               View audit trail (default: 50)
dam config show                                    Display current configuration
dam config validate [--json]                       Validate config + key paths
dam config get KEY                                 Get a config value
dam config set KEY VALUE                           Update a config value
```

## Architecture

7 focused crates, single binary output:

```
dam-core       Types, reference format, config, errors
dam-vault      Encrypted SQLite storage, envelope crypto, keychain, consent, audit
dam-detect     PII detection pipeline (regex + locale patterns + user rules)
dam-resolve    Outbound resolution with consent checking and audit
dam-mcp        MCP server — 7 tools over stdio transport
dam-http       HTTP proxy — streaming SSE, Anthropic + OpenAI + Responses + Codex
dam-cli        CLI binary — wires everything together
```

### Build from source

```bash
cargo build --release            # single ~6MB binary
cargo test --workspace           # 640+ tests
cargo clippy --workspace         # lint
cargo fmt --check                # format check
```

## Roadmap

- [ ] NER-based detection (names, addresses, organizations)
- [ ] Vault cross-reference (flag values similar to known PII)
- [ ] Derived operations (compare, compute on encrypted values)
- [ ] Additional provider formats (Google Gemini, etc.)
- [ ] Web dashboard for vault and consent management
- [ ] Team/org vault with shared consent policies

## License

Apache-2.0 — see [LICENSE](LICENSE) for details.
