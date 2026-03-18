<div align="center">
  <h1>DAM</h1>
  <h3>Data Access Mediator</h3>
  <p><strong>Your AI is leaking sensitive data. Fix it in 60 seconds.</strong></p>
</div>

<p align="center">
  <a href="https://opensource.org/licenses/Apache-2.0"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License: Apache-2.0"></a>
  <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/rust-1.94%2B-orange.svg" alt="Rust 1.94+"></a>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> &middot;
  <a href="#how-it-works">How It Works</a> &middot;
  <a href="#what-it-detects">Detection</a> &middot;
  <a href="#cli">CLI</a>
</p>

---

```
"Send the contract to john@acme.com      "Send the contract to [email:7B2HkqFn9xR4mWpD3nYvKt]
 and CC sarah@corp.io,                    and CC [email:4fWzR3qN7vJ8xK2hLbYdRv],
 charge card 4111-1111-1111-1111"         charge card [cc:HnT5wQ8mK2hLbYdRv3qN7vJ]"
                                  ──dam──►
        What you type                            What the LLM sees
```

DAM sits between your app and the LLM provider. It detects sensitive data in outbound requests, tokenizes it (stores encrypted originals locally), and forwards clean requests upstream. The LLM reasons about data types. It never touches data values.

One binary. Zero config. Zero dependencies. Plug and play.

## Quick Start

### Install

```bash
# Coming soon
brew install dam
npx dam
curl -fsSL https://get.dam.dev | sh

# Available now (requires Rust 1.94+)
cargo install --path dam-cli
```

### Run

```bash
dam
```

```
DAM running on :7828
```

### Use

Point your LLM client at DAM:

```bash
curl -H "X-DAM-Upstream: https://api.anthropic.com/v1/messages" \
     -H "x-api-key: $ANTHROPIC_API_KEY" \
     -H "content-type: application/json" \
     -d '{
       "model": "claude-sonnet-4-20250514",
       "max_tokens": 1024,
       "messages": [{"role": "user", "content": "Email john@acme.com about the meeting, SSN 123-45-6789"}]
     }' \
     http://localhost:7828/
```

The LLM sees: `"Email [email:7B2HkqFn9xR4mWpD3nYvKt] about the meeting, SSN [ssn:9cXJrNpT5wQ8mK2hLbYdRv]"`

The originals are encrypted in your local vault. The LLM responds with tokens — you resolve them when you need the real values:

```bash
dam resolve email:7B2HkqFn9xR4mWpD3nYvKt    # → john@acme.com
dam tokens                                     # list everything in the vault
dam stats                                      # see what was detected and where
```

## How It Works

```
             YOUR MACHINE                              CLOUD
┌──────────────────────────────────────────┐   ┌──────────────────┐
│                                          │   │                  │
│  ┌─────────┐      ┌───────────────────┐  │   │                  │
│  │ Your    │      │       dam         │  │   │    LLM           │
│  │ App     │─────►│                   │──┼──►│    Provider      │
│  │         │      │  detect-pii       │  │   │                  │
│  │         │      │  detect-secrets   │  │   │  Only sees:      │
│  │         │      │  vault (tokenize) │  │   │  [email:7B2Hkq...]│
│  │         │      │  log (record)     │  │   │  [ssn:9cXJrN...]  │
│  └─────────┘      └────────┬──────────┘  │   └──────────────────┘
│                            │             │
│                     ┌──────▼──────────┐  │
│                     │  Encrypted      │  │
│                     │  Vault          │  │
│                     │  (SQLite +      │  │
│                     │   AES-256-GCM)  │  │
│                     └─────────────────┘  │
│                                          │
│  Everything stays on your machine.       │
└──────────────────────────────────────────┘
```

### The pipeline

Traffic flows through a chain of modules:

| Module | What it does |
|--------|-------------|
| **detect-pii** | Finds PII: email, phone, SSN, credit card, IBAN, IP address. Regex + validators (Luhn, Mod97, SSN area rules). Text normalization catches zero-width chars, unicode dashes, URL-encoded values. |
| **detect-secrets** | Finds credentials: API keys (AWS, GitHub, Stripe, OpenAI, Anthropic), JWTs, PEM private keys, credential URLs. |
| **vault** | Tokenizes detections: encrypts originals (AES-256-GCM envelope encryption), stores in local SQLite, replaces with `[type:base58id]` tokens. Only activates for LLM API calls. |
| **log** | Records every detection: what type, where it was going, what action was taken. Never logs the actual sensitive value. |

### Zero config

On first run, DAM auto-creates:
- `~/.dam/key` — 32-byte encryption key (file permissions 0600)
- `~/.dam/dam.db` — encrypted vault (SQLite)
- `~/.dam/log.db` — detection log (SQLite)

No init command. No config file. No keychain setup. Just `dam`.

## What It Detects

### PII (detect-pii)

| Type | Tag | Example | Validation |
|------|-----|---------|------------|
| Email | `email` | `user@example.com` | Format |
| Phone | `phone` | `+14155551234` | E.164 + NANP, 7-15 digits |
| SSN | `ssn` | `123-45-6789` | Area rules (000/666/900+ rejected) |
| Credit Card | `cc` | `4111111111111111` | Luhn checksum |
| IBAN | `iban` | `DE89370400440532013000` | Mod97 |
| IP Address | `ip` | `203.0.113.42` | Private ranges rejected |

### Secrets (detect-secrets)

| Type | Tag | Example |
|------|-----|---------|
| JWT Token | `jwt` | `eyJhbGciOiJIUzI1NiIs...` |
| AWS Key | `aws_key` | `AKIAIOSFODNN7EXAMPLE` |
| GitHub Token | `gh_token` | `ghp_xxxxxxxxxxxxxxxxxxxx` |
| Stripe Key | `stripe_key` | `sk_live_xxxxxxxxxxxxxxxx` |
| OpenAI Key | `llm_key` | `sk-xxxxxxxxxxxxxxxx` |
| Anthropic Key | `llm_key` | `sk-ant-xxxxxxxxxxxxxxxx` |
| Private Key | `priv_key` | `-----BEGIN RSA PRIVATE KEY-----` |
| Credential URL | `cred_url` | `postgres://user:pass@host/db` |

### Token format

```
[email:7B2HkqFn9xR4mWpD3nYvKt]    — an email address
[phone:9cXJrNpT5wQ8mK2hLbYdRv]    — a phone number
[ssn:4fWzR3qN7vJ8mK2hLbYdRv]      — a social security number
[cc:HnT5wQ8mK2hLbYdRv3qN7vJ]      — a credit card number
```

Each ID is a 128-bit UUID encoded in base58 (22 chars). Base58 excludes `0`, `O`, `I`, `l` to avoid visual ambiguity in logs and debugging output. Same value + same type = same token (dedup).

## CLI

```
dam                         Start proxy on :7828
dam --port 8080             Custom port
dam -v                      Verbose output
dam stats                   Detection counts by type and destination
dam resolve <token>         Resolve a token to its original value
dam tokens                  List all tokens in the vault
dam log [-n 50]             Show recent detection events
```

### Proxy routing

Set the `X-DAM-Upstream` header to tell DAM where to forward:

```bash
# Anthropic
curl -H "X-DAM-Upstream: https://api.anthropic.com/v1/messages" ...

# OpenAI
curl -H "X-DAM-Upstream: https://api.openai.com/v1/chat/completions" ...

# Any HTTP endpoint
curl -H "X-DAM-Upstream: https://your-api.com/endpoint" ...
```

Or use path-based routing:

```bash
curl http://localhost:7828/https://api.openai.com/v1/chat/completions ...
```

LLM endpoints are auto-detected by host. LLM calls get tokenized. Everything else gets logged (detection only, no modification).

## Security

- **Envelope encryption** — each value gets its own DEK (AES-256-GCM), wrapped by a master key
- **Auto-generated key** — 32 random bytes at `~/.dam/key`, file permissions 0600, no OS keychain
- **Deduplication** — same value + type stored once via normalized SHA-256 hash
- **Separate databases** — vault entries and detection logs in different SQLite files
- **Zero plaintext at rest** — sensitive values only exist decrypted in memory during processing

## Architecture

6 crates, single binary:

```
dam-core             Spine — proxy, Module trait, flow executor, streaming
dam-detect-pii       Vertebra — PII detection patterns + validators
dam-detect-secrets   Vertebra — secrets/credentials detection
dam-vault            Vertebra — tokenize, encrypt, store, resolve
dam-log              Vertebra — detection event logging, stats
dam-cli              Binary — wires spine + vertebrae, CLI
```

Modules implement a shared `Module` trait. The spine knows nothing about detection or storage — it just runs traffic through a configurable chain of modules.

### Build from source

```bash
cargo build --workspace          # debug build
cargo test --workspace           # 318 tests
cargo build --release -p dam-cli # release binary
```

## Roadmap

- [ ] MCP server for AI agent integration (resolve tokens, list vault, grant passthrough)
- [ ] Auto-resolve: optionally resolve tokens in LLM responses before returning to client
- [ ] Consent model: control which tokens get resolved, by whom, for what purpose
- [ ] WASM module system (`dam install author/module@version`)
- [ ] Config file for custom detection rules and module flows
- [ ] Analytics dashboard
- [ ] Remote vault (Postgres)
- [ ] Full traffic interception (corporate network deployment)
- [ ] Module marketplace

## License

Apache-2.0 — see [LICENSE](LICENSE) for details.
