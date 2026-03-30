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
  <a href="#session-scrubbing">Session Scrubbing</a> &middot;
  <a href="#consent">Consent</a> &middot;
  <a href="#detection">Detection</a> &middot;
  <a href="#cli">CLI</a>
</p>

---

Every time an AI agent processes a customer email, a phone number, or an API key, that data flows through servers and context windows you don't control.

**DAM** sits between your app and the LLM provider. It detects sensitive data, checks your consent rules, tokenizes what you haven't approved, stores encrypted originals locally, and forwards clean requests upstream. The LLM reasons about data types. It never touches data values.

```
  "Send the contract to john@acme.com        "Send the contract to [email:a3f71b]
   and CC sarah@corp.io,                      and CC [email:d4f82c],
   charge card 4111-1111-1111-1111"  ──dam──► charge card [cc:b7e31a]"

        What you type                             What the LLM sees
```

Single binary. Zero config. Plug and play.

## Quick Start

### Install

```bash
# Coming soon
brew install dam
npx dam
curl -fsSL https://get.dam.dev | sh

# Available now
npm install -g @rpblc/dam
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

The LLM sees: `"Email [email:a3f71b] about the meeting, SSN [ssn:b2c81e]"`

The originals are encrypted in your local vault. You decide what gets through:

```bash
dam resolve email:a3f71b     # → john@acme.com
dam consent grant --type email --dest api.anthropic.com   # let emails pass to Anthropic
dam tokens                   # list everything in the vault
dam stats                    # see what was detected and where
```

## How It Works

```
                 YOUR MACHINE                            CLOUD
  ┌─────────────────────────────────────────┐    ┌──────────────────┐
  │                                         │    │                  │
  │  ┌───────────┐      ┌──────────────┐    │    │    LLM           │
  │  │ User /    │      │     DAM      │    │    │    Provider      │
  │  │ App       │─────►│              │────┼───►│                  │
  │  │           │      │  1. Detect   │    │    │  Only sees:      │
  │  │ "john@    │      │  2. Consent  │    │    │  [email:a3f71b]  │
  │  │  acme.com │      │  3. Vault    │    │    │                  │
  │  │  at 555-  │      │  4. Redact   │    │    │  Responds with:  │
  │  │  1234"    │      │  5. Log      │    │    │  "Send to        │
  │  │           │      │              │◄───┼────│  [email:a3f71b]" │
  │  │  sees     │◄─────│  Response    │    │    │                  │
  │  │  tokens   │      │  passthrough │    │    └──────────────────┘
  │  └───────────┘      └──────┬───────┘    │
  │       │                    │            │
  │       │              ┌─────▼────────┐   │
  │       └─────────────►│  Vault       │   │     User resolves tokens
  │        dam resolve   │  (AES-256)   │   │     via CLI or MCP
  │        dam consent   │  Consent DB  │   │     when needed
  │                      └──────────────┘   │
  │                                         │
  │      Everything stays on your machine.  │
  └─────────────────────────────────────────┘
```

### The pipeline

Traffic flows through a chain of modules. Each module reads from and appends to a shared context. Modules never remove data — they only add detections, set verdicts, store values, or modify the outbound body.

```
detect-pii ──┐
              ├──► consent ──► vault ──► redact ──► log
detect-secrets┘
```

| Module | Type | What it does |
|--------|------|-------------|
| **detect-pii** | Detection | Finds PII: email, phone, SSN, credit card, IBAN, IP. Appends detections to the shared context. |
| **detect-secrets** | Detection | Finds secrets: API keys, JWTs, private keys, credential URLs. Appends detections. |
| **consent** | Filter | Checks each detection against your consent rules. Sets verdict: `pass` (let through) or `redact` (tokenize). Default: redact everything. |
| **vault** | Storage | Stores ALL detected values encrypted — both passed and redacted — for audit and recovery. |
| **redact** | Action | Replaces values in the request body with `[type:id]` tokens — only for detections with verdict `redact`. Passed values stay as-is. |
| **log** | Action | Records every detection: type, destination, verdict, action taken. Never logs the actual value. |

### Zero config

On first run, DAM auto-creates:
- `~/.dam/key` — 32-byte encryption key (file permissions 0600)
- `~/.dam/dam.db` — encrypted vault (SQLite)
- `~/.dam/consent.db` — consent rules (SQLite)
- `~/.dam/log.db` — detection log (SQLite)

No init command. No config file. No keychain setup. Just `dam`.

## Session Scrubbing

DAM ships a second binary — `dam-filter` — for stripping PII and secrets from any text or JSON. Clean coding sessions before sharing, sanitize logs, scrub database exports. Same detection engine, no proxy required.

```bash
# Pipe a session through dam-filter
cat session.json | dam-filter > clean.json
```

```
  Input:  {"role": "user", "content": "My key is sk-ant-api03-abc... email john@acme.com"}
  Output: {"role": "user", "content": "My key is [DAM:LLM_KEY] email [DAM:EMAIL]"}
```

The `[DAM:TYPE]` placeholders are permanent — originals are destroyed, not stored.

```bash
# Works with extraction tools
ai-data-extract dump --format json | dam-filter > clean-session.json

# See what was found
dam-filter session.json --report > clean.json 2>report.txt
```

`dam-filter` reads JSON or plain text from stdin or a file. JSON mode walks the structure and independently filters every string value, preserving the document shape.

## Consent

By default, DAM redacts everything in LLM calls. You control what passes through with consent rules.

### Grant consent

```bash
# Let emails pass to Anthropic (24h default TTL)
dam consent grant --type email --dest api.anthropic.com

# Let emails pass everywhere, permanently
dam consent grant --type email --dest "*" --ttl permanent

# Let a specific token pass (use brackets or key format)
dam consent grant --token [email:a3f71b] --dest "*" --ttl 30m

# Let a specific value pass (resolves from vault)
dam consent grant --value "john@acme.com" --dest api.anthropic.com

# Let everything pass to Anthropic
dam consent grant --type "*" --dest api.anthropic.com
```

### Deny (explicit block)

```bash
# Never let SSNs pass anywhere, even if a broader rule allows it
dam consent deny --type ssn --dest "*"

# Block a specific token
dam consent deny --token [cc:b7e31a] --dest "*"
```

### Manage rules

```bash
dam consent list              # show all active rules
dam consent revoke <rule-id>  # remove a rule
```

### How consent works

Rules are layered. Most specific match wins:

1. **Token + exact destination** — highest priority
2. **Token + wildcard destination**
3. **Type + exact destination**
4. **Type + wildcard destination**
5. **Wildcard type + exact destination**
6. **Wildcard type + wildcard destination**
7. **No match → redact** (default deny)

TTL defaults to 24 hours. Use `--ttl permanent` to override. Use `--ttl 30m`, `--ttl 1h`, `--ttl 7d` for custom durations.

## Detection

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
[email:a3f71b]     — an email address
[phone:c2d81e]     — a phone number
[ssn:b7e31a]       — a social security number
[cc:d4f82c]        — a credit card number
[aws_key:e5a93b]   — an AWS access key
```

Each ID is a 128-bit UUID encoded in base58 (22 chars in practice). Base58 excludes `0`, `O`, `I`, `l` to avoid visual ambiguity. Same value + same type = same token (dedup). IDs in this README are shortened for readability.

## CLI

Commands are grouped by module.

### Proxy

```
dam                          Start proxy on :7828
dam --port 8080              Custom port
dam -v                       Verbose output
```

### Consent (dam-consent)

```
dam consent grant [OPTIONS]  Grant consent — allow data to pass
dam consent deny [OPTIONS]   Deny — explicitly block data
dam consent list             List all active rules
dam consent revoke <id>      Remove a rule
```

### Vault (dam-vault)

```
dam resolve <token>          Resolve a token to its original value
dam tokens                   List all tokens in the vault
```

### Log (dam-log)

```
dam stats                    Detection counts by type and destination
dam log [-n 50]              Show recent detection events
```

### Proxy routing

```bash
# Route via header
curl -H "X-DAM-Upstream: https://api.anthropic.com/v1/messages" ... http://localhost:7828/

# Route via path
curl ... http://localhost:7828/https://api.openai.com/v1/chat/completions
```

LLM endpoints are auto-detected by host. LLM calls get the full pipeline (detect → consent → vault → redact → log). Non-LLM traffic gets detect + vault + log (stored and logged, but not redacted).

## Security

- **Envelope encryption** — each value gets its own DEK (AES-256-GCM), wrapped by a master key
- **Auto-generated key** — 32 random bytes at `~/.dam/key`, file permissions 0600, no OS keychain
- **Deduplication** — same value + type stored once via normalized SHA-256 hash
- **Separate databases** — vault, consent rules, and detection logs in different SQLite files
- **Zero plaintext at rest** — sensitive values only exist decrypted in memory during processing
- **Default deny** — no data passes through LLM calls without explicit consent

## Architecture

9 crates, two binaries:

```
dam-core             Spine — proxy, Module trait, FlowExecutor, streaming, config
dam-detect-pii       Vertebra — PII detection patterns + validators
dam-detect-secrets   Vertebra — secrets/credentials detection
dam-consent          Vertebra — consent rules, verdict assignment
dam-vault            Vertebra — encrypt and store all detected values
dam-redact           Vertebra — replace body text for redacted detections
dam-log              Vertebra — detection event logging, stats
dam-cli              Binary — full proxy + vault + consent + MCP
dam-filter           Binary — standalone PII/secret filter (no proxy, no vault)
```

### The module contract

Every module implements the same trait. Modules read from and append to a shared `FlowContext`. The `Detection` struct carries a `Verdict` field that flows through the pipeline:

```rust
pub enum Verdict { Pending, Redact, Pass }

pub struct Detection {
    pub data_type: SensitiveDataType,
    pub value: String,
    pub span: Span,
    pub confidence: f32,
    pub source_module: String,
    pub verdict: Verdict,
}
```

Detection modules set `verdict: Pending`. The consent module sets it to `Pass` or `Redact`. Action modules read the verdict to decide what to do.

### Build from source

```bash
cargo build --workspace          # debug build
cargo test --workspace              # 418 tests
cargo build --release -p dam-cli    # release proxy binary
cargo build --release -p dam-filter # release filter binary
```

## Roadmap

**Done:**
- [x] PII detection (email, phone, SSN, credit card, IBAN, IP)
- [x] Secrets detection (API keys, JWTs, private keys, credential URLs)
- [x] Consent model (layered rules, per-type/per-token, TTL, default deny)
- [x] Encrypted vault (AES-256-GCM, auto-generated key, dedup)
- [x] HTTPS proxy (CONNECT + selective TLS interception)
- [x] Streaming (SSE, WebSocket, zstd decompression)
- [x] CLI (consent grant/deny/list/revoke, resolve, tokens, stats, log)
- [x] MCP server (resolve tokens, grant/deny/revoke consent, list tokens, stats with pass/redact breakdown)
- [x] Verdict-aware logging (redacted vs passed vs logged)
- [x] Auto-resolve: tokens in LLM responses resolved back to original values before returning to client
- [x] Session scrubbing (`dam-filter` — strip PII/secrets from coding sessions, `[DAM:TYPE]` branded placeholders)
- [x] JSON-aware scanning (user/assistant content only, skips system prompts and tool definitions)

**Next:**
- [ ] Config TOML modules (custom detection rules, drop in `~/.dam/modules/`)
- [ ] Configurable trust levels per accessor (auto-approve vs require human approval)
- [ ] Notification system for consent requests (agent requests, human approves)
- [ ] WASM module system (`dam install author/module@version`)
- [ ] Process modules (external binaries for ML/GPU detection)
- [ ] Analytics dashboard
- [ ] Remote vault (Postgres)
- [ ] Full traffic interception (corporate network deployment)
- [ ] Module marketplace

## License

Apache-2.0 — see [LICENSE](LICENSE) for details.
