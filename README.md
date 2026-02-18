<p align="center">
  <h1 align="center">DAM</h1>
  <p align="center"><strong>The PII firewall for AI agents.</strong></p>
  <p align="center">
    Your data never leaves your machine. The LLM never sees it. Every access is logged.
  </p>
</p>

<p align="center">
  <a href="https://github.com/alexyboyer/RPBLC.DAM/actions/workflows/ci.yml"><img src="https://github.com/alexyboyer/RPBLC.DAM/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://codecov.io/gh/alexyboyer/RPBLC.DAM"><img src="https://codecov.io/gh/alexyboyer/RPBLC.DAM/graph/badge.svg" alt="codecov"></a>
  <a href="https://opensource.org/licenses/Apache-2.0"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License: Apache-2.0"></a>
  <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/rust-1.85%2B-orange.svg" alt="Rust 1.85+"></a>
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
| **Detect** | Regex pipeline finds emails, phones, SSNs, credit cards, IPs, IBANs, and 15+ locale-specific patterns across US, Canada, UK, France, Germany, and the EU |
| **Encrypt** | Each value gets its own AES-256-GCM key (envelope encryption). The master key lives in your OS keychain — never on disk |
| **Replace** | Values become typed references: `[email:a3f71bc9]`. The LLM knows the *type* but never the *value* |
| **Resolve** | When the LLM responds with references, DAM replaces them with real values before returning to the client. The user sees real data; the LLM never did |
| **Audit** | Every operation is logged in a SHA-256 hash-chained trail. Tampered rows are detectable. Full compliance visibility |

## Quick Start

### Prerequisites

- [Rust](https://rustup.rs/) 1.85+ (edition 2024)
- A C compiler (for bundled SQLite)
  - **Windows**: MSVC via Visual Studio Build Tools
  - **macOS**: `xcode-select --install`
  - **Linux**: `build-essential`

### Install

```bash
git clone https://github.com/alexyboyer/RPBLC.DAM.git
cd RPBLC.DAM
cargo install --path crates/dam-cli
```

Single binary. ~6 MB. No runtime dependencies.

### Initialize

```bash
dam init
```

This creates your encrypted vault, config, and stores a 256-bit master key in your OS keychain. You'll select which regional PII patterns to enable (global patterns are always on).

### Start the proxy

```bash
dam serve                                         # listen on 127.0.0.1:7828
export ANTHROPIC_BASE_URL=http://127.0.0.1:7828   # point your client at it
```

That's it. All messages now flow through DAM. User messages are scanned and redacted before reaching the LLM. Responses are resolved back to real values before reaching you.

### Try it with curl

```bash
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
dam consent grant email:a3f71bc9 claude send_email    # specific
dam consent grant email:a3f71bc9 "*" "*"              # blanket
dam consent revoke email:a3f71bc9 claude send_email   # revoke
dam consent list                                      # view all rules
```

### Audit

```bash
dam audit                          # last 50 entries
dam audit --ref email:a3f71bc9     # filter by reference
```

## Integration

### HTTP Proxy (primary)

The proxy is the primary integration path. It provides a hard security boundary: PII is intercepted and redacted *before* the request leaves your machine, with no reliance on LLM behavior.

```bash
dam serve
```

The proxy:
- Intercepts `POST /v1/messages` requests
- Scans **user** messages for PII, replaces with vault references
- Forwards the redacted request to `https://api.anthropic.com`
- Resolves references in the response before returning to the client
- Handles both streaming (SSE) and non-streaming responses
- Passes through `x-api-key`, `authorization`, and `anthropic-version` headers

Works with `curl`, Python SDK, TypeScript SDK — anything that calls the Anthropic Messages API.

### MCP Server (supplementary agent tools)

DAM also speaks the [Model Context Protocol](https://modelcontextprotocol.io/) over stdio, exposing vault tools to AI agents.

**Important**: MCP tools are called *by* the LLM, which means the LLM has already seen the data in its context window by the time it calls a tool. MCP does **not** provide the same security boundary as the proxy. Use the proxy for PII interception; use MCP tools for supplementary operations like:

- Scanning data fetched from external sources (files, APIs) before forwarding it elsewhere
- Searching the vault for existing references
- Managing consent and checking vault status
- Resolving references when executing actions (consent-checked)

<details>
<summary><strong>Claude Code</strong> — <code>.mcp.json</code> in project root or <code>~/.claude/mcp.json</code></summary>

```json
{
  "mcpServers": {
    "dam": {
      "command": "dam",
      "args": ["mcp"]
    }
  }
}
```
</details>

<details>
<summary><strong>Codex</strong> — <code>~/.codex/config.toml</code></summary>

```toml
[mcp_servers.dam]
command = "dam"
args = ["mcp"]
```
</details>

<details>
<summary><strong>OpenClaw</strong> — <code>mcp_config.json</code></summary>

```json
{
  "mcpServers": {
    "dam": {
      "command": "dam",
      "args": ["mcp"]
    }
  }
}
```
</details>

### CLI (scripts and pipelines)

Every operation is available as a CLI command. See the [full reference](#cli-reference) below.

### Proxy vs. MCP: security comparison

| | HTTP Proxy | MCP Tools |
|---|---|---|
| PII reaches the LLM | No — intercepted before the request | Yes — LLM sees data before calling tools |
| Relies on LLM compliance | No — enforced at network layer | Yes — LLM must choose to call `dam_scan` |
| Automatic | Yes — transparent, no code changes | No — requires LLM to follow instructions |
| Best for | Primary PII protection | Vault operations, scanning external data, consent management |

## MCP Tools

When running as an MCP server, the agent receives these tools:

| Tool | Purpose |
|------|---------|
| `dam_scan` | Scan text for PII, return redacted version |
| `dam_resolve` | Resolve references for action execution (consent-checked) |
| `dam_consent` | Grant or revoke consent for a specific ref + accessor + purpose |
| `dam_vault_search` | Search vault by type — returns refs only, never values |
| `dam_status` | Vault stats: entry counts, recent activity |
| `dam_reveal` | Emergency override: reveal PII (bypasses consent, always audited) |
| `dam_compare` | Derived operations without revealing values (Phase 2) |

The server injects these instructions into the LLM context:

> ALWAYS use `dam_scan` on user input before processing. Work with references like `[email:a3f71bc9]`, never raw values. Use `dam_resolve` only when executing actions that need real data. If consent is denied, ask the user to grant it via `dam_consent`. Never reconstruct or guess PII from references.

## Security Model

### Encryption

- **Envelope encryption** — each PII value encrypted with its own DEK (AES-256-GCM), DEK wrapped by a KEK stored in your OS keychain
- KEK never written to disk. DEKs zeroized from memory after use
- Same value + same type = same reference (deduplication without storing duplicates)

### Consent

- **Default-denied** — no tool can resolve PII without explicit consent
- Granular: per-reference, per-accessor, per-purpose
- Wildcards supported for convenience (`"*"`)
- `dam_reveal` bypasses consent for emergencies — but always logs a reason

### Audit trail

- Every scan, resolve, reveal, consent change is logged
- SHA-256 hash chain: each entry includes the hash of the previous entry
- Tampered or deleted rows are detectable via chain verification
- Full compliance visibility for SOC 2, GDPR, HIPAA audit requirements

## PII Detection

### Supported types

| Type | Tag | Example | Locale |
|------|-----|---------|--------|
| Email | `email` | `user@example.com` | Global |
| Credit Card | `cc` | `4111-1111-1111-1111` (Luhn-validated) | Global |
| International Phone | `phone` | `+44 20 7946 0958` | Global |
| IPv4 Address | `ip` | `203.0.113.1` (public only) | Global |
| Date of Birth | `dob` | `1990-05-15` | Global |
| IBAN | `iban` | `DE89 3704 0044 0532 0130 00` | Global |
| SSN | `ssn` | `123-45-6789` | US |
| US Phone | `phone` | `(555) 867-5309` | US |
| SIN | `sin` | `130 692 544` | Canada |
| Postal Code | `postal` | `K1A 0B1` | Canada |
| NI Number | `ni` | `AB 123 456 C` | UK |
| NHS Number | `nhs` | `943 476 5919` | UK |
| Driving Licence | `dl` | `MORGA657054SM9IJ` | UK |
| INSEE/NIR | `nir` | `1 85 05 78 006 084 91` | France |
| Tax ID (Steuer-ID) | `taxid` | `65929970489` | Germany |
| National ID | `natid` | `T220001293` | Germany |
| VAT Number | `vat` | `DE123456789` | EU |
| SWIFT/BIC | `swift` | `DEUTDEFF` | EU |

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

```
dam init                                          Initialize vault, config, and KEK
dam serve [--port PORT]                           Start HTTP proxy (default: 7828)
dam mcp                                           Start MCP server (stdio)
dam scan [TEXT]                                    Scan text for PII (stdin if omitted)
dam vault list [--type TYPE]                       List vault entries
dam vault show REF_ID                              Decrypt and display entry
dam vault delete REF_ID                            Delete entry
dam consent list [--ref REF_ID]                    List consent rules
dam consent grant REF_ID ACCESSOR PURPOSE          Grant consent
dam consent revoke REF_ID ACCESSOR PURPOSE         Revoke consent
dam audit [--ref REF_ID] [--limit N]               View audit trail (default: 50)
dam config show                                    Display current configuration
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
dam-http       HTTP proxy — streaming SSE, Anthropic API passthrough
dam-cli        CLI binary — wires everything together
```

### Build from source

```bash
cargo build --release            # single ~6MB binary
cargo test --workspace           # 496 tests
cargo clippy --workspace         # lint
cargo fmt --check                # format check
```

## Roadmap

- [ ] NER-based detection (names, addresses, organizations)
- [ ] Vault cross-reference (flag values similar to known PII)
- [ ] Derived operations (compare, compute on encrypted values)
- [ ] Multi-provider proxy support (OpenAI, Google, etc.)
- [ ] Web dashboard for vault and consent management
- [ ] Team/org vault with shared consent policies

## License

Apache-2.0 — see [LICENSE](LICENSE) for details.
