# DAM - Data Access Mediator

**A PII firewall for AI agents.**

DAM sits between your application and the LLM provider as a local proxy. It intercepts personally identifiable information (PII) before it enters LLM context windows, replaces it with opaque typed references like `[email:a3f71bc9]`, stores the encrypted originals in a local vault, and resolves references back to real values in the response — so the user sees the original data but the LLM never does.

## Why

LLMs process personal data in ways users can't control: training pipelines, provider logging, context window leaks to other tools. DAM gives users a hard boundary — PII stays encrypted locally, the model gets references, and all operations are logged in a tamper-evident audit trail.

## Security Layers

```
                         YOUR MACHINE                          │  PROVIDER
                                                               │
  ┌─────────┐         ┌──────────────────────────────────┐     │    ┌──────────┐
  │  User /  │         │            DAM Proxy             │     │    │          │
  │  App     │         │                                  │     │    │   LLM    │
  │          │─────────┤►  1. INTERCEPT                   │     │    │ Provider │
  │ "Email   │  raw    │   Captures API request           │     │    │          │
  │  john@   │  PII    │                                  │     │    │          │
  │  acme.co │         │►  2. DETECT                      │     │    │          │
  │  at 555- │         │   Regex pipeline finds PII       │     │    │          │
  │  1234"   │         │                                  │     │    │          │
  │          │         │►  3. ENCRYPT + VAULT             │     │    │          │
  │          │         │   AES-256-GCM per value ──► 🔒   │     │    │          │
  │          │         │                                  │     │    │          │
  │          │         │►  4. REPLACE                     │     │    │          │
  │          │         │   john@acme.co → [email:a3f71bc9]│     │    │          │
  │          │         │   555-1234     → [phone:c2d81e4f]│─────┼───►│          │
  │          │         │                                  │ ref │    │ Only     │
  │          │         │                  redacted only ──┼─────┼───►│ sees     │
  │          │         │                                  │     │    │ [refs]   │
  │          │         │►  5. RESOLVE RESPONSE            │     │    │          │
  │          │◄────────┤   [email:a3f71bc9] → john@acme.co│◄────┼────│          │
  │  sees    │  real   │   refs back to real values       │     │    │          │
  │  real    │  values │                                  │     │    │          │
  │  values  │         │►  6. AUDIT                       │     │    │          │
  │          │         │   SHA-256 hash-chained log       │     │    │          │
  └─────────┘         └──────────────────────────────────┘     │    └──────────┘
                                                               │
                       Everything stays local.                 │  PII never leaves
                       Vault, keys, audit — on your machine.   │  your machine.
```

The proxy operates transparently: no code changes needed in your application. Point your API client at DAM instead of the provider, and PII is intercepted automatically.

## How It Works

1. **Intercept** — DAM receives the API request before it leaves your machine.
2. **Detect** — Regex detectors find emails, phones, SSNs, credit cards, IPs, and more.
3. **Encrypt + Vault** — Each PII value is encrypted (AES-256-GCM, per-entry key) and stored in a local SQLite vault.
4. **Replace** — Original values are swapped for typed references: `[email:a3f71bc9]`. The LLM receives only these tokens.
5. **Resolve response** — When the LLM responds with references, DAM replaces them with the original values before returning to the client. The user sees real data; the LLM never did.
6. **Audit** — Every scan, resolve, and reveal is logged with a SHA-256 hash chain. Tampered or deleted rows are detectable.

## Installation

### Prerequisites

- [Rust](https://rustup.rs/) toolchain (edition 2024, Rust 1.85+)
- A C compiler (required by the bundled SQLite build)
  - **Windows**: MSVC via Visual Studio Build Tools
  - **macOS**: Xcode command-line tools (`xcode-select --install`)
  - **Linux**: `build-essential` or equivalent

### Build from source

```bash
git clone https://github.com/alexyboyer/RPBLC.DAM.git
cd RPBLC.DAM
cargo install --path crates/dam-cli
```

This produces a single `dam` binary. The release build (`cargo build --release`) is ~6 MB with LTO and symbol stripping.

### Verify installation

```bash
dam --version
dam --help
```

## Quick Start

### 1. Initialize

```bash
dam init
```

During init, you'll select which regions' PII patterns to enable. Global patterns (email, credit card, IP, IBAN) are always active.

This creates:
- `~/.dam/` — home directory
- `~/.dam/vault.db` — encrypted SQLite vault
- `~/.dam/config.toml` — configuration file (with your selected locales)
- A 256-bit KEK stored in your OS keychain (DPAPI on Windows, Keychain on macOS, libsecret on Linux)

### 2. Start the proxy

```bash
dam serve                  # listen on 127.0.0.1:7828 (default)
dam serve --port 9000      # custom port
```

Point any Anthropic API client at the proxy:

```bash
export ANTHROPIC_BASE_URL=http://127.0.0.1:7828
```

That's it. All messages now flow through DAM. User messages are scanned and redacted before reaching the LLM. Responses are resolved back to real values before reaching you.

### 3. Try it with curl

```bash
# With DAM running, this request gets intercepted:
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

### 4. Scan text manually (CLI)

```bash
dam scan "Email me at john@acme.com, SSN 123-45-6789"
```

Output:
```
Redacted text:
Email me at [email:a3f71bc9], SSN [ssn:b2c81e4f]

Detections (2):
  [email:a3f71bc9] -> email (confidence: 95%)
  [ssn:b2c81e4f] -> ssn (confidence: 98%)
```

You can also pipe from stdin:
```bash
echo "Call me at 555-867-5309" | dam scan
```

### 5. View vault entries

```bash
dam vault list                    # all entries
dam vault list --type email       # filter by type
dam vault show email:a3f71bc9     # decrypt and display a value
dam vault delete email:a3f71bc9   # remove an entry
```

### 6. Manage consent

```bash
# Grant: allow "claude" to access email:a3f71bc9 for "send_email"
dam consent grant email:a3f71bc9 claude send_email

# Grant blanket access to a reference
dam consent grant email:a3f71bc9 "*" "*"

# List rules
dam consent list

# Revoke
dam consent revoke email:a3f71bc9 claude send_email
```

### 7. View audit trail

```bash
dam audit                          # last 50 entries
dam audit --ref email:a3f71bc9     # filter by reference
dam audit --limit 10               # limit output
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

This works with any tool that uses the Anthropic Messages API: `curl`, Python SDK, TypeScript SDK, etc.

### MCP Server (supplementary agent tools)

DAM also speaks the [Model Context Protocol](https://modelcontextprotocol.io/) over stdio, exposing vault tools to AI agents.

**Important**: MCP tools are called *by* the LLM, which means the LLM has already seen the data in its context window by the time it calls a tool. MCP does **not** provide the same security boundary as the proxy. Use the proxy for PII interception; use MCP tools for supplementary operations like:

- Scanning data fetched from external sources (files, APIs) before forwarding it elsewhere
- Searching the vault for existing references
- Managing consent and checking vault status
- Resolving references when executing actions (consent-checked)

After running `dam init`, add to your agent's MCP configuration:

**Claude Code** (`.mcp.json` in project root or `~/.claude/mcp.json` globally):
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

**Codex** (`~/.codex/config.toml`):
```toml
[mcp_servers.dam]
command = "dam"
args = ["mcp"]
```

**OpenClaw** (`mcp_config.json`):
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

### MCP Tools Reference

| Tool | Description | Parameters |
|------|-------------|------------|
| `dam_scan` | Scan text for PII, return redacted version | `text`, `source` (optional) |
| `dam_resolve` | Resolve references for action execution (consent-checked) | `text`, `accessor`, `purpose` |
| `dam_consent` | Grant or revoke consent | `ref_id`, `accessor`, `purpose`, `action` ("grant"/"revoke") |
| `dam_vault_search` | Search vault by type, returns refs only | `pii_type` (optional) |
| `dam_status` | Vault stats: entry counts, recent activity | (none) |
| `dam_reveal` | Override: reveal PII value (bypasses consent, audited) | `ref_id`, `reason` |
| `dam_compare` | Derived operations without revealing (stub) | `operation`, `ref_a`, `ref_b` (optional) |

## CLI Reference

```
dam init                                          Initialize vault, config, and KEK
dam serve [--port PORT]                           Start HTTP proxy (default: 7828)
dam mcp                                           Start MCP server (stdio transport)
dam scan [TEXT]                                    Scan text for PII (stdin if omitted)
dam vault list [--type TYPE]                       List vault entries
dam vault show REF_ID                              Decrypt and display entry
dam vault delete REF_ID                            Delete entry
dam consent list [--ref REF_ID]                    List consent rules
dam consent grant REF_ID ACCESSOR PURPOSE          Grant consent
dam consent revoke REF_ID ACCESSOR PURPOSE         Revoke consent
dam audit [--ref REF_ID] [--limit N]               View audit trail (default: 50)
dam config show                                    Display configuration
dam config get KEY                                 Get a config value
dam config set KEY VALUE                           Update a config value
```

## PII Types

DAM detects and classifies these PII types:

| Type | Tag | Example Pattern |
|------|-----|-----------------|
| Email | `email` | `user@example.com` |
| Phone | `phone` | `555-867-5309`, `(555) 867-5309` |
| SSN | `ssn` | `123-45-6789` |
| Credit Card | `cc` | `4111-1111-1111-1111` (Luhn-validated) |
| IP Address | `ip` | `203.0.113.1` (public IPs only) |
| Date of Birth | `dob` | (via custom rules) |
| Name | `name` | (via custom rules / NER) |
| Address | `addr` | (via custom rules) |
| Organization | `org` | (via custom rules) |
| Location | `loc` | (via custom rules) |
| Custom | `custom` | (user-defined regex) |

Built-in detectors cover email, phone, SSN, credit card, and IP address. Other types can be detected through custom regex rules in the config.

## Reference Format

All PII references follow the format `[type:hex_id]`:

```
[email:a3f71bc9]    — an email address
[phone:c2d81e4f]    — a phone number
[ssn:b7e31a02]      — a social security number
[cc:d4f82c19]       — a credit card number
```

- **Type tag**: lowercase identifier (see table above)
- **Hex ID**: 8-character random hex (4-16 chars accepted for future expansion)
- Same value + same type = same reference (deduplication)
- Different types with same value get different references

## Configuration

Config file location: `~/.dam/config.toml`

```toml
[vault]
path = "~/.dam/vault.db"    # vault database path
key_source = "os_keychain"  # "os_keychain", "passphrase", or { env_var = { name = "DAM_KEK" } }

[detection]
sensitivity = "standard"    # "standard", "elevated", or "maximum"
locales = ["global", "us"]  # active locale modules for PII detection
excluded_types = []         # e.g. ["ip", "phone"] to skip detection
whitelist = []              # terms to never flag as PII

[server]
http_port = 7828            # HTTP proxy port
```

### Key source options

| Source | Description |
|--------|-------------|
| `os_keychain` | KEK stored in OS keychain (DPAPI/Keychain/libsecret). Default. |
| `passphrase` | KEK derived from passphrase via Argon2id. Prompts on every command. |
| `env_var` | KEK read from environment variable. Set `name` to the variable name. |

### Sensitivity levels

| Level | Detects |
|-------|---------|
| `standard` | Structured PII: email, phone, SSN, credit card, IP address |
| `elevated` | + names, dates, organizations, locations |
| `maximum` | + any noun phrase matching vault history |

### Custom detection rules

Add custom regex rules in `config.toml`:

```toml
[detection.custom_rules.employee_id]
pattern = "EMP-\\d{6}"
pii_type = "custom"
description = "Internal employee ID"
```

## Security Model

### Encryption

- **Envelope encryption**: each PII value is encrypted with a unique DEK (Data Encryption Key) using AES-256-GCM
- The DEK is then wrapped (encrypted) by the KEK (Key Encryption Key)
- The KEK is stored in the OS keychain, never on disk
- DEKs are zeroized from memory after use

### Consent

- **Default-denied**: no tool can resolve PII without explicit consent
- Consent is per-reference, per-accessor, per-purpose
- Wildcard (`"*"`) supported for accessor and purpose
- `dam_reveal` bypasses consent but is always audited with a reason

### Audit trail

- Every operation (scan, resolve, reveal, consent grant/revoke) is logged
- Entries are SHA-256 hash-chained: each row includes the hash of the previous row
- Tampered or deleted rows are detectable via `dam audit` chain verification

### Deduplication

- Storing the same value with the same type returns the existing reference
- Different types with the same value get separate entries

### Proxy vs. MCP: security comparison

| | HTTP Proxy | MCP Tools |
|---|---|---|
| PII reaches the LLM | No — intercepted before the request | Yes — LLM sees data before calling tools |
| Relies on LLM compliance | No — enforced at network layer | Yes — LLM must choose to call `dam_scan` |
| Automatic | Yes — transparent, no code changes | No — requires LLM to follow instructions |
| Best for | Primary PII protection | Vault operations, scanning external data, consent management |

## Architecture

DAM is a Cargo workspace with 7 focused crates:

```
dam-core      Types, reference format, config, errors
dam-vault     Encrypted SQLite storage, envelope crypto, keychain, consent, audit
dam-detect    PII detection pipeline (regex, user rules, NER stub, xref stub)
dam-resolve   Outbound resolution with consent checking
dam-mcp       MCP server with 7 tools (stdio transport)
dam-http      HTTP proxy, streaming SSE resolver, Anthropic API types
dam-cli       CLI binary — all commands, wires everything together
```

Data flow (HTTP proxy):

```
                      ┌──────────────┐
User input ──────────►│  dam-detect  │──── scan + encrypt ────►┌───────────┐
                      │  (pipeline)  │                         │ dam-vault │
                      └──────────────┘                         │ (SQLite)  │
                             │                                 └─────┬─────┘
                    redacted text with                               │
                    [type:hex] refs                                  │
                             │                                       │
                             ▼                                       │
                      ┌─────────────┐     consent check +            │
LLM context ─────────►│ dam-resolve │◄──── decrypt ──────────────────┘
                      └─────────────┘
                             │
                      real values (only
                      with consent)
                             │
                             ▼
                      Action execution
```

## Building from Source

```bash
cargo build                      # debug build
cargo build --release            # release build (single ~6MB binary)
cargo test --workspace           # run all tests
cargo clippy --workspace         # lint
cargo fmt --check                # format check
```

## License

Apache-2.0 — see [LICENSE](LICENSE) for details.
