# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **Tier 2 checksummed patterns** — 9 new `PiiType` variants with checksum validators, 6 new locales:
  - **Vehicle** — `Vin` (ISO 3779 check digit, position 9): Global
  - **Singapore** — `Nric` (MOD-11 check letter, S/T/F/G/M series): `Locale::Sg`
  - **Spain** — `Nif` (mod23 table check letter) and `Nie` (same algorithm with X/Y/Z→digit prefix): `Locale::Es`
  - **Italy** — `CodiceFiscale` (odd/even position table, 16-char tax code): `Locale::It`
  - **Brazil** — `Cpf` (double mod-11 two-digit check, formatted as `ddd.ddd.ddd-dd`): `Locale::Br`
  - **Mexico** — `Curp` (ascending position-weight sum mod 10, 18-char identity code): `Locale::Mx`
  - **UAE** — `EmiratesId` (Luhn, 15-digit `784-…` format): `Locale::Ae`
  - **US** — `DeaNumber` (checksum mod 10 on 7 digits, 2-letter + 7-digit format): `Locale::Us`

- **LLM provider API keys** — new `LlmApiKey` type (tag: `llm_key`) with 9 patterns covering every major LLM provider by structural prefix: Anthropic (`sk-ant-api…`), OpenAI legacy (`sk-`+48), OpenAI project (`sk-proj-…`), OpenAI service-account (`sk-svcacct-…`), Hugging Face (`hf_…`), Replicate (`r8_…`), xAI (`xai-…`), Groq (`gsk_…`), Perplexity (`pplx-…`); Google Gemini already covered by `ApiKey` via `AIza…`

- **Tier 1 high-confidence patterns** — 15 new `PiiType` variants and 29 new regex patterns covering digital secrets, credentials, crypto wallets, and network identifiers. All patterns have near-zero false-positive rates due to highly specific structural formats; no keyword-anchoring required:
  - **Credentials** — JWT (`eyJ...`), AWS access key (`AKIA...`), AWS ARN (`arn:aws:...`), GitHub tokens (`gh[pousr]_...`), Stripe API keys (`sk_/pk_live/test_...`) and object IDs (`cus_/tok_/pm_/src_/sub_/card_...`)
  - **Generic API keys** — Google (`AIza...`), Slack webhooks (`hooks.slack.com/...`) and tokens (`xox[baprs]-...`), SendGrid (`SG....`), npm (`npm_...`), Mailgun (`key-...`), Twilio (`SK...`)
  - **Private keys** — RSA, EC, and OpenSSH PEM blocks (`-----BEGIN ... PRIVATE KEY-----`)
  - **Credential URLs** — database connection strings (`postgres://user:pass@host`) and generic HTTP URLs with embedded credentials (`https://user:pass@host`)
  - **Cryptocurrency** — Ethereum (`0x` + 40 hex), Bitcoin bech32 (`bc1...`), Bitcoin legacy (base58, P2PKH/P2SH)
  - **Network** — IPv6 fully-expanded form (loopback/link-local/multicast filtered), MAC addresses (broadcast/unspecified filtered)
  - **Documents** — Passport MRZ TD3 two-line format
  - **Logistics** — UPS tracking numbers (`1Z...`)
  - **UK banking** — Sort code + account number pair (`XX-XX-XX XXXXXXXX`) added to UK locale

## [0.3.0] — 2026-02-26

### Added

- **Auto-init** — `dam serve` and `dam mcp` now auto-create config, vault, and KEK if they don't exist, eliminating the mandatory `dam init` step and preventing agents from bricking themselves during proxy setup
- **`dam daemon` subcommand** — manage DAM as a persistent background service that survives reboots and auto-restarts on crash; supports `install`, `uninstall`, `start`, `stop`, `status` with platform-native backends (systemd on Linux, launchd on macOS, Registry Run key on Windows)
- **PID file + graceful shutdown** — `dam serve` writes `~/.dam/dam.pid` on startup and removes it on clean shutdown; handles SIGTERM (Unix) and ctrl-c for graceful request draining
- **npm distribution** — install via `npm install -g @rpblc/dam` or `npx @rpblc/dam daemon install`; platform-specific binary packages for Linux x64, macOS ARM64/x64, and Windows x64
- **`X-DAM-Upstream` header routing** — per-request upstream URL override via `X-DAM-Upstream` header, enabling multi-provider setups (e.g. xAI + OpenAI) without extra config
- **OpenAI Responses API proxy** (`POST /v1/responses`) — PII redaction and streaming SSE resolution for OpenAI's Responses API, enabling DAM to proxy codex/responses traffic (e.g. OpenClaw's `openai-codex` provider)

### Fixed

- **PII format preservation** — vault now stores the original format of PII values (e.g. `(555) 867-5309`) instead of the normalized form (`5558675309`); normalization is used only for deduplication comparison

## [0.2.0] — 2026-02-19

### Added

- **Consent-aware proxy redaction** — PII with granted consent now passes through to the LLM un-redacted; without consent, PII is still redacted as before
- **Mandatory consent duration** — `--ttl` flag required on `dam consent grant` and MCP `dam_consent` tool (no infinite consent allowed); accepts durations like `30m`, `1h`, `24h`, `7d`
- **OpenAI Chat Completions proxy** (`POST /v1/chat/completions`) — PII redaction and streaming SSE resolution for OpenAI-compatible APIs (OpenAI, OpenRouter, xAI, Ollama, etc.)
- Configurable upstream URLs for Anthropic and OpenAI via config or CLI (`--anthropic-upstream`, `--openai-upstream`)
- Release binary workflow — cross-compiled binaries for Linux, macOS (ARM + Intel), and Windows published to GitHub Releases on tag push, with SHA-256 checksums
- Rustdoc comments on all public API types, methods, and error variants across all crates
- Crate-level `//!` doc comments on all seven `lib.rs` / `main.rs` files
- `docs/ARCHITECTURE.md` — deep design documentation covering envelope encryption, consent resolution, audit hash chain, detection pipeline, streaming SSE resolution, threat model, and crate dependency graph
- "Who Is This For?" section in README with developer, compliance, and solo developer personas
- `--verbose` / `-v` CLI flag for debug-level tracing output on `serve`, `scan`, and all non-MCP commands
- Improved `dam init` post-setup instructions — quick-start example, proxy-first integration flow, and a command reference
- `dam vault clear` command — delete all vault entries and consent rules (with interactive confirmation or `--yes` flag)
- "Adding a New PII Type" step-by-step guide in `docs/ARCHITECTURE.md`
- Rustdoc comments on internal normalization helpers (`url_decode`, `decode_base64_segments`, `base64_decode`)

### Fixed

- CLI commands (`vault show`, `vault delete`, `consent grant`, `audit --ref`) now accept bracketed references like `[email:a3f71bc9]` in addition to bare `email:a3f71bc9`
- Rust version badge corrected from 1.85+ to 1.88+
- README quick start updated with OpenAI curl example and both provider base URLs

## [0.1.0] — 2026-02-16

### Added

- **HTTP proxy mode** (`dam serve`) — transparent PII interception for Anthropic Messages API, with streaming SSE support
- **MCP server mode** (`dam mcp`) — 7 tools for AI agent vault operations over stdio transport
- **Encrypted vault** — AES-256-GCM envelope encryption with per-entry DEKs, OS keychain KEK storage
- **Consent management** — default-denied, granular per-reference/accessor/purpose rules with wildcards and expiry
- **Audit trail** — SHA-256 hash-chained log for tamper-evident compliance visibility
- **PII detection pipeline** — regex-based with validators, 18+ PII types across 7 locales:
  - Global: email, credit card (Luhn), international phone, IPv4, date of birth, IBAN (Mod97)
  - US: SSN, US phone
  - Canada: SIN (Luhn), postal code
  - UK: NI number, NHS number (Mod11), driving licence (DVLA)
  - France: INSEE/NIR
  - Germany: Personalausweis (ICAO), Steuer-ID
  - EU: VAT number, SWIFT/BIC
- **Text normalization** — zero-width character stripping, Unicode dash mapping, NFKC normalization, URL decoding, Base64 decoding
- **CLI** — `dam init`, `dam scan`, `dam vault`, `dam consent`, `dam audit`, `dam config`, `dam serve`, `dam mcp`
- **Interactive locale selection** — `dam init` suggests locales based on OS locale
- **Custom detection rules** — user-defined regex patterns via config
- **Deduplication** — same value + same type stored once, returns existing reference
- **Apache-2.0 license**
