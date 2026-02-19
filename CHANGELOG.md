# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

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
