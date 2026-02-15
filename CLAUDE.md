# DAM — Development Guide

## What is DAM?

DAM (Data Access Mediator) is a PII firewall for AI agents. It intercepts personal data before it enters LLM context windows, replaces it with typed references like `[email:a3f71bc9]`, stores encrypted originals in a local vault, and resolves references only at execution boundaries with consent checks.

## Build Commands

```bash
cargo build                      # debug build
cargo build --release            # release build (single binary)
cargo test --workspace           # all tests
cargo clippy --workspace         # lint
cargo fmt --check                # format check
```

## Architecture

Cargo workspace with focused crates:

- **dam-core** — Types, reference format, config, errors
- **dam-vault** — Encrypted local storage (SQLite + AES-256-GCM envelope encryption)
- **dam-detect** — PII detection pipeline (regex, user rules, NER stub, xref stub)
- **dam-resolve** — Outbound resolution with consent check
- **dam-mcp** — MCP server with 7 tools
- **dam-http** — HTTP proxy, streaming SSE resolver, Anthropic API types
- **dam-cli** — CLI binary (`dam` command)

## Key Design Decisions

- **Envelope encryption**: Each PII value gets its own DEK, wrapped by a KEK from OS keychain
- **Typed references**: `[email:a3f71bc9]` format lets LLMs reason about PII type without seeing values
- **Consent-by-default-denied**: No tool can resolve PII without explicit consent
- **Hash-chained audit**: Every operation logged with SHA-256 chain for tamper detection
- **Deduplication**: Same value+type stored once, returns existing reference

## MCP Tools

| Tool | Purpose |
|------|---------|
| `dam_scan` | Scan text for PII, return redacted version |
| `dam_resolve` | Resolve refs for action execution (consent-checked) |
| `dam_consent` | Grant/revoke consent (ref + accessor + purpose) |
| `dam_vault_search` | Search vault by type, returns refs only |
| `dam_status` | Vault stats, entry counts, recent activity |
| `dam_reveal` | Override: temporarily reveal PII (audited) |
| `dam_compare` | Derived operations without revealing (Phase 3 stub) |

## Locales

Detection patterns are organized by geographic locale in `crates/dam-detect/src/locales/`:

- `global.rs` — patterns not specific to any country (email, credit card, intl phone, IPv4, DOB)
- `us.rs` — US-specific patterns (SSN, US phone)
- `mod.rs` — `build_patterns()` dispatcher that assembles patterns from active locales

**Adding a new locale**: create `xx.rs`, add `mod xx;` + match arm in `mod.rs`, create `docs/locales/xx.md`.

**Classification rule**: if a pattern is country-specific, it goes in that locale module; otherwise it goes in `global.rs`.

Keep `docs/locales/` in sync when patterns change.

## Conventions

- Error type: `DamError` / `DamResult<T>` in dam-core
- PII types: `PiiType` enum with `tag()` for short form, `Display` for long
- References: `PiiRef` with `key()` → `"email:a3f71bc9"`, `display()` → `"[email:a3f71bc9]"`
- All vault operations go through `VaultStore` (mutex-protected SQLite)
- Consent: `ConsentManager::check_consent(conn, ref_id, accessor, purpose)`
- Audit: `AuditLog::record_locked(conn, ref_id, accessor, purpose, action, granted, detail)`
