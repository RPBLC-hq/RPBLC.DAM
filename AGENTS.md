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

## PII Types

The full PII type reference lives in **`docs/pii-types.md`**. When adding a new `PiiType` variant:

1. Follow the steps in `docs/pii-types.md` → "Adding a New PII Type"
2. **Update `docs/pii-types.md`** with the new row in the appropriate category table
3. Add tests in the locale's `#[cfg(test)]` module and/or `stage_regex.rs`

The README (`PII Detection` section) shows only a curated spotlight of the most commonly leaked/critical types — do **not** expand that table. Update `docs/pii-types.md` for the complete list.

## Governance Files

Keep these files up to date when making changes:

- **CHANGELOG.md** — add entries under an `[Unreleased]` section for every user-facing change (new features, bug fixes, breaking changes). When releasing, rename `[Unreleased]` to `[version] — date`.
- **SECURITY.md** — update scope if new security-sensitive components are added (e.g., new encryption schemes, auth mechanisms, network-exposed endpoints).
- **CONTRIBUTING.md** — update if build steps, PR process, or code conventions change.

## Workflow

- Before creating a PR, pull the latest `main` and rebase your branch to avoid merge conflicts.

## Conventions

- Error type: `DamError` / `DamResult<T>` in dam-core
- PII types: `PiiType` enum with `tag()` for short form, `Display` for long
- References: `PiiRef` with `key()` → `"email:a3f71bc9"`, `display()` → `"[email:a3f71bc9]"`
- All vault operations go through `VaultStore` (mutex-protected SQLite)
- Consent: `ConsentManager::check_consent(conn, ref_id, accessor, purpose)`
- Audit: `AuditLog::record_locked(conn, ref_id, accessor, purpose, action, granted, detail)`

## Release Checklist

When preparing a release, follow these steps in order:

### 1. Pre-release Verification

- [ ] All CI checks pass on `main` (`cargo test --workspace`, `cargo clippy --workspace`, `cargo fmt --all --check`)
- [ ] No unmerged feature branches intended for this release

### 2. Version Bump

- [ ] Bump `version` in root `Cargo.toml` (`[workspace.package]` — all crates inherit from it)
- [ ] Run `cargo build` to update `Cargo.lock`

### 3. Changelog

- [ ] Rename `[Unreleased]` section in `CHANGELOG.md` to `[X.Y.Z] — YYYY-MM-DD`
- [ ] Add a new empty `[Unreleased]` section above it

### 4. Documentation Review

Review all READMEs and docs against the changelog. For each entry in the new release section, check if any docs need updating:

- [ ] **README.md** (root) — Quick Start, CLI Reference, Integration routes, feature descriptions, PII types spotlight, config examples
- [ ] **docs/pii-types.md** — full PiiType reference; add rows for any new types in this release
- [ ] **npm/dam/README.md** — npm package page on npmjs.com; keep CLI commands, routes table, and feature list in sync
- [ ] **docs/integrations.md** — daemon setup, proxy routes, MCP server config, install instructions
- [ ] **docs/ARCHITECTURE.md** — if internals changed (new crates, new encryption schemes, new pipeline stages)
- [ ] **docs/security-model.md** — if security-relevant changes were made
- [ ] **docs/routing.md** — if proxy routing or upstream handling changed
- [ ] **SECURITY.md** — if new attack surface was added (new endpoints, new auth mechanisms)
- [ ] **CONTRIBUTING.md** — if build steps, PR process, or dependencies changed

### 5. Commit and Tag

- [ ] Commit all changes: version bump, changelog, doc updates
- [ ] Push to `main`
- [ ] Create and push tag: `git tag vX.Y.Z && git push origin vX.Y.Z`

### 6. Verify Release

- [ ] GitHub Actions release workflow completes (all 4 platform builds + GitHub Release + npm publish)
- [ ] GitHub Release page has binaries and checksums
- [ ] npm packages updated: check https://www.npmjs.com/package/@rpblc/dam
- [ ] `npm install -g @rpblc/dam` installs the new version
- [ ] `npx @rpblc/dam --help` works

### 7. Post-release

- [ ] Delete the release branch if one was used
- [ ] Close any related GitHub issues with a comment referencing the release
