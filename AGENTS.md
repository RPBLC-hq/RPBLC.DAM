# DAM — Development Guide

## What is DAM?

DAM (Data Access Mediator) mediates access to sensitive data in transit. It sits between applications and the internet as a forward proxy, detects sensitive data (PII, credentials, secrets), tokenizes it (stores encrypted originals in a local vault), and provides MCP + CLI tools to selectively release data.

## Build Commands

```bash
cargo build --workspace              # debug build
cargo build --release -p dam-cli     # release binary
cargo test --workspace               # all tests
cargo clippy --workspace -- -D warnings  # lint
cargo fmt --all --check              # format check
cargo fmt --all                      # auto-fix formatting
cargo run -p dam-cli                 # start proxy on :7828
cargo run -p dam-cli -- --port 8080  # custom port
```

## Architecture

Spine + Vertebrae model. The spine knows nothing about detection, storage, or logging. Each vertebra is a module that plugs into the spine via the `Module` trait.

### Crates

| Crate | Role | Type |
|---|---|---|
| `dam-core` | Proxy engine, Module trait, FlowExecutor, streaming, config | Spine |
| `dam-detect-pii` | PII detection (email, phone, SSN, CC, IBAN, IP) | Detection vertebra |
| `dam-detect-secrets` | Secrets detection (API keys, JWTs, private keys, credentials) | Detection vertebra |
| `dam-vault` | Tokenize, encrypt (AES-256-GCM), store (SQLite), resolve | Action vertebra |
| `dam-log` | Detection event logging, `dam stats` | Action vertebra |
| `dam-cli` | Binary entry point, CLI commands, wires spine + vertebrae | Binary |
| `_legacy/` | Old v0.3.1 codebase — reference only, do not build | Archive |

### Dependency graph

```
dam-core         → (no internal deps)
dam-detect-pii   → dam-core
dam-detect-secrets → dam-core
dam-vault        → dam-core
dam-log          → dam-core
dam-cli          → all of the above
```

### Default module flow

```
detect-pii → detect-secrets → vault (LLM calls only) → log (all traffic)
```

### Module trait

Every vertebra implements:

```rust
pub trait Module: Send + Sync {
    fn name(&self) -> &str;
    fn module_type(&self) -> ModuleType; // Detection or Action
    fn matches(&self, ctx: &FlowContext) -> bool;
    fn process(&self, ctx: &mut FlowContext) -> Result<(), DamError>;
}
```

## Key Design Decisions

- **Envelope encryption**: Each value gets a random DEK (AES-256-GCM), wrapped by a KEK stored at `~/.dam/key`
- **Auto-generated key**: No OS keychain. 32 random bytes written to file with 0600 permissions on first run.
- **Typed tokens**: `[email:7B2HkqFn9xR4mWpD3nYvKt]` format — 128-bit UUID in base58 (22 chars). LLMs reason about data type without seeing values
- **Deduplication**: Same value+type stored once, returns existing token
- **Separate DBs**: `~/.dam/dam.db` (vault), `~/.dam/log.db` (detection events)
- **Zero config**: `dam` with no arguments starts the proxy. No TOML, no init, no setup.
- **Graceful degradation**: Never break traffic. Detection failure → pass through. Vault failure → redact without token.

## CLI Commands

| Command | Purpose |
|---------|---------|
| `dam` | Start proxy on default port (7828) |
| `dam --port 8080` | Start proxy on custom port |
| `dam -v` | Verbose output |
| `dam stats` | Detection counts by type and destination |
| `dam resolve <token>` | Resolve a token to its original value |
| `dam tokens` | List all tokens in the vault |
| `dam log` | Show recent detection events |
| `dam mcp` | Start MCP server on stdio (phase 2) |

## Proxy Usage

Set the `X-DAM-Upstream` header to route through DAM:

```bash
curl -H "X-DAM-Upstream: https://api.anthropic.com/v1/messages" \
     -H "x-api-key: $ANTHROPIC_API_KEY" \
     -H "content-type: application/json" \
     -d '{"model":"claude-sonnet-4-20250514","messages":[{"role":"user","content":"My email is alice@example.com"}]}' \
     http://localhost:7828/
```

Or use path-based routing:

```bash
curl -d '...' http://localhost:7828/https://api.anthropic.com/v1/messages
```

## Detection

### PII types (dam-detect-pii)

Email, Phone (E.164 + NANP), SSN, Credit Card (Luhn validated), IBAN (Mod97), IP Address (private ranges rejected).

Text normalization: zero-width char stripping, NFKC, unicode dash normalization, URL decoding.

### Secret types (dam-detect-secrets)

JWT tokens, AWS access keys, GitHub tokens, Stripe keys, OpenAI keys, Anthropic keys, PEM private keys, credential URLs.

## Conventions

- Error type: `DamError` / `DamResult<T>` in dam-core
- Data types: `SensitiveDataType` enum with `tag()` for short form
- Tokens: `Token` with `key()` → `"email:7B2HkqFn9xR4mWpD3nYvKt"`, `display()` → `"[email:7B2HkqFn9xR4mWpD3nYvKt]"`. IDs are 128-bit UUID base58-encoded (22 chars).
- All vault operations go through `VaultStore` (mutex-protected SQLite)
- Module names match crate names: `"detect-pii"`, `"detect-secrets"`, `"vault"`, `"dam-log"`

## Adding a new detection module

1. Create a new crate: `cargo init --lib dam-detect-<name>`
2. Add `dam-core` as a dependency
3. Implement the `Module` trait with `ModuleType::Detection`
4. Add regex patterns in `patterns.rs`, validators if needed
5. Wire it into `dam-cli/src/main.rs` in the module chain
6. Add to workspace `Cargo.toml` members

## Release Checklist

1. All tests pass: `cargo test --workspace`
2. Lint clean: `cargo clippy --workspace -- -D warnings`
3. Format clean: `cargo fmt --all --check`
4. Bump version in root `Cargo.toml`
5. Update changelog
6. Tag and push: `git tag vX.Y.Z && git push origin vX.Y.Z`
