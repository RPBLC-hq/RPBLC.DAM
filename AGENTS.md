# DAM — Development Guide

## What is DAM?

DAM (Data Access Mediator) mediates access to sensitive data in transit. It sits between applications and the internet as a forward proxy. It detects sensitive data, checks consent rules, stores everything encrypted, redacts what isn't approved, and logs all activity.

## Build Commands

```bash
cargo build --workspace              # debug build
cargo build --release -p dam-cli     # release proxy binary
cargo build --release -p dam-filter  # release filter binary
cargo test --workspace               # all tests
cargo clippy --workspace -- -D warnings  # lint
cargo fmt --all --check              # format check
cargo fmt --all                      # auto-fix formatting
cargo run -p dam-cli                 # start proxy on :7828
cargo run -p dam-cli -- --port 8080  # custom port
```

## Architecture

Spine + Vertebrae model. The spine knows nothing about detection, consent, storage, or logging. Each vertebra is a module that plugs into the spine via the `Module` trait.

### Crates

| Crate | Role | Type |
|---|---|---|
| `dam-core` | Proxy engine, Module trait, FlowExecutor, FlowContext, streaming, config | Spine |
| `dam-detect-pii` | PII detection (email, phone, SSN, CC, IBAN, IP) | Detection vertebra |
| `dam-detect-secrets` | Secrets detection (API keys, JWTs, private keys, credentials) | Detection vertebra |
| `dam-consent` | Consent rules, verdict assignment (pass/redact per detection) | Filter vertebra |
| `dam-vault` | Encrypt and store ALL detected values (AES-256-GCM, SQLite) | Storage vertebra |
| `dam-redact` | Replace body text with tokens for Verdict::Redact detections | Action vertebra |
| `dam-log` | Detection event logging, `dam stats` | Action vertebra |
| `dam-cli` | Binary entry point, CLI commands, wires spine + vertebrae | Binary |
| `dam-filter` | Standalone PII/secret filter for sessions — detect + redact, no vault/proxy | Binary |
| `_legacy/` | Old v0.3.1 codebase — reference only, do not build | Archive |

### Dependency graph

```
dam-core           → (no internal deps)
dam-detect-pii     → dam-core
dam-detect-secrets → dam-core
dam-consent        → dam-core
dam-vault          → dam-core
dam-redact         → dam-core, dam-vault
dam-log            → dam-core
dam-cli            → all of the above
dam-filter         → dam-core, dam-detect-pii, dam-detect-secrets (no vault/consent/redact/log)
```

### Default module flow (dam-cli proxy)

```
detect-pii → detect-secrets → consent → vault → redact → log
```

### Filter flow (dam-filter standalone)

```
stdin → detect-pii → detect-secrets → dedup → replace with [DAM:TYPE] → stdout
```

dam-filter skips consent/vault/redact/log. Every detection is replaced with a branded placeholder (`[DAM:EMAIL]`, `[DAM:SSN]`, etc.). No vault tokens, no storage.

- **detect-***: find sensitive data, append `Detection` objects with `verdict: Pending`
- **consent**: check rules, set `verdict: Pass` or `verdict: Redact` per detection
- **vault**: store ALL detections encrypted (pass AND redact) for audit/recovery
- **redact**: replace body text only for `verdict: Redact` detections (LLM calls only)
- **log**: record everything

### Module trait

Every vertebra implements:

```rust
pub enum Verdict { Pending, Redact, Pass }

pub trait Module: Send + Sync {
    fn name(&self) -> &str;
    fn module_type(&self) -> ModuleType; // Detection or Action
    fn matches(&self, ctx: &FlowContext) -> bool;
    fn process(&self, ctx: &mut FlowContext) -> Result<(), DamError>;
}
```

Modules communicate through `FlowContext` — a shared struct with `detections: Vec<Detection>`, `modified_body`, `tokens_created`, and `destination`. Modules append data, never remove.

## Key Design Decisions

- **Envelope encryption**: Each value gets a random DEK (AES-256-GCM), wrapped by a KEK stored at `~/.dam/key`
- **Auto-generated key**: No OS keychain. 32 random bytes written to file with 0600 permissions on first run.
- **Typed tokens**: `[email:a3f71b]` format — 128-bit UUID in base58 (22 chars). LLMs reason about data type without seeing values.
- **Deduplication**: Same value+type stored once, returns existing token
- **Separate DBs**: `~/.dam/dam.db` (vault), `~/.dam/consent.db` (rules), `~/.dam/log.db` (events)
- **Zero config**: `dam` with no arguments starts the proxy. No TOML, no init, no setup.
- **Default deny**: No data passes through LLM calls without explicit consent.
- **Vault stores everything**: Both passed and redacted values stored for audit and recovery.
- **Graceful degradation**: Never break traffic. Detection failure → pass through. Vault failure → redact without token.

## CLI Commands

Commands are grouped by the module that owns them.

### Proxy

| Command | Purpose |
|---------|---------|
| `dam` | Start proxy on default port (7828) |
| `dam --port 8080` | Start proxy on custom port |
| `dam -v` | Verbose output |

### Consent (dam-consent)

| Command | Purpose |
|---------|---------|
| `dam consent grant [OPTIONS]` | Grant consent — allow data to pass |
| `dam consent deny [OPTIONS]` | Deny — explicitly block data |
| `dam consent list` | List all active rules |
| `dam consent revoke <id>` | Remove a rule |

Grant/deny options: `--type <tag>`, `--token <key>`, `--value <raw>`, `--dest <host>`, `--ttl <duration>`

### Vault (dam-vault)

| Command | Purpose |
|---------|---------|
| `dam resolve <token>` | Resolve a token to its original value |
| `dam tokens` | List all tokens in the vault |

### Log (dam-log)

| Command | Purpose |
|---------|---------|
| `dam stats` | Detection counts by type and destination |
| `dam log [-n 50]` | Show recent detection events |

## Consent Model

Rules are layered — most specific match wins:

1. Token + exact destination (highest priority)
2. Token + wildcard destination
3. Type + exact destination
4. Type + wildcard destination
5. Wildcard type + exact destination
6. Wildcard type + wildcard destination
7. No match → redact (default deny)

Default TTL: 24 hours. `--ttl permanent` for no expiration.

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

## Conventions

- Error type: `DamError` / `DamResult<T>` in dam-core
- Data types: `SensitiveDataType` enum with `tag()` for short form
- Tokens: `Token` with `key()` → `"email:a3f71b"`, `display()` → `"[email:a3f71b]"`. IDs are 128-bit UUID base58-encoded (22 chars).
- Verdicts: `Verdict::Pending` (just detected), `Verdict::Redact` (tokenize), `Verdict::Pass` (let through)
- All vault operations go through `VaultStore` (mutex-protected SQLite)
- Module names: `"detect-pii"`, `"detect-secrets"`, `"consent"`, `"vault"`, `"redact"`, `"dam-log"`

## Adding a new module

1. Create a new crate: `cargo init --lib dam-<name>`
2. Add `dam-core` as a dependency
3. Implement the `Module` trait
4. Wire it into `dam-cli/src/main.rs` in the module chain
5. Add to workspace `Cargo.toml` members
6. Add CLI subcommands if the module needs them

## Release Checklist

1. All tests pass: `cargo test --workspace`
2. Lint clean: `cargo clippy --workspace -- -D warnings`
3. Format clean: `cargo fmt --all --check`
4. Bump version in root `Cargo.toml`
5. Update changelog
6. Tag and push: `git tag vX.Y.Z && git push origin vX.Y.Z`
