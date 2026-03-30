# DAM — Data Access Mediator

See [AGENTS.md](AGENTS.md) for development instructions.

## Quick reference

- **Architecture:** Spine (dam-core) + Vertebrae (modules). See AGENTS.md for details.
- **Pipeline:** detect-pii → detect-secrets → consent → vault → redact → log
- **Build:** `cargo build --workspace`
- **Test:** `cargo test --workspace`
- **Run proxy:** `cargo run -p dam-cli` or `cargo run -p dam-cli -- --port 8080`
- **Run filter:** `echo '{"msg":"alice@test.com"}' | cargo run -p dam-filter -- --format json`
- **Lint:** `cargo clippy --workspace -- -D warnings`
- **Format:** `cargo fmt --check`

## Crate map

| Crate | Role |
|---|---|
| `dam-core` | Spine — proxy, Module trait, FlowExecutor, streaming, config |
| `dam-detect-pii` | Vertebra — PII detection (email, phone, SSN, CC, IBAN, IP) |
| `dam-detect-secrets` | Vertebra — secrets detection (API keys, JWTs, private keys) |
| `dam-consent` | Vertebra — consent rules, verdict assignment (pass/redact) |
| `dam-vault` | Vertebra — encrypt and store all detected values |
| `dam-redact` | Vertebra — replace body text for redacted detections |
| `dam-log` | Vertebra — detection event logging, stats |
| `dam-cli` | Binary — wires spine + vertebrae, CLI commands |
| `dam-filter` | Binary — standalone PII/secret filter for sessions (no vault/proxy) |
| `_legacy/` | Old v0.3.1 codebase — reference only, do not build |
