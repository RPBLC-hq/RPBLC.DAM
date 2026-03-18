# DAM — Data Access Mediator

See [AGENTS.md](AGENTS.md) for development instructions.

## Quick reference

- **Architecture:** Spine (dam-core) + Vertebrae (modules). See AGENTS.md for details.
- **Build:** `cargo build --workspace`
- **Test:** `cargo test --workspace`
- **Run:** `cargo run -p dam-cli` or `cargo run -p dam-cli -- --port 8080`
- **Lint:** `cargo clippy --workspace -- -D warnings`
- **Format:** `cargo fmt --check`

## Crate map

| Crate | Role |
|---|---|
| `dam-core` | Spine — proxy, Module trait, FlowExecutor, streaming, config |
| `dam-detect-pii` | Vertebra — PII detection (email, phone, SSN, CC, IBAN, IP) |
| `dam-detect-secrets` | Vertebra — secrets detection (API keys, JWTs, private keys) |
| `dam-vault` | Vertebra — tokenize, encrypt, store, resolve |
| `dam-log` | Vertebra — detection event logging, stats |
| `dam-cli` | Binary — wires spine + vertebrae, CLI commands |
| `_legacy/` | Old v0.3.1 codebase — reference only, do not build |
