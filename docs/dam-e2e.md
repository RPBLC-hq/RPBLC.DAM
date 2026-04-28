# dam-e2e

`dam-e2e` is the process-level end-to-end test package.

It tests multiple DAM binaries and modules together using temp SQLite databases, synthetic data, fake upstreams, and no real provider calls.

## Scope

Current E2E coverage:

- `dam-filter -> dam-vault -> dam-log -> dam-resolve` roundtrip.
- Token reordering before resolve, proving resolution is keyed by `[kind:id]` and not token order.
- `dam-web` smoke test against vault/log DBs populated by `dam-filter`.
- `dam-proxy` through a fake OpenAI-like upstream, proving raw sensitive values are redacted before upstream receives the request and resolved before the local client receives the response.
- `dam-proxy` inbound resolution setting coverage in module tests, including `--no-resolve-inbound`.
- `dam-proxy -> dam-vault -> dam-log -> dam-resolve` restoration of the protected upstream payload.
- `dam codex` ChatGPT-login fail-closed behavior, `dam codex --api` custom-provider wiring, and `dam claude` launcher wiring with fake tool executables.
- Persisted log privacy checks for raw sensitive values.

## How It Runs

The E2E tests build the real binaries first:

```text
dam
dam-filter
dam-resolve
dam-proxy
dam-web
```

Then tests invoke the binaries from `target/debug` against temp directories. This keeps `cargo test -p dam-e2e` usable without relying on package-local `CARGO_BIN_EXE_*` variables.

## Run

```bash
cargo test -p dam-e2e
```

Full workspace verification:

```bash
cargo fmt --all --check
cargo clippy --workspace -- -D warnings
cargo test --workspace
```

## Rules

- Use synthetic data only.
- Use temp databases only.
- Do not call OpenAI, Anthropic, OpenRouter, or other real providers.
- Prefer fake upstreams and local processes.
- Assert that persisted logs do not contain raw sensitive values.
