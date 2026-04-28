# DAM Agent Instructions

This workspace is being rebuilt one module at a time. Keep changes small, explicit, and contract-driven.

## Open Source Guidelines

This project is intended to be open source.

- Do not add proprietary business logic, private customer assumptions, or environment-specific behavior to core modules.
- Do not commit secrets, real credentials, real personal data, private URLs, or internal-only deployment details.
- Prefer small public contracts and replaceable implementations over closed, tightly coupled integrations.
- Keep public APIs, config keys, CLI behavior, and failure modes documented.
- Use synthetic data in examples, tests, fixtures, docs, and manual test commands.
- Keep dependencies minimal and compatible with the project license. Avoid adding a dependency unless it is clearly justified.
- Do not introduce telemetry, network calls, or external services without explicit config and documentation.
- Treat local SQLite implementations as reference implementations, not as the only possible backends.
- Keep error messages useful, but avoid leaking raw sensitive values or secret material.
- Preserve a clean contributor path: format, clippy, tests, docs, and clear module boundaries.

## Module Changes

When editing a module under `crates/<module>`:

- Update the matching module doc in `docs/<module>.md` in the same change.
- Update `docs/README.md` if module responsibilities, pipeline position, or public commands change.
- Update `dam.example.toml` if configuration keys, defaults, or supported values change.
- Update `../RPBLC.Architecture` when an agreed design decision, implemented behavior, public interface, config key, failure mode, pipeline shape, or module boundary changes.
- Do not introduce direct cross-module calls that bypass `dam-core` contracts.

## Architecture Sync

`../RPBLC.Architecture` is the authoritative contract repo. Keep it current when design decisions are agreed in discussion and when behavior is implemented in code.

- Update the relevant architecture files in the same change as the DAM implementation whenever possible.
- If an architecture update is needed but cannot be completed in the same change, call it out explicitly before considering the work done.
- Do not let local DAM docs, README claims, config examples, or code behavior drift away from the architecture contracts.

## Tests

Every module change should include relevant tests.

- Keep existing unit tests passing.
- Add or update unit tests for changed behavior.
- Add edge-case coverage for boundary conditions, failure paths, invalid config, and privacy-sensitive behavior.
- For CLI or integration behavior, update tests under the consuming module, e.g. `crates/dam-filter/tests/`.
- For policy, vault, log, and redaction behavior, test that raw sensitive values are not persisted outside the vault.

## Verification

Before considering work complete, run:

```bash
cargo fmt --all --check
cargo clippy --workspace -- -D warnings
cargo test --workspace
```

If a command cannot be run, document why in the final response.

## Documentation Rule

Docs are part of the implementation. A module edit without corresponding docs and tests is incomplete unless the change is purely mechanical and does not affect behavior, config, contracts, or usage.
