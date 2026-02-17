# Contributing to DAM

Thank you for your interest in contributing to DAM! This document explains how to get involved.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/<you>/RPBLC.DAM.git`
3. Create a branch: `git checkout -b your-feature`
4. Make your changes
5. Push and open a pull request against `main`

## Development Setup

Requires [Rust](https://rustup.rs/) 1.85+ (edition 2024) and a C compiler (for bundled SQLite).

```bash
cargo build                               # debug build
cargo test --workspace                    # all tests (must pass)
cargo clippy --workspace -- -D warnings   # lint (must pass, zero warnings)
cargo fmt --check                         # format (must pass)
```

All three checks must pass before a PR will be reviewed.

## Pull Request Process

1. Keep PRs focused — one feature or fix per PR
2. Add or update tests for your changes
3. Update documentation if you changed behavior (README, docs/, CLAUDE.md)
4. Write a clear PR description explaining what and why
5. Ensure CI passes (tests, clippy, fmt)

## Adding a New Locale

See [docs/locales/README.md](docs/locales/README.md) for the full guide. Summary:

1. Create `crates/dam-detect/src/locales/xx.rs` with patterns and validators
2. Add `mod xx;` and a match arm in `locales/mod.rs`
3. Add the locale variant to `Locale` enum in `dam-core/src/locale.rs`
4. Create `docs/locales/xx.md` documenting each pattern
5. Add tests — see `qa_european.rs` for the adversarial test template

## Adding a New PII Type

1. Add the variant to `PiiType` in `crates/dam-core/src/pii_type.rs`
2. Add `tag()` short form and `Display` long form
3. Add detection pattern in the appropriate locale module
4. Add a validator if the type has a checksum or structural rule
5. Update the PII detection table in README.md

## Code Style

- Follow existing patterns in the codebase
- Use `DamError` / `DamResult<T>` for error handling
- Prefer `?` propagation over `.unwrap()` in non-test code
- Use parameterized SQL queries (never string interpolation)
- Add `(?i)` flag on regex patterns containing letter ranges

## Commit Messages

- Use imperative mood: "Add feature" not "Added feature"
- First line under 72 characters
- Reference issue numbers where applicable: "Fix detection bypass (#123)"

## Reporting Issues

- Use the issue templates when available
- Include DAM version, OS, and steps to reproduce for bugs
- For security vulnerabilities, see [SECURITY.md](SECURITY.md)

## License

By contributing, you agree that your contributions will be licensed under the [Apache-2.0 License](LICENSE).
