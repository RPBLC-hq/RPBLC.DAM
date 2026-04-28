# dam-detect

`dam-detect` is a pure detection module.

It receives text and returns sensitive spans. It does not redact, write to vault, log, or decide policy.

## Current Coverage

- Email, including whitespace around separators such as `alice@ example.com` or `alice @example.com`.
- NANP phone numbers in dashed form, e.g. `415-555-2671`.
- SSN with basic area validation.
- Credit card numbers with Luhn validation.

Known current limitation: formats like `+1 (415) 555-2671` and zero-width-character obfuscation are not detected yet.

## Output

The module returns `Vec<Detection>`:

```rust
Detection {
    kind,
    span,
    value,
}
```

The raw `value` is required downstream for tokenization, but it must not be persisted outside the vault.

## Architecture Rules

- Detection modules only emit candidates.
- No vault calls.
- No redaction.
- No policy decisions.
- No persistent logging.

Future multiple-detector orchestration should happen through the spine/pipeline, not inside individual detectors.

## Tests

```bash
cargo test -p dam-detect
```
