# dam-core

`dam-core` is the spine/contracts crate.

It owns shared types and coordination rules. Other modules may implement contracts, but they should not invent cross-module behavior outside `dam-core`.

## Responsibilities

- Shared detection types: `SensitiveType`, `Span`, `Detection`.
- Reference generation and parsing: base58-encoded 128-bit UUID, 22 characters.
- Vault write contract: `VaultWriter`.
- Vault read contract: `VaultReader`.
- Logging contract: `EventSink`.
- Policy action contract: `PolicyAction`.
- Replacement planning from `PolicyDecision` values.
- Non-sensitive operational log event creation.
- Resolve planning for `[kind:id]` references.
- Proxy log event types for forward, bypass, and failure states.

## Replacement Behavior

Policy action effects:

| Action | Vault Write | Replacement |
|---|---:|---|
| `tokenize` | yes | `[kind:id]` |
| `redact` | no | `[kind]` |
| `allow` | no | unchanged |
| `block` | no | no transformed output |

By default, replacement planning deduplicates repeated equal `(kind, action, value)` matches within one plan. Repeated tokenized values reuse the same `[kind:id]` reference and require one vault write. Set `policy.deduplicate_replacements = false` to generate separate references for each occurrence when equality leakage is a concern.

Vault write failure while tokenizing uses redact-only fallback:

```text
[email]
```

## Contracts

Implementations plug in through traits:

```rust
pub trait VaultWriter: Send + Sync {
    fn write(&self, record: &VaultRecord) -> Result<(), VaultWriteError>;
}

pub trait VaultReader: Send + Sync {
    fn read(&self, reference: &Reference) -> Result<Option<String>, VaultReadError>;
}

pub trait EventSink: Send + Sync {
    fn record(&self, event: &LogEvent) -> Result<(), LogWriteError>;
}
```

## Resolve Behavior

`dam-core` parses only valid tokenized references:

```text
[email:7B2HkqFn9xR4mWpD3nYvKt]
```

Redact-only placeholders such as `[email]`, unknown kinds, and malformed IDs are ignored.

Known references become replacements with the original value. Missing references and read failures stay unchanged unless a caller chooses strict failure behavior.

## Privacy Rules

- Log events must not contain raw detected values.
- References may be logged after successful vault writes.
- Current `--report` output may show short local previews for manual verification; persisted logs do not.

## Log Event Types

Current event types:

- `detection`
- `policy_decision`
- `vault_write`
- `vault_write_failed`
- `vault_read`
- `vault_read_failed`
- `redaction`
- `resolve`
- `proxy_forward`
- `proxy_bypass`
- `proxy_failure`

## Tests

```bash
cargo test -p dam-core
```
