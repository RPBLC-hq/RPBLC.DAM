# dam-policy

`dam-policy` maps detections to actions.

It separates "what was found" from "what should happen."

## Actions

| Action | Meaning |
|---|---|
| `tokenize` | Store original in vault, replace text with `[kind:id]`. |
| `redact` | Do not store original, replace text with `[kind]`. |
| `allow` | Do not store original, leave text unchanged. |
| `block` | Do not store original, fail the operation before output. |

## Current Implementation

`StaticPolicy` supports:

- One default action.
- Optional per-kind overrides.

Example:

```toml
[policy]
default_action = "tokenize"
deduplicate_replacements = true

[policy.kind.ssn]
action = "redact"

[policy.kind.cc]
action = "redact"
```

`deduplicate_replacements` is consumed by replacement planning, not by `dam-policy` itself. It defaults to `true`; set it to `false` to avoid reusing the same token reference for repeated equal values.

## Responsibilities

- Read detections.
- Return `PolicyDecision` values.
- No vault writes.
- No text mutation.
- No raw value logging.

## Failure Behavior

`block` is enforced by `dam-filter` before vault writes. The current CLI exits non-zero and writes no transformed output.

## Tests

```bash
cargo test -p dam-policy
```
