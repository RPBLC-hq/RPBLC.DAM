# dam-redact

`dam-redact` is a pure text replacement module.

It applies a replacement plan to input text.

## Responsibility

Input:

- Original text.
- Ordered replacement spans and replacement strings.

Output:

- Transformed text.

## Architecture Rules

- No detection.
- No policy.
- No vault calls.
- No logging.
- No reference generation.

`dam-redact` should remain boring. The spine decides what replacements exist; this module only applies them safely.

## Span Handling

Replacements are applied from the end of the string toward the beginning so earlier replacements do not shift later spans.

## Tests

```bash
cargo test -p dam-redact
```
