# Locale Pattern Reference

DAM's detection pipeline uses locale-based pattern modules. Each locale contributes its own set of regex patterns for PII detection.

## Locale Status

| Locale | Code | Status | Doc |
|--------|------|--------|-----|
| Global | `global` | Implemented | [global.md](global.md) |
| United States | `us` | Implemented | [us.md](us.md) |
| Canada | `ca` | Placeholder | [ca.md](ca.md) |
| United Kingdom | `uk` | Placeholder | — |
| France | `fr` | Placeholder | — |
| Germany | `de` | Placeholder | — |
| Japan | `jp` | Placeholder | — |
| South Korea | `kr` | Placeholder | — |
| India | `in` | Placeholder | — |
| China | `cn` | Placeholder | — |

## Adding a New Locale

1. Create `crates/dam-detect/src/locales/xx.rs` with a `pub(crate) fn patterns() -> Vec<Pattern>` function
2. Add `mod xx;` to `crates/dam-detect/src/locales/mod.rs`
3. Add the match arm in `build_patterns()` to dispatch to `xx::patterns()`
4. Create `docs/locales/xx.md` documenting each pattern (regex, PiiType, confidence, validator, examples)
5. Update this README table with the new locale status

## Pattern Classification

- **Global**: Patterns that are not specific to any country (email, credit card, international phone, IPv4, DOB)
- **Locale-specific**: Patterns tied to a particular country's formats (US SSN, US phone, Canadian SIN, etc.)
