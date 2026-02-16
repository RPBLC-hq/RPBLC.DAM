# Locale Pattern Reference

DAM's detection pipeline uses locale-based pattern modules. Each locale contributes its own set of regex patterns for PII detection.

## Locale Status

| Locale | Code | Doc |
|--------|------|-----|
| Global | `global` | [global.md](global.md) |
| United States | `us` | [us.md](us.md) |
| Canada | `ca` | [ca.md](ca.md) |
| EU | `eu` | [eu.md](eu.md) |
| United Kingdom | `uk` | [uk.md](uk.md) |
| France | `fr` | [fr.md](fr.md) |
| Germany | `de` | [de.md](de.md) |

## Adding a New Locale

1. Create `crates/dam-detect/src/locales/xx.rs` with a `pub(crate) fn patterns() -> Vec<Pattern>` function
2. Add `mod xx;` to `crates/dam-detect/src/locales/mod.rs`
3. Add the match arm in `build_patterns()` to dispatch to `xx::patterns()`
4. Add the variant to `Locale` enum in `crates/dam-core/src/locale.rs` (including `label()`, `selectable()`, `all()`, `Display`, `FromStr`)
5. Create `docs/locales/xx.md` documenting each pattern (regex, PiiType, confidence, validator, examples)
6. Update this README table with the new locale status

## Pattern Classification

- **Global**: Patterns that are not specific to any country (email, credit card, international phone, IPv4, DOB, IBAN)
- **Locale-specific**: Patterns tied to a particular country's formats (US SSN, Canadian SIN, UK NI number, etc.)
