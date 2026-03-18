# Canada Patterns

Canada-specific PII detection patterns.

## Social Insurance Number (SIN)

- **PiiType**: `Sin`
- **Confidence**: 0.85
- **Regex**: `\b\d{3}[-\s]?\d{3}[-\s]?\d{3}\b`
- **Validator**: `validate_luhn_sin` — Luhn checksum + 9 digits + first digit not 0 or 8
- **Examples**: `130-692-544`, `130 692 544`, `130692544`
- **Rejected**: SINs starting with 0 (not issued), starting with 8 (reserved), or failing Luhn checksum

## Postal Code

- **PiiType**: `PostalCode`
- **Confidence**: 0.80
- **Regex**: `(?i)\b[ABCEGHJ-NPRSTVXY]\d[ABCEGHJ-NPRSTV-Z][\s-]?\d[ABCEGHJ-NPRSTV-Z]\d\b` (case-insensitive)
- **Validator**: None (character class restrictions are sufficient)
- **Examples**: `K1A 0B1`, `V6B2W2`, `M5W-1E6`, `k1a 0b1`
- **Notes**: Canadian postal codes use alternating letter-digit format. Case-insensitive matching. Letters D, F, I, O, Q, U are never used. W and Z are not used as the first letter.
