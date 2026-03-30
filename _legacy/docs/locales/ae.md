# UAE Patterns

UAE-specific PII detection patterns.

## Emirates ID

- **PiiType**: `EmiratesId`
- **Confidence**: 0.97
- **Regex**: `\b784[-\s]?\d{4}[-\s]?\d{7}[-\s]?\d\b`
- **Validator**: `validate_emirates_id` — Luhn checksum on all 15 digits after stripping separators
- **Format**: `784-YYYY-NNNNNNN-C` (15 digits total). `784` is the UAE country code, `YYYY` is birth year, followed by a 7-digit sequence and 1 Luhn check digit. Hyphens and spaces are optional separators.
- **Examples**: `784-1234-1234567-2`, `784123412345672`
- **Rejected**: Numbers failing Luhn checksum, wrong digit count
- **Regulatory context**: National identity number issued by the Federal Authority for Identity and Citizenship (ICA). Protected under UAE Federal Decree-Law No. 45/2021 on personal data protection.
