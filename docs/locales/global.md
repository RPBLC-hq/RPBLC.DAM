# Global Patterns

Patterns that apply regardless of locale selection. These detect PII formats that are not specific to any single country.

## Email

- **PiiType**: `Email`
- **Confidence**: 0.95
- **Regex**: `[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`
- **Validator**: None
- **Examples**: `john@example.com`, `alice+tag@test.org`

## Credit Card

- **PiiType**: `CreditCard`
- **Confidence**: 0.85
- **Regex**: `\b(\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}|\d{4}[-\s]?\d{6}[-\s]?\d{5})\b`
- **Validator**: Luhn checksum (`validate_luhn_cc`)
- **Examples**: `4111 1111 1111 1111`, `3782-822463-10005`

## International Phone (E.164)

- **PiiType**: `Phone`
- **Confidence**: 0.9
- **Regex**: `\+[1-9]\d{6,14}\b` (strict E.164: + followed by 7-15 digits, first digit non-zero)
- **Validator**: None
- **Examples**: `+442079460958`, `+818312345678`

## IPv4 Address

- **PiiType**: `IpAddress`
- **Confidence**: 0.8
- **Regex**: `\b((?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.…)\b` (full octet validation)
- **Validator**: `validate_ip` — excludes loopback, broadcast, private, and link-local ranges
- **Examples**: `8.8.8.8`, `203.0.113.1`
- **Excluded**: `127.0.0.1`, `10.0.0.1`, `192.168.1.1`, `169.254.x.x`

## Date of Birth

- **PiiType**: `DateOfBirth`
- **Confidence**: 0.5 (low — needs surrounding context for reliable detection)
- **Regex**: `\b(\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4})\b`
- **Validator**: None
- **Examples**: `01/15/1990`, `3-7-85`

## IBAN

- **PiiType**: `Iban`
- **Confidence**: 0.90
- **Regex**: `\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b`
- **Validator**: `validate_iban` — format check (2 letters + 2 check digits + 11-30 alphanumeric), country-specific length table, MOD 97-10 checksum
- **Examples**: `DE89370400440532013000`, `GB29NWBK60161331926819`, `FR7630006000011234567890189`
- **Notes**: IBAN regex only matches uppercase (normalization converts input to uppercase). Spaces and dashes are stripped before validation.
