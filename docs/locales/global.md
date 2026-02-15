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
- **Validator**: Luhn checksum (`validate_luhn`)
- **Examples**: `4111 1111 1111 1111`, `3782-822463-10005`

## International Phone

- **PiiType**: `Phone`
- **Confidence**: 0.9
- **Regex**: `\+\d{1,3}[-.\s]?\d{1,4}[-.\s]?\d{3,4}[-.\s]?\d{3,4}\b`
- **Validator**: None
- **Examples**: `+44 20 7946 0958`, `+81-3-1234-5678`

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
