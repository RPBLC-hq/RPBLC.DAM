# US Patterns

United States-specific PII patterns.

## Social Security Number (SSN)

- **PiiType**: `Ssn`
- **Confidence**: 0.9
- **Regex**: `\b(\d{3}[-\s]\d{2}[-\s]\d{4})\b`
- **Validator**: `validate_ssn`
  - Area (first 3 digits): cannot be `000`, `666`, or `900-999`
  - Group (middle 2 digits): cannot be `00`
  - Serial (last 4 digits): cannot be `0000`
- **Examples**: `123-45-6789`, `123 45 6789`
- **Not matched**: `123456789` (no separators), `000-12-3456` (invalid area)

## US Phone

- **PiiType**: `Phone`
- **Confidence**: 0.85
- **Regex**: `(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b`
- **Validator**: None
- **Examples**: `555-123-4567`, `(555) 123-4567`, `+1 555.123.4567`

## DEA Registration Number

- **PiiType**: `DeaNumber`
- **Confidence**: 0.88
- **Regex**: `(?i)\b[A-PR-VXYZ][A-Z9]\d{7}\b` (case-insensitive)
- **Validator**: `validate_dea_number` — check digit = `(d1 + d3 + d5 + 2*(d2 + d4 + d6)) % 10` must equal d7
- **Format**: 2-letter prefix + 7 digits = 9 characters. First letter indicates registrant type (A-P, R-V, X-Z); second letter is last-name initial or `9`.
- **Examples**: `AB1234563`
- **Rejected**: Numbers with wrong check digit, invalid first letter (Q not used), wrong length
- **Regulatory context**: Issued by the US Drug Enforcement Administration for controlled substance handling. Regulated under 21 CFR Part 1301.
