# United Kingdom Patterns

UK-specific PII detection patterns.

## National Insurance Number (NI Number)

- **PiiType**: `NiNumber`
- **Confidence**: 0.90
- **Regex**: `\b[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]\d{6}[A-D]\b`
- **Validator**: `validate_ni_prefix` — excludes invalid prefixes (BG, GB, NK, KN, TN, NT, ZZ) and invalid first letters (D, F, I, Q, U, V)
- **Examples**: `AB123456C`, `CE654321D`
- **Rejected**: Numbers with excluded prefix pairs or first letters not issued by HMRC
- **Regulatory context**: Used for tax and National Insurance contributions (HMRC). Protected under UK Data Protection Act 2018.

## NHS Number

- **PiiType**: `NhsNumber`
- **Confidence**: 0.90
- **Regex**: `\b\d{3}[-\s]?\d{3}[-\s]?\d{4}\b`
- **Validator**: `validate_nhs_mod11` — MOD 11 weighted check digit (weights 10,9,8,...,2). Check digit of 10 means invalid.
- **Examples**: `943 476 5919`, `9434765919`
- **Rejected**: Numbers failing the MOD 11 check
- **Regulatory context**: Used by NHS England, Wales, and Isle of Man for patient identification. Special category data under UK GDPR (health data).

## Driving Licence (DVLA)

- **PiiType**: `DriversLicense`
- **Confidence**: 0.85
- **Regex**: `\b[A-Z9]{5}\d{6}[A-Z9]{2}[A-Z0-9]{3}\b`
- **Validator**: `validate_dvla_license` — validates 16-char format: surname(5) + date-of-birth encoding(6) + initials(2) + check(3). Month values 51-62 indicate female licence holders.
- **Examples**: `MORGA657054SM9IJ`, `SMITH701010JJ9AA`
- **Rejected**: Numbers with invalid month (>12 and not 51-62), invalid day (0 or >31), wrong length
- **Notes**: UK driving licences encode the holder's surname and date of birth directly. The '9' character is used as padding in the surname and initials fields.
