# Spain Patterns

Spain-specific PII detection patterns.

## NIF (Número de Identificación Fiscal)

- **PiiType**: `Nif`
- **Confidence**: 0.96
- **Regex**: `(?i)\b\d{8}[A-HJ-NP-TV-Z]\b` (case-insensitive)
- **Validator**: `validate_nif` — check letter = `TABLE[n % 23]` where TABLE = `TRWAGMYFPDXBNJZSQVHLCKE`
- **Format**: 8 digits + 1 check letter = 9 characters. Check letter excludes I, O, U.
- **Examples**: `12345678Z`
- **Rejected**: Numbers with wrong check letter, wrong length
- **Regulatory context**: Spain's primary tax identification number for citizens. Protected under Spain's LOPD-GDD and EU GDPR.

## NIE (Número de Identidad de Extranjero)

- **PiiType**: `Nie`
- **Confidence**: 0.96
- **Regex**: `(?i)\b[XYZ]\d{7}[A-HJ-NP-TV-Z]\b` (case-insensitive)
- **Validator**: `validate_nie` — substitute prefix X→0, Y→1, Z→2, then apply the same mod-23 table lookup as NIF
- **Format**: 1 prefix letter (X, Y, or Z) + 7 digits + 1 check letter = 9 characters
- **Examples**: `X1234567L`, `Y1234567X`, `Z1234567R`
- **Rejected**: Numbers with wrong check letter, invalid prefix
- **Regulatory context**: Identification number for foreigners in Spain. Protected under Spain's LOPD-GDD and EU GDPR.
