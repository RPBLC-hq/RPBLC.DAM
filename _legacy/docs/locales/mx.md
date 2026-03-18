# Mexico Patterns

Mexico-specific PII detection patterns.

## CURP (Clave Única de Registro de Población)

- **PiiType**: `Curp`
- **Confidence**: 0.95
- **Regex**: `(?i)\b[A-Z][AEIOU][A-Z]{2}\d{6}[HM][A-Z]{2}[A-Z]{3}[0-9A-Z]\d\b` (case-insensitive)
- **Validator**: `validate_curp` — position-weighted sum using the CURP alphabet (0-9, then A-Z with Ñ between N and O); check digit = `(10 - sum % 10) % 10`
- **Format**: 18 characters — surname initial(1) + first vowel(1) + surname initial(1) + given name initial(1) + birth date YYMMDD(6) + sex H/M(1) + state(2) + consonants(3) + disambiguator(1) + check digit(1)
- **Examples**: `AAEA010101HDFFFF01`
- **Rejected**: Numbers with wrong check digit, wrong length
- **Regulatory context**: Mexico's unique population registry key, issued by RENAPO. Protected under Mexico's LFPDPPP (Ley Federal de Protección de Datos Personales en Posesión de los Particulares).
