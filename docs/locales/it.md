# Italy Patterns

Italy-specific PII detection patterns.

## Codice Fiscale

- **PiiType**: `CodiceFiscale`
- **Confidence**: 0.95
- **Regex**: `(?i)\b[A-Z]{6}\d{2}[ABCDEHLMPRST]\d{2}[A-Z]\d{3}[A-Z]\b` (case-insensitive)
- **Validator**: `validate_codice_fiscale` — odd/even position lookup tables with different value mappings; check letter = `'A' + (sum % 26)`
- **Format**: surname(3) + name(3) + birth year(2) + month letter(1) + birth day(2) + municipality(4) + check letter(1) = 16 characters
- **Month letters**: A=Jan, B=Feb, C=Mar, D=Apr, E=May, H=Jun, L=Jul, M=Aug, P=Sep, R=Oct, S=Nov, T=Dec
- **Examples**: `RSSMRA85T10A562S` (Mario Rossi, born 10 Nov 1985, Rome)
- **Rejected**: Numbers with wrong check letter, invalid month letter, wrong length
- **Regulatory context**: Italy's primary personal identification code, issued by the Agenzia delle Entrate. Protected under Italian privacy law (D.Lgs. 196/2003) and EU GDPR.
