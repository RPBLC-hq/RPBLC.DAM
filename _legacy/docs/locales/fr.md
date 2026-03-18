# France Patterns

France-specific PII detection patterns.

## INSEE/NIR (Numéro de Sécurité Sociale)

- **PiiType**: `InseeNir`
- **Confidence**: 0.90
- **Regex**: `\b[12]\d{2}(?:0[1-9]|1[0-2]|[2-9]\d)(?:\d{2}|2[AB])\d{3}\d{3}\d{2}\b`
- **Validator**: `validate_nir_key` — computes key = 97 - (first 13 digits mod 97). Handles Corsica départements 2A (→19) and 2B (→18) for numeric conversion.
- **Format**: sex(1) + year(2) + month(2) + département(2) + commune(3) + order(3) + key(2) = 15 characters
- **Examples**: `185057800608491` (male, born May 1985, dept 78)
- **Rejected**: Numbers with invalid sex digit (not 1 or 2), invalid month, or wrong key
- **Regulatory context**: France's primary social security identifier. Protected under CNIL regulations and RGPD (French GDPR implementation). The NIR is classified as sensitive by the CNIL and its use is restricted to specific purposes.

### Corsica handling

Départements 2A (Corse-du-Sud) and 2B (Haute-Corse) contain letters in positions 5-6. For the mod-97 key computation, 2A is replaced by 19 and 2B by 18 before numeric division.
