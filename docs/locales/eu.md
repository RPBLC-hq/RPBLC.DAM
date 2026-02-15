# EU Patterns

EU-wide PII detection patterns not specific to any single member state.

## EU VAT Identification Number

- **PiiType**: `VatNumber`
- **Confidence**: 0.85
- **Regex**: `\b(?:AT|BE|BG|CY|CZ|DE|DK|EE|EL|ES|FI|FR|HR|HU|IE|IT|LT|LU|LV|MT|NL|PL|PT|RO|SE|SI|SK)[A-Z0-9]{2,13}\b`
- **Validator**: `validate_eu_vat` — country-specific format and length validation for all 27 EU member states. Checks digit/letter composition per country rules.
- **Format**: 2-letter country prefix + country-specific body (varies from 4 to 15 total characters)
- **Examples**: `DE123456789` (Germany), `ATU12345678` (Austria), `FR12345678901` (France), `NL123456789B01` (Netherlands)
- **Rejected**: Unknown country prefixes (including GB post-Brexit), wrong body length for the given country, invalid character types
- **Regulatory context**: VAT identification numbers are issued under the EU VAT Directive (2006/112/EC). They are business identifiers but can identify sole traders (natural persons) and are therefore PII under GDPR Article 4(1).

### Supported countries

AT, BE, BG, CY, CZ, DE, DK, EE, EL (Greece), ES, FI, FR, HR, HU, IE, IT, LT, LU, LV, MT, NL, PL, PT, RO, SE, SI, SK.

Note: GB (United Kingdom) is excluded as it is no longer part of the EU VAT system post-Brexit.

## SWIFT/BIC Code

- **PiiType**: `SwiftBic`
- **Confidence**: 0.80
- **Regex**: `\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b`
- **Validator**: `validate_swift_bic` — validates 8 or 11 character format: 4-letter bank code + 2-letter ISO 3166-1 country code + 2-char location code + optional 3-char branch code. Country code must be a valid ISO 3166-1 alpha-2 code.
- **Format**: 8 characters (head office) or 11 characters (specific branch)
- **Examples**: `DEUTDEFF` (Deutsche Bank Frankfurt), `BNPAFRPP` (BNP Paribas), `CHASUS33` (JPMorgan Chase)
- **Rejected**: Codes with invalid country codes, wrong total length (not 8 or 11), or digits in the bank code portion
- **Regulatory context**: SWIFT/BIC codes identify financial institutions and are used in international wire transfers. While primarily institutional identifiers, they appear alongside personal financial data and are relevant for PII detection in financial contexts. Governed by ISO 9362.
