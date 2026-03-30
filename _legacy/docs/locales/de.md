# Germany Patterns

Germany-specific PII detection patterns.

## Personalausweis (National ID Card)

- **PiiType**: `NationalId`
- **Confidence**: 0.85
- **Regex**: `\b[CFGHJKLMNPRTVWXYZ][0-9CFGHJKLMNPRTVWXYZ]{8}\d\b`
- **Validator**: `validate_icao_check` — ICAO 9303 check digit with weights 7-3-1 repeating. Letters mapped A=10..Z=35.
- **Format**: 10-character ICAO Machine Readable Zone format. First character is a letter from a restricted set (excludes A, B, D, E, I, O, Q, S, U). Last digit is the check digit.
- **Examples**: `T220001293`
- **Rejected**: Numbers with invalid first character, wrong check digit, or wrong length
- **Regulatory context**: German identity card number. Protected under BDSG (Bundesdatenschutzgesetz) and EU GDPR. The Personalausweis is governed by the PAuswG (Personalausweisgesetz).

## Steuer-ID (Tax Identification Number)

- **PiiType**: `TaxId`
- **Confidence**: 0.85
- **Regex**: `\b[1-9]\d{10}\b`
- **Validator**: `validate_steuer_id` — validates 11-digit format with digit frequency check (exactly one digit appears 2 or 3 times in first 10 digits) and iterative product-sum check digit algorithm.
- **Format**: 11 digits, first digit not 0
- **Examples**: `65929970489`
- **Rejected**: Numbers starting with 0, failing digit frequency rules, or wrong check digit
- **Regulatory context**: Assigned by the Bundeszentralamt für Steuern (BZSt) to every person registered in Germany. Lifetime identifier for tax purposes. Protected under BDSG and EU GDPR, with specific provisions in the Abgabenordnung (AO).
