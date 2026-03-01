# Singapore Patterns

Singapore-specific PII detection patterns.

## NRIC/FIN (National Registration Identity Card)

- **PiiType**: `Nric`
- **Confidence**: 0.97
- **Regex**: `(?i)\b[STFGM]\d{7}[A-Z]\b` (case-insensitive)
- **Validator**: `validate_nric` — MOD-11 weighted checksum with series-specific lookup tables. Weights [2,7,6,5,4,3,2] applied to the 7 digits; offset added for T/G/M series; check letter looked up from a per-series table (11 entries each).
- **Format**: 1 prefix letter + 7 digits + 1 check letter = 9 characters
- **Series**:
  - `S` — citizens/PRs born before 2000
  - `T` — citizens/PRs born 2000 onwards (offset +4)
  - `F` — foreigners issued before 2000
  - `G` — foreigners issued 2000 onwards (offset +4)
  - `M` — recent work pass holders (offset +3)
- **Examples**: `S1234567D`, `T1234567G`, `F1234567N`, `G1234567R`, `M1234567X`
- **Rejected**: Numbers with wrong check letter for their series, wrong length
- **Regulatory context**: Issued by the Immigration & Checkpoints Authority (ICA). Protected under Singapore's Personal Data Protection Act (PDPA).
