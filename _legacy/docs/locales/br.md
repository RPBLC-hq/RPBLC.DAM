# Brazil Patterns

Brazil-specific PII detection patterns.

## CPF (Cadastro de Pessoas Físicas)

- **PiiType**: `Cpf`
- **Confidence**: 0.97
- **Regex**: `\b\d{3}\.\d{3}\.\d{3}-\d{2}\b`
- **Validator**: `validate_cpf` — double MOD-11 check digits. First check digit computed from digits 1-9 with descending weights (10-2); second check digit from digits 1-10 with descending weights (11-2). All-same-digit numbers are rejected.
- **Format**: `NNN.NNN.NNN-DD` (11 digits with dots and dash separators)
- **Examples**: `123.456.789-09`
- **Rejected**: Numbers with wrong check digits, all-same-digit numbers (e.g., `111.111.111-11`, `000.000.000-00`)
- **Regulatory context**: Brazil's individual taxpayer registry number, issued by the Receita Federal. Protected under Brazil's LGPD (Lei Geral de Proteção de Dados).
