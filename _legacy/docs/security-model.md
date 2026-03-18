# Security Model

## Proxy vs MCP security boundary

| | HTTP Proxy | MCP Tools |
|---|---|---|
| PII reaches remote LLM | **No** (redacted before outbound) | **Yes** (LLM can already see input context) |
| Depends on LLM compliance | No | Yes |
| Default usage | Primary protection path | Supplementary tooling |
| Best for | Redaction + response rehydration | Vault/consent operations |

## Core guarantees

- Outbound PII redaction happens locally.
- Vault values are encrypted at rest (envelope crypto).
- Detokenization is scoped to refs minted during current request flow.
- Consent passthrough is configurable; strict redaction default is `false` passthrough.
- Sensitive operations are auditable.

## Practical guidance

- Use **proxy mode** for normal model traffic.
- Use **MCP mode** for operational tool workflows.
- Treat MCP tool calls as privileged operations, not primary shielding.
