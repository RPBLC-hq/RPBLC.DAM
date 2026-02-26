# Security Model

Core guarantees:
- Redaction happens locally before outbound requests.
- Raw values are stored encrypted in vault (envelope encryption).
- Response detokenization is scoped to refs minted during that request flow.
- Consent controls resolution behavior; strict redaction is default.
- Audit trails record sensitive actions.

Threat boundaries and caveats are maintained here instead of the README.
