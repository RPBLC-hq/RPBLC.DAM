# Upstream Routing

`X-DAM-Upstream` allows per-request upstream selection when multiple providers share request formats.

Rules:
- `http://` and `https://` only
- no credentials (`@`), query string (`?`), or fragment (`#`)
- trailing slashes are normalized
- absent/empty header uses configured defaults

Use cases:
- OpenAI-compatible multi-provider routing (OpenAI, xAI, gateways)
- temporary failover during provider incidents
