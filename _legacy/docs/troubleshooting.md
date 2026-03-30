# Troubleshooting

## Fast checks

1. `dam status --json`
2. `dam health --port 7828 --json`
3. `dam config validate --json`

## Common issues

### 1) Request not reaching provider
- Verify route and upstream config (`dam config get server.openai_upstream_url` etc.)
- Check auth header was sent by client
- If using `X-DAM-Upstream`, verify it passes validation rules

### 2) Unexpected unresolved refs in response
- Confirm refs were minted in that request flow (detokenization is allowlist-scoped)
- Verify vault entry still exists and not expired

### 3) Readiness failing (`/readyz`)
- Verify vault path exists and process can read/write DB file
- Check filesystem permissions and lock contention

### 4) CI/lint failures
- Run format/lint locally before pushing:
  - `cargo fmt --all --check`
  - `cargo test --workspace`

### 5) Consent behavior not matching expectation
- Confirm `server.consent_passthrough` setting
- Inspect consent rules via CLI and audit logs
