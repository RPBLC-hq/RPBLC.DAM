# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in DAM, please report it responsibly.

**Email**: [contact@rpblc.com](mailto:contact@rpblc.com)

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

## Response Timeline

- **Acknowledgement**: within 48 hours
- **Initial assessment**: within 7 days
- **Fix timeline**: within 90 days for confirmed vulnerabilities

## Embargo

We ask that you do not publicly disclose the vulnerability until we have released a fix or 90 days have passed since the initial report, whichever comes first.

## Scope

The following areas are in scope for security reports:

- **Encryption**: vault encryption bypass, key leakage, weak cryptographic practices
- **Vault access**: unauthorized PII retrieval, consent bypass
- **Audit trail**: hash chain tampering, log forgery, audit bypass
- **Detection bypass**: techniques that reliably evade PII detection
- **Reference collisions**: predictable or brute-forceable reference IDs
- **Proxy security**: header leakage, request/response manipulation, PII passthrough

## Out of Scope

- Vulnerabilities in upstream dependencies (report these to the dependency maintainer; we will update promptly)
- Attacks requiring local root/admin access (DAM trusts the local OS)
- Social engineering
- Denial of service against the local proxy

## Safe Harbor

We will not pursue legal action against security researchers who:
- Act in good faith and follow this disclosure policy
- Avoid accessing or modifying other users' data
- Do not degrade the service for others

Thank you for helping keep DAM and its users safe.
