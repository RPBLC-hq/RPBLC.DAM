# DAM — Data Access Mediator

**The PII firewall for AI agents.**

Your data never leaves your machine. The LLM never sees it. Every access is logged.

```
  "Send the contract to john@acme.com        "Send the contract to [email:a3f71bc9]
   and CC sarah@corp.io,                       and CC [email:d4f82c19],
   charge card 4111-1111-1111-1111"  ──DAM──►  charge card [cc:b7e31a02]"

        What the user types                       What the LLM sees
```

DAM sits between your app and the LLM as a local proxy, intercepts PII before it leaves your machine, and replaces it with typed references. Originals stay encrypted in a local vault. When the LLM responds with references, DAM resolves them back — the user sees real data, the LLM never does.

## Install

```bash
npm install -g @rpblc/dam
```

## Quick Start

```bash
# Start the proxy
dam serve
export OPENAI_BASE_URL=http://127.0.0.1:7828/v1
export ANTHROPIC_BASE_URL=http://127.0.0.1:7828

# Or run as a background service (auto-starts on login, restarts on crash)
dam daemon install
```

No `dam init` needed — config, vault, and encryption keys are auto-created on first run.

## What It Does

| Stage | What happens |
|-------|-------------|
| **Detect** | Regex pipeline finds emails, phones, SSNs, credit cards, IPs, IBANs, and 15+ locale-specific patterns |
| **Encrypt** | Each value gets its own AES-256-GCM key (envelope encryption). Master key lives in your OS keychain |
| **Replace** | Values become typed references: `[email:a3f71bc9]`. The LLM knows the *type* but never the *value* |
| **Resolve** | When the LLM responds with references, DAM replaces them with real values before returning to the client |
| **Audit** | Every operation is logged in a SHA-256 hash-chained trail |

## Supported Routes

| Route | Format | Default upstream |
|-------|--------|-----------------|
| `POST /v1/messages` | Anthropic Messages | `https://api.anthropic.com` |
| `POST /v1/chat/completions` | OpenAI Chat | `https://api.openai.com` |
| `POST /v1/responses` | OpenAI Responses | `https://api.openai.com` |
| `POST /codex/responses` | Codex | `https://chatgpt.com/backend-api` |

## Agent Install (One Command)

```bash
npx @rpblc/dam daemon install
```

Downloads the binary, registers DAM as an OS service, starts it, and verifies health — all in one command. Supports Linux (systemd), macOS (launchd), and Windows (Registry Run key).

## CLI

```bash
dam serve [--port PORT]              Start HTTP proxy
dam daemon install|start|stop|status Manage background service
dam scan [TEXT]                      Scan text for PII
dam vault list|show|delete           Manage encrypted vault
dam consent grant|revoke|list        Control PII access consent
dam audit [--ref REF]                View audit trail
```

## PII Types

Email, credit card (Luhn), phone, IPv4, date of birth, IBAN, SSN, SIN, postal code, NI number, NHS number, driving licence, INSEE/NIR, tax ID, national ID, VAT number, SWIFT/BIC — plus custom regex patterns via config.

## Links

- [GitHub](https://github.com/RPBLC-hq/RPBLC.DAM)
- [Full Documentation](https://github.com/RPBLC-hq/RPBLC.DAM/tree/main/docs)
- [Changelog](https://github.com/RPBLC-hq/RPBLC.DAM/blob/main/CHANGELOG.md)

## License

Apache-2.0
