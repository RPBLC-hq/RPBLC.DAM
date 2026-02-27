# PII Type Reference

Full reference for all built-in `PiiType` variants. Keep this file in sync when adding new types (see [AGENTS.md](../AGENTS.md)).

Types are organized by category. The **tag** column shows the short form used in references like `[email:a3f71bc9]`.

---

## Personal

| Type | Tag | Description | Locale | Validator |
|------|-----|-------------|--------|-----------|
| `Email` | `email` | Email address | Global | — |
| `Phone` | `phone` | International phone (E.164) + NANP with parens | Global + US | Length/format |
| `DateOfBirth` | `dob` | Date in `DD/MM/YYYY`, `MM-DD-YY`, etc. | Global | — |
| `Name` | `name` | Person name *(Phase 2 NER — not yet active)* | Global | — |
| `Address` | `addr` | Physical address *(Phase 2 NER — not yet active)* | Global | — |
| `Organization` | `org` | Organization name *(Phase 2 NER — not yet active)* | Global | — |
| `Location` | `loc` | Geographic location *(Phase 2 NER — not yet active)* | Global | — |

---

## Financial

| Type | Tag | Description | Locale | Validator |
|------|-----|-------------|--------|-----------|
| `CreditCard` | `cc` | Credit/debit card number (13–19 digits, common formats) | Global | Luhn |
| `Iban` | `iban` | International Bank Account Number | Global | Mod97 |
| `BankAccount` | `bank_acct` | UK sort code + 8-digit account pair (`XX-XX-XX XXXXXXXX`) | UK | Prefix + structure |

---

## National IDs & Government Documents

| Type | Tag | Description | Locale | Validator |
|------|-----|-------------|--------|-----------|
| `Ssn` | `ssn` | US Social Security Number | US | Area/group rules |
| `Sin` | `sin` | Canadian Social Insurance Number | Canada | Luhn |
| `PostalCode` | `postal` | Canadian postal code (`A1A 1A1`) | Canada | — |
| `NiNumber` | `ni` | UK National Insurance number | UK | Prefix exclusion list |
| `NhsNumber` | `nhs` | UK NHS number (10 digits) | UK | Mod11 |
| `DriversLicense` | `dl` | UK DVLA driving licence (16 chars) | UK | Date/gender encoding |
| `InseeNir` | `nir` | French INSEE/NIR social security number | France | — |
| `NationalId` | `natid` | German Personalausweis (ICAO format) | Germany | ICAO check digit |
| `TaxId` | `taxid` | German Steuer-Identifikationsnummer | Germany | — |
| `VatNumber` | `vat` | EU VAT number (country-specific formats) | EU | Country prefix + length |
| `SwiftBic` | `swift` | SWIFT/BIC bank identifier code | EU | — |
| `PassportMrz` | `mrz` | Passport Machine Readable Zone — TD3 two-line format (44 chars/line) | Global | — |

---

## Digital Secrets & Credentials

| Type | Tag | Description | Locale | Validator |
|------|-----|-------------|--------|-----------|
| `JwtToken` | `jwt` | JSON Web Token — `eyJ…`.`eyJ…`.`…` (three base64url segments) | Global | — |
| `AwsKey` | `aws_key` | AWS access key ID — `AKIA` + 16 uppercase alphanumeric | Global | — |
| `AwsArn` | `aws_arn` | AWS resource name — `arn:aws:<service>:<region>:<account>:<resource>` | Global | — |
| `GitHubToken` | `gh_token` | GitHub token — `gh[pousr]_` + 36+ alphanumeric | Global | — |
| `StripeKey` | `stripe_key` | Stripe API key (`sk_/pk_live/test_…`) or object ID (`cus_/tok_/pm_/src_/sub_/card_…`) | Global | — |
| `ApiKey` | `api_key` | Generic API key — Google (`AIza…`), Slack (`xox[baprs]-…` / webhook), SendGrid (`SG.…`), npm (`npm_…`), Mailgun (`key-…`), Twilio (`SK…`) | Global | — |
| `LlmApiKey` | `llm_key` | LLM provider API key — Anthropic (`sk-ant-api…`), OpenAI (`sk-…` / `sk-proj-…` / `sk-svcacct-…`), Hugging Face (`hf_…`), Replicate (`r8_…`), xAI (`xai-…`), Groq (`gsk_…`), Perplexity (`pplx-…`) | Global | — |
| `PrivateKey` | `priv_key` | PEM-encoded private key — RSA, EC, or OpenSSH (`-----BEGIN … PRIVATE KEY-----`) | Global | — |
| `CredentialUrl` | `cred_url` | URL with embedded credentials — `postgres://user:pass@host` or `https://user:pass@host` | Global | — |

---

## Cryptocurrency

| Type | Tag | Description | Locale | Validator |
|------|-----|-------------|--------|-----------|
| `CryptoWallet` | `wallet` | Bitcoin legacy (P2PKH/P2SH, base58), Bitcoin bech32 (`bc1…`), or Ethereum (`0x` + 40 hex) | Global | — |

---

## Network

| Type | Tag | Description | Locale | Validator |
|------|-----|-------------|--------|-----------|
| `IpAddress` | `ip` | Public IPv4 address (private/loopback filtered) | Global | Public range check |
| `IPv6Address` | `ipv6` | IPv6 — fully-expanded 8-group form (loopback/link-local/multicast filtered) | Global | Not reserved |
| `MacAddress` | `mac` | MAC/hardware address — colon or hyphen separated (broadcast/unspecified filtered) | Global | Not broadcast |

---

## Logistics

| Type | Tag | Description | Locale | Validator |
|------|-----|-------------|--------|-----------|
| `UpsTracking` | `ups` | UPS shipment tracking number — `1Z` + 16 uppercase alphanumeric | Global | — |

---

## Custom

| Type | Tag | Description |
|------|-----|-------------|
| `Custom` | `custom` | User-defined pattern from `[detection.custom_rules]` in config |

Custom patterns are defined in `~/.dam/config.toml`:

```toml
[detection.custom_rules.employee_id]
pattern = "EMP-\\d{6}"
pii_type = "custom"
description = "Internal employee ID"
```

---

## Adding a New PII Type

1. Add variant to `PiiType` enum in `crates/dam-core/src/pii_type.rs`
2. Add `tag()`, `Display`, `FromStr`, `from_tag()`, and `all()` entries for the variant
3. Add regex `Pattern` to the appropriate locale file in `crates/dam-detect/src/locales/`
4. If a checksum or structural validator is needed, add it to `crates/dam-detect/src/validators.rs`
5. Add unit tests in the locale's `#[cfg(test)]` module and/or in `stage_regex.rs`
6. Update this file (`docs/pii-types.md`) with the new type
7. Add a `CHANGELOG.md` entry under `[Unreleased]`

See `docs/ARCHITECTURE.md` for the full detection pipeline.
