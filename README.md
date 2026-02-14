# RPBLC DAM

**PII firewall for AI agents.** DAM intercepts personal data before it enters LLM context windows, replaces it with typed references, and resolves them only when needed — with consent.

## Quick Start

```bash
# Install
cargo install --path crates/dam-cli

# Initialize (creates vault, stores encryption key in OS keychain)
dam init

# Scan text for PII
dam scan "Email me at john@acme.com, SSN 123-45-6789"
# Output: Email me at [email:a3f71bc9], SSN [ssn:b2c81e4f]

# View vault entries
dam vault list

# Decrypt a specific entry
dam vault show email:a3f71bc9

# Grant consent for a tool to access PII
dam consent grant email:a3f71bc9 claude send_email

# View audit trail
dam audit
```

## How It Works

1. **Scan**: Text is scanned for PII using regex patterns (emails, phones, SSNs, credit cards, IPs)
2. **Encrypt**: Each detected value is encrypted with AES-256-GCM envelope encryption and stored in a local SQLite vault
3. **Replace**: Original values are replaced with typed references like `[email:a3f71bc9]`
4. **Resolve**: When an action needs real values, consent is checked before decryption
5. **Audit**: Every operation is logged in a hash-chained audit trail

## MCP Integration

DAM runs as an MCP server, compatible with Claude Code, Codex, and OpenClaw.

After `dam init`, add to your agent's MCP config:

```json
{
  "mcpServers": {
    "dam": {
      "command": "dam",
      "args": ["mcp"]
    }
  }
}
```

The LLM gets 7 tools: `dam_scan`, `dam_resolve`, `dam_consent`, `dam_vault_search`, `dam_status`, `dam_reveal`, `dam_compare`.

## CLI Commands

| Command | Description |
|---------|-------------|
| `dam init` | Initialize vault and config |
| `dam mcp` | Start MCP server (stdio) |
| `dam scan <text>` | Scan text for PII |
| `dam vault list` | List vault entries |
| `dam vault show <ref>` | Decrypt and display entry |
| `dam vault delete <ref>` | Delete entry |
| `dam consent list` | List consent rules |
| `dam consent grant <ref> <accessor> <purpose>` | Grant consent |
| `dam consent revoke <ref> <accessor> <purpose>` | Revoke consent |
| `dam audit` | View audit trail |
| `dam config show` | Show configuration |
| `dam config set <key> <value>` | Update configuration |

## Security Model

- **Envelope encryption**: Per-entry DEK wrapped by KEK from OS keychain (DPAPI/Keychain/libsecret)
- **Consent-by-default-denied**: No PII resolution without explicit consent
- **Hash-chained audit**: Tamper-evident log of all operations
- **Deduplication**: Same value stored once, referenced by all occurrences
- **Zeroize**: Encryption keys cleared from memory after use

## Building

```bash
cargo build --release    # produces target/release/dam binary
cargo test --workspace   # run all tests
```

## License

RPBLC
