# dam-mcp

`dam-mcp` is the first local MCP server for agent-managed DAM operations.

It currently exposes consent tools over stdio:

- `dam_consent_list`
- `dam_consent_grant`
- `dam_consent_revoke`

`dam_consent_request` is parked until `dam-notify` exists.

## Stable Handles

Grant uses `vault_key`, not bracket display references:

```json
{
  "vault_key": "email:ANJFsZtLfEA9WeP3bZS8Nw",
  "ttl_seconds": 3600,
  "reason": "user approved sending this support address"
}
```

This avoids friction when `[email:...]` has been resolved inbound before the agent can call MCP.

## Usage

```bash
dam-mcp --config dam.toml
dam-mcp --db vault.db --consent-db consent.db
```

Claude/Codex MCP config can point at the installed binary:

```json
{
  "mcpServers": {
    "dam": {
      "command": "dam-mcp",
      "args": ["--config", "dam.toml"]
    }
  }
}
```

Write tools are enabled by default through:

```toml
[consent]
mcp_write_enabled = true
```

Set it to `false` to expose list-only behavior.
