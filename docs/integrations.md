# Integrations

DAM supports two integration styles:

- **HTTP proxy (primary)** — strongest privacy boundary (PII redacted before upstream call)
- **MCP server (supplementary)** — tool access from agent runtimes

## HTTP proxy routes

| Route | Format | Default upstream |
|---|---|---|
| `POST /v1/messages` | Anthropic Messages | `https://api.anthropic.com` |
| `POST /v1/chat/completions` | OpenAI Chat Completions | `https://api.openai.com` |
| `POST /v1/responses` | OpenAI Responses | `https://api.openai.com` |
| `POST /codex/responses` | Codex Responses | `https://chatgpt.com/backend-api` |

Also available:
- `GET /healthz`
- `GET /readyz`

## MCP server setup

### Claude Code (`.mcp.json` or `~/.claude/mcp.json`)

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

### Codex (`~/.codex/config.toml`)

```toml
[mcp_servers.dam]
command = "dam"
args = ["mcp"]
```

### OpenClaw (`mcp_config.json`)

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

## MCP tools exposed

| Tool | Purpose |
|---|---|
| `dam_scan` | Scan text for PII and return redacted output |
| `dam_resolve` | Resolve refs for action execution (consent-checked) |
| `dam_consent` | Grant/revoke consent for ref/accessor/purpose |
| `dam_vault_search` | Search vault by type (returns refs, not values) |
| `dam_status` | Vault stats and recent activity summary |
| `dam_reveal` | Emergency override reveal (always audited) |
| `dam_compare` | Derived compare operation without direct reveal |
