# Integrations

DAM supports two integration styles:

- **HTTP proxy (primary)** — strongest privacy boundary (PII redacted before upstream call)
- **MCP server (supplementary)** — tool access from agent runtimes

## Install

### npm (recommended)

```bash
npm install -g @rpblc/dam
```

### From source

```bash
cargo install --path crates/dam-cli
```

### One-line agent install

```bash
npx @rpblc/dam daemon install
```

This downloads the binary, registers DAM as an OS service, starts it, and verifies health — all in one command.

## Daemon setup

`dam daemon` manages DAM as a persistent background service that auto-starts on login and restarts on crash.

```bash
dam daemon install [--port 7828]   # Register + start as OS service
dam daemon uninstall               # Stop + remove service
dam daemon start                   # Start registered service
dam daemon stop                    # Stop running service
dam daemon status                  # Show service status
```

### Platform backends

| Platform | Backend | Service file |
|----------|---------|-------------|
| Linux | systemd user unit | `~/.config/systemd/user/dam.service` |
| macOS | launchd user agent | `~/Library/LaunchAgents/dev.rpblc.dam.plist` |
| Windows | Registry Run key + detached process | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` |

All backends are user-level — no root/admin required.

### Linux notes

- Enable linger for the service to survive logout: `loginctl enable-linger $USER`

### macOS notes

- Logs are written to `~/.dam/dam.stdout.log` and `~/.dam/dam.stderr.log`
- The service restarts on crash but not on clean exit

### Windows notes

- The service spawns as a detached process with no console window
- PID is tracked via `~/.dam/dam.pid`

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
