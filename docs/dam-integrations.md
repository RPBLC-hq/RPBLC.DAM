# dam-integrations

`dam-integrations` defines known local harness profiles for the background DAM endpoint.

The first slice is intentionally descriptive and deterministic. It does not mutate harness config files, install system proxy settings, or write secrets. It tells `dam` and future installer/tray surfaces how a harness should point at the connected daemon.

## User Commands

```bash
dam integrations list
dam integrations show <profile>
dam connect --profile <profile>
```

`dam integrations list` shows known profiles. `dam integrations show` renders the base URL settings and command snippets for one profile. `dam connect --profile` applies the daemon-side defaults for profiles that need a specific provider/upstream.

Use `--json` on `list` or `show` for machine-readable profile data:

```bash
dam integrations list --json
dam integrations show codex-api --json
```

Use `--proxy-url` to render snippets for a non-default daemon endpoint:

```bash
dam integrations show anthropic --proxy-url http://127.0.0.1:7829
```

When `--proxy-url` is omitted, `dam` uses the connected daemon state if available. Otherwise it renders the default local endpoint `http://127.0.0.1:7828`.

## Current Profiles

| Profile | Purpose | Daemon target |
|---|---|---|
| `openai-compatible` | Generic OpenAI-compatible SDK or harness using `OPENAI_BASE_URL`. | OpenAI-compatible default upstream. |
| `anthropic` | Generic Anthropic-compatible harness using `ANTHROPIC_BASE_URL`. | Anthropic default upstream. |
| `claude-code` | Claude Code against a background DAM daemon. | Anthropic default upstream. |
| `codex-api` | Codex API-key mode against a background DAM daemon. | OpenAI-compatible default upstream. |
| `xai-compatible` | xAI as an OpenAI-compatible upstream. | `https://api.x.ai` through the OpenAI-compatible provider adapter. |

## Privacy Rules

Profiles must not contain raw sensitive values, provider API keys, auth headers, or vault values.

Profiles may contain:

- local DAM base URLs;
- provider names and upstream URLs;
- environment variable names;
- command-line flags;
- notes explaining where the harness should keep its own provider credentials.

## Current Limits

- Profiles are not yet applied by editing harness config files.
- No model discovery is performed.
- No system proxy, VPN/TUN, TLS interception, or WebSocket configuration is installed.
- One `dam connect --profile` command still starts one daemon target at a time.
