# dam-integrations

`dam-integrations` defines known local harness profiles for the background DAM endpoint and owns the deterministic apply/rollback engine behind those profiles.

The first slice is intentionally local and reversible. It does not install system proxy settings or write secrets. It tells `dam` and future installer/tray surfaces how a harness should point at the connected daemon, and it prepares safe file mutations with backup records when a profile has a known write path.

## User Commands

```bash
dam integrations list
dam integrations show <profile>
dam integrations apply <profile>
dam integrations apply <profile> --write
dam integrations rollback <profile>
dam profile status
dam profile set <profile>
dam profile clear
dam connect --profile <profile> --apply
dam connect --apply
```

`dam integrations list` shows known profiles. `dam integrations show` renders the base URL settings and command snippets for one profile. `dam connect --profile` applies the daemon-side defaults for profiles that need a specific provider/upstream. Add `--apply` to apply the profile target before connecting.

`dam profile set <id>` writes the active local harness profile under DAM's integration state directory. `dam profile status` reports the active profile, effective proxy URL, and apply state for the profile target. `dam connect --apply` uses the active profile when `--profile` is omitted.

`dam integrations apply` previews profile setup by default. Add `--write` to call the `dam-integrations` apply engine and write profile setup to a safe target with a rollback record:

- `codex-api` updates the Codex TOML config with the `dam_openai` provider and selects it as `model_provider`.
- `claude-code` updates Claude Code `settings.json` by setting `env.ANTHROPIC_BASE_URL`.
- Generic `openai-compatible`, `anthropic`, and `xai-compatible` profiles write a DAM-managed environment file that can be sourced or inspected.

Preview without writing:

```bash
dam integrations apply codex-api
```

Write the profile setup:

```bash
dam integrations apply codex-api --write
```

Override the target file for tests or non-standard installs:

```bash
dam integrations apply codex-api --write --target-path ./codex-test.toml
dam integrations apply claude-code --write --target-path ./.claude/settings.local.json
```

Rollback restores the last DAM-created backup for that profile:

```bash
dam integrations rollback codex-api
```

One-command setup and connect:

```bash
dam connect --profile claude-code --apply
dam profile set claude-code
dam connect --apply
```

All apply callers, including `dam integrations apply --write`, `dam connect --profile <id> --apply`, and `dam connect --apply` with an active profile, refuse to overwrite a target that DAM previously applied but that no longer matches DAM's desired content. Use `damctl integrations check <id>` to inspect that state, or `dam integrations rollback <id>` to restore the last DAM-created backup.

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

## Apply Contract

`dam-integrations` owns:

- active local profile state;
- default target path selection for known profiles;
- desired file content generation;
- dry-run planning;
- install-state inspection for `applied`, `needs_apply`, and `modified` profile targets;
- backup creation with unique backup directories;
- rollback record format written before target mutation so interrupted applies remain reachable;
- atomic target restore/write behavior using temporary files and rename where the filesystem supports it;
- rollback restore/delete behavior.

The `dam` binary owns the user command surface and supplies local environment context, including `DAM_STATE_DIR`, `HOME`, `CODEX_HOME`, and the effective proxy URL.

## Privacy Rules

Profiles must not contain raw sensitive values, provider API keys, auth headers, or vault values.

Profiles may contain:

- local DAM base URLs;
- provider names and upstream URLs;
- environment variable names;
- command-line flags;
- notes explaining where the harness should keep its own provider credentials.

## Current Limits

- `codex-api` and `claude-code` edit known harness config files directly with rollback records.
- Generic profiles write DAM-managed environment files rather than mutating shell or unknown harness config.
- No model discovery is performed.
- No system proxy, VPN/TUN, TLS interception, or WebSocket configuration is installed.
- One `dam connect --profile` or active-profile `dam connect --apply` command still starts one daemon target at a time.
