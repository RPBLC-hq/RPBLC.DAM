# CLI Automation Roadmap (LLM + CI Friendly)

This roadmap defines a **fully scriptable** CLI surface while preserving optional interactive UX for humans.

## Design principles

- Every interactive flow must have a non-interactive equivalent.
- Commands intended for automation must support `--json`.
- Output schemas should be stable and versionable.
- Exit codes should be deterministic and documented.

## Global flags contract

- `--json`: machine-readable output only
- `--yes`: accept confirmations
- `--no-input`: fail instead of prompting
- `--quiet`: reduce non-essential output

## Exit code contract

- `0` success
- `2` validation/config error
- `3` runtime unavailable/dependency failure
- `4` auth/permission failure
- `5` upstream/provider failure

## Command surface target

### 1) Config lifecycle
- `dam config init [--path] [--yes]`
- `dam config show [--json]`
- `dam config get <key> [--json]`
- `dam config set <key> <value>`
- `dam config unset <key>`
- `dam config validate [--json]`
- `dam config export --format toml|json`
- `dam config import --file <path> [--merge|--replace]`

### 2) Runtime/diagnostics
- `dam serve [--config ...]`
- `dam status [--json]`
- `dam health [--json]` (checks `/healthz` + `/readyz`)
- `dam doctor [--json]` (vault, DB, key, upstream checks)

### 3) Pipeline interaction
- `dam scan --text "..." [--json]`
- `dam resolve --text "..." [--json]`
- `dam request --provider anthropic|openai|responses|codex --input-file req.json [--stream] [--json]`
- `dam route test --provider ... [--stream] [--json]`

### 4) Vault / consent / audit
- `dam vault stats [--json]`
- `dam vault list [--limit N] [--json]`
- `dam vault get --ref <ref> [--json]`
- `dam vault cleanup [--expired-only] [--json]`
- `dam consent grant|revoke|check ... [--json]`
- `dam audit list [--ref ... --limit N] [--json]`

## Phased rollout

### Phase 1 (minimum LLM usability)
- Add global non-interactive flags where missing.
- `config validate`, `status`, `doctor`, `health` with `--json`.

### Phase 2 (full request interaction)
- `request` and `route test` commands with structured JSON output.

### Phase 3 (operational completeness)
- Full vault/consent/audit command coverage.

## Compatibility policy

- Keep existing interactive commands for human users.
- Do not remove interactive UX unless equivalent script mode exists.
- Treat JSON output schema changes as breaking unless versioned.
