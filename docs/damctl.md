# damctl

`damctl` is the local DAM control and diagnostics CLI.

The current slice does not start or stop services. It answers these questions:

- is the local proxy protecting traffic?
- is this local install ready for the protected agent UX?
- can configured failure modes reduce protection guarantees?
- what daemon state file and process does the local lifecycle layer see?
- what local TLS trust readiness state is visible without changing system trust?
- is local macOS PAC routing state installed without changing system routes?
- what is the next safe setup action for the local connect flow?
- are known integration profiles applied, unapplied, or modified?
- is the local config valid for the current implementation?
- what MCP config should an agent use for DAM?

## Commands

```bash
cargo run -p damctl -- status
cargo run -p damctl -- doctor
cargo run -p damctl -- bypass status
cargo run -p damctl -- daemon inspect
cargo run -p damctl -- trust inspect
cargo run -p damctl -- network inspect
cargo run -p damctl -- setup plan
cargo run -p damctl -- integrations check
cargo run -p damctl -- config check
cargo run -p damctl -- mcp config
```

With an explicit config:

```bash
cargo run -p damctl -- status --config dam.example.toml
cargo run -p damctl -- doctor --config dam.example.toml
cargo run -p damctl -- bypass status --config dam.example.toml
cargo run -p damctl -- setup plan --config dam.example.toml
cargo run -p damctl -- config check --config dam.example.toml
cargo run -p damctl -- mcp config --config dam.example.toml
```

With an explicit proxy URL:

```bash
cargo run -p damctl -- status --proxy-url http://127.0.0.1:7828
cargo run -p damctl -- integrations check codex-api --proxy-url http://127.0.0.1:7828
```

JSON output:

```bash
cargo run -p damctl -- status --json
cargo run -p damctl -- doctor --json
cargo run -p damctl -- bypass status --json
cargo run -p damctl -- daemon inspect --json
cargo run -p damctl -- trust inspect --json
cargo run -p damctl -- network inspect --json
cargo run -p damctl -- setup plan --json
cargo run -p damctl -- integrations check --json
cargo run -p damctl -- config check --json
```

## `status`

`status` calls the proxy `/health` endpoint and expects a `dam-api` `ProxyReport`.

Default health URL comes from config:

```text
http://<proxy.listen>/health
```

`--proxy-url` overrides the configured proxy URL and appends `/health`.

Exit codes:

- `0`: proxy reports `protected`.
- `1`: proxy reports anything else, returns unreadable health JSON, or cannot be reached.
- `2`: command arguments, config loading, or URL construction failed.

## `doctor`

`doctor` runs local readiness checks through `dam-diagnostics` and emits a `dam-api` `HealthReport`.

It checks:

- normal config loading;
- vault/log/consent compatibility and local SQLite openability;
- router target selection, provider support, auth mode, and failure mode;
- proxy runtime `/health` when proxy is enabled;
- default setup-plan readiness for the local proxy/interception connect flow;
- integration profile apply state summary;
- enabled integration profile and Codex ChatGPT-login setup readiness.

Exit codes:

- `0`: doctor state is `healthy` or `degraded`.
- `1`: doctor state is `unhealthy`.
- `2`: command arguments or config loading failed.

Use `--proxy-url` to check a specific running proxy endpoint instead of the configured `proxy.listen`. Use `--state-dir PATH` to evaluate setup-plan and integration readiness against a non-default daemon/integration state directory.

## `bypass status`

`bypass status` loads config and reports whether any configured failure mode can reduce DAM's protection guarantees.

It reports:

- proxy default failure mode;
- per-target configured and effective proxy failure mode;
- vault write failure mode;
- log write failure mode;
- diagnostics explaining every reduced-protection mode.

The command treats these settings as reduced guarantees:

- `proxy.default_failure_mode = "bypass_on_error"` or target-level `failure_mode = "bypass_on_error"` because traffic can forward unprotected when DAM cannot inspect/protect it.
- `proxy.default_failure_mode = "redact_only"` or target-level `failure_mode = "redact_only"` because recoverability can be lost.
- `failure.vault_write = "redact_only"` because references cannot be restored after vault write failure.
- `failure.log_write = "warn_continue"` because audit failure does not stop the protected path.

Exit codes:

- `0`: failure modes are strict.
- `1`: one or more reduced-protection modes are enabled.
- `2`: command arguments or config loading failed.

## `daemon inspect`

`daemon inspect` reads the local daemon state file and reports what lifecycle state DAM sees. It does not start, stop, or repair the daemon.

```bash
cargo run -p damctl -- daemon inspect
cargo run -p damctl -- daemon inspect --json
```

It reports:

- lifecycle state: `connected`, `stale`, or `disconnected`;
- state directory and state file path;
- whether the recorded PID is running when a state file exists;
- proxy URL, target, provider, upstream, network mode, transparent AI route count, per-route routing readiness, trust mode, local CA installed state, per-route trust readiness, per-route interception readiness, local database paths, and inbound resolution setting from the state file.

Use `--state-dir PATH` to inspect a non-default state directory, for example in tests or support sessions.

Exit codes:

- `0`: daemon state inspection completed, including disconnected and stale states.
- `2`: command arguments failed, state path resolution failed, or the daemon state file was unreadable.

## `trust inspect`

`trust inspect` reports local TLS trust readiness metadata without installing certificates or changing system trust. Mutating trust commands live under `dam trust` and preview by default.

```bash
cargo run -p damctl -- trust inspect
cargo run -p damctl -- trust inspect --json
```

It reports:

- source: connected daemon state, stale daemon state, or default trust state;
- trust mode;
- platform trust-store tag;
- whether a local CA record is installed;
- local CA artifact paths when artifacts exist;
- trusted AI host count;
- per-route trust readiness for the active traffic profile routes recorded in daemon state;
- trust actions and whether each is implemented or planned.

Use `--state-dir PATH` to inspect a non-default daemon state directory.

Exit codes:

- `0`: trust inspection completed.
- `2`: state path resolution failed or the daemon state file was unreadable.

## `network inspect`

`network inspect` reports local network routing readiness without installing or removing system routes.

```bash
cargo run -p damctl -- network inspect
cargo run -p damctl -- network inspect --json
cargo run -p damctl -- network inspect --config dam.example.toml --json
```

It reports:

- DAM state directory;
- macOS PAC rollback record path;
- generated PAC path;
- whether DAM sees system-proxy routing installed;
- active traffic-profile hosts when `--config` is supplied;
- per-route system-proxy readiness.

Use `--state-dir PATH` to inspect a non-default daemon state directory. Use `--config PATH` to preview route readiness for a custom traffic profile before starting the daemon or applying system proxy routing.

Exit codes:

- `0`: network routing inspection completed.
- `2`: state path resolution failed.

## `setup plan`

`setup plan` reports the next read-only setup action for the local connect flow. It does not apply profiles, install system proxy routing, install local CA trust, start the daemon, or repair state.

```bash
cargo run -p damctl -- setup plan
cargo run -p damctl -- setup plan --json
cargo run -p damctl -- setup plan --config dam.example.toml --network-mode tun --trust-mode local_ca
```

It reports:

- overall state: `ready`, `needs_action`, or `blocked`;
- DAM state directory and integration state directory;
- effective proxy URL;
- requested network mode and trust mode;
- active integration profile when one is selected;
- setup steps for app selection, system proxy or Network Extension routing, local CA trust, and daemon lifecycle.

Each step reports:

- `done`: already ready.
- `needed`: a next action can continue setup.
- `blocked`: review or rollback is needed first.
- `skipped`: the step is not required for the selected mode.

Use `--network-mode explicit_proxy|system_proxy|tun` and `--trust-mode disabled|local_ca` to preview a richer local setup path. `system_proxy`, `tun`, and `local_ca` steps are marked as system-changing when they require installation. `tun` reports the macOS Network Extension install step and still requires the signed helper/app bundle before it can become active.

Exit codes:

- `0`: setup plan is `ready`.
- `1`: setup plan is `needs_action` or `blocked`.
- `2`: command arguments, config loading, or setup inspection failed.

## `integrations check`

`integrations check` inspects known profile apply state without changing files.

```bash
cargo run -p damctl -- integrations check
cargo run -p damctl -- integrations check codex-api
cargo run -p damctl -- integrations check codex-api --target-path ./codex-test.env
```

It reports each profile as:

- `applied`: desired content is present.
- `needs_apply`: the profile target is missing or does not yet contain DAM's desired content and no rollback record exists.
- `modified`: DAM has a rollback record, but the target no longer matches DAM's desired content.

Exit codes:

- `0`: no checked profile is modified and rollback records are readable. For all-profile inventory, unapplied profiles are allowed.
- `1`: a specific checked profile needs apply, or any checked profile is modified or has an unreadable rollback record.
- `2`: command arguments or profile inspection failed.

`--target-path` is only valid when checking one profile.

## `config check`

`config check` loads the normal DAM config stack through `dam-diagnostics` and emits a `dam-api` `HealthReport`.

It checks:

- config file/env/CLI loading;
- vault backend compatibility with the current local implementation;
- log backend compatibility with the current local implementation;
- consent backend compatibility and default TTL;
- proxy listen address parseability;
- proxy target provider support;
- proxy upstream URL parseability;
- missing proxy target API key env values when the proxy is enabled.

Exit codes:

- `0`: config is `healthy` or `degraded`.
- `1`: config is `unhealthy`.
- `2`: command arguments failed.

`degraded` is not fatal because DAM can still be used in non-proxy modes, for example `dam-filter` and `dam-resolve`.

## `mcp config`

`mcp config` prints a JSON snippet that points supported MCP clients at the installed `dam-mcp` binary.

This is the bridge until the installer layer can write agent-specific MCP config files automatically.

## Current Limits

- No daemon lifecycle management yet.
- `damctl daemon inspect` is read-only. Use `dam connect` and `dam disconnect` for lifecycle changes.
- `damctl bypass status` is read-only. No bypass toggle command yet.
- No real-provider credential validation beyond checking whether configured env vars are present.

## Tests

```bash
cargo test -p damctl
```
