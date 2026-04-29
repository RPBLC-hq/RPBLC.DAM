# damctl

`damctl` is the local DAM control and diagnostics CLI.

The current slice does not start or stop services. It answers these questions:

- is the local proxy protecting traffic?
- is this local install ready for the protected agent UX?
- is the local config valid for the current implementation?
- what MCP config should an agent use for DAM?

## Commands

```bash
cargo run -p damctl -- status
cargo run -p damctl -- doctor
cargo run -p damctl -- config check
cargo run -p damctl -- mcp config
```

With an explicit config:

```bash
cargo run -p damctl -- status --config dam.example.toml
cargo run -p damctl -- doctor --config dam.example.toml
cargo run -p damctl -- config check --config dam.example.toml
cargo run -p damctl -- mcp config --config dam.example.toml
```

With an explicit proxy URL:

```bash
cargo run -p damctl -- status --proxy-url http://127.0.0.1:7828
```

JSON output:

```bash
cargo run -p damctl -- status --json
cargo run -p damctl -- doctor --json
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
- launcher readiness for `dam claude`, `dam codex --api`, and fail-closed Codex ChatGPT-login mode.

Exit codes:

- `0`: doctor state is `healthy` or `degraded`.
- `1`: doctor state is `unhealthy`.
- `2`: command arguments or config loading failed.

Use `--proxy-url` to check a specific running proxy endpoint instead of the configured `proxy.listen`.

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
- No automatic install/integration profile writes yet.
- No bypass toggle command yet.
- No real-provider credential validation beyond checking whether configured env vars are present.

## Tests

```bash
cargo test -p damctl
```
