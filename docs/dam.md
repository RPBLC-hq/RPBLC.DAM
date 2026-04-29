# dam

`dam` is the local UX entry point for running selected AI traffic through DAM with minimal setup.

It currently supports the background daemon UX, Claude Code, and explicit Codex API-key mode:

```bash
cargo run -p dam -- connect
cargo run -p dam -- status
cargo run -p dam -- disconnect
cargo run -p dam -- integrations list
cargo run -p dam -- claude
cargo run -p dam -- codex --api
```

`dam codex` without `--api` still fails closed. Codex v0.125 ChatGPT-login mode sends model turns to `wss://chatgpt.com/backend-api/codex/responses` and HTTPS fallback on the same path; that transport is not controlled by `chatgpt_base_url`, so the current explicit base-URL launcher cannot protect it.

`dam connect` starts a background local daemon that owns a `dam-proxy` until `dam disconnect`.

The launcher commands start an embedded `dam-proxy`, wait for `/health`, start the selected tool with a DAM base URL, and shut the proxy down when the tool exits.

By default, the embedded proxy redacts outbound requests before they reach the provider and leaves DAM references unresolved on inbound responses. Inbound responses are not redacted. Set `proxy.resolve_inbound = true` or use `--resolve-inbound` to restore known `[kind:id]` references back to local values before the tool sees the response.

## Auth Model

The launcher uses pass-through provider authentication by default.

- `dam codex` without `--api` refuses to launch until DAM can protect Codex's `backend-api/codex/responses` WebSocket/HTTPS transport.
- `dam claude` starts Claude Code with `ANTHROPIC_BASE_URL=http://127.0.0.1:7828` and uses the `anthropic` proxy provider.
- `dam codex --api` starts Codex with a temporary custom provider named `dam_openai`, `base_url = "http://127.0.0.1:7828/v1"`, `env_key = "OPENAI_API_KEY"`, `wire_api = "responses"`, and `supports_websockets = false`.
- Provider credentials stay with the tool. DAM forwards the caller's auth headers.
- DAM does not require `ANTHROPIC_API_KEY` for `dam claude`. `dam codex --api` requires `OPENAI_API_KEY` because Codex API-key mode uses OpenAI Platform auth.

Proxy-managed API key injection still exists in `dam-proxy` for gateway-style deployments, but it is not the default local UX. Codex ChatGPT-login mode remains separate from the API-key path.

## Commands

```bash
dam connect [--openai|--anthropic] [DAM_OPTIONS]
dam connect --profile <profile> [--apply] [DAM_OPTIONS]
dam status [--json]
dam disconnect
dam integrations list [--json]
dam integrations show <profile> [--json]
dam integrations apply <profile> [--dry-run]
dam integrations rollback <profile>
dam codex --api [DAM_OPTIONS] [-- CODEX_ARGS...]
dam claude [DAM_OPTIONS] [-- CLAUDE_ARGS...]
```

DAM options:

```text
--profile <id>       Apply integration profile daemon defaults (connect only)
--apply              Apply the selected integration profile before connecting
--openai             Use the OpenAI-compatible daemon preset (default for connect)
--anthropic          Use the Anthropic daemon preset (connect only)
--api                Use Codex API-key mode through DAM (Codex only)
--config <path>      Load DAM config file before launcher overrides
--listen <addr>      Local proxy listen address (default: 127.0.0.1:7828)
--target-name <name> Proxy target name (connect only)
--provider <name>    Provider adapter: openai-compatible or anthropic (connect only)
--upstream <url>     Provider upstream
--db <path>          Vault SQLite path (default: vault.db)
--log <path>         Log SQLite path (default: log.db)
--consent-db <path>  Consent SQLite path (default: consent.db)
--no-log             Disable DAM log writes
--no-resolve-inbound Leave DAM references unresolved in inbound responses (default)
--resolve-inbound    Restore DAM references in inbound responses
```

Examples:

```bash
dam connect
dam connect --profile xai-compatible
dam connect --profile claude-code --apply
dam connect --anthropic
dam status
dam integrations show codex-api
dam integrations apply codex-api --dry-run
dam disconnect
cargo run -p dam -- claude -- --model sonnet
cargo run -p dam -- codex --api -- -m gpt-5.5
cargo run -p dam -- claude --listen 127.0.0.1:7829
```

## npm Wrapper

The npm package entry point is a small Node wrapper around native DAM binaries. It does not own protection behavior.

```bash
npx @rpblc/dam claude
npx @rpblc/dam codex --api
```

When invoked from `npx`, `claude` and `codex` run in trial mode by default. Trial mode creates a temporary directory, passes explicit `--db`, `--log`, and `--consent-db` paths to the native launcher, and removes the directory when the protected tool exits. Use `--keep` to preserve the trial databases, or `--persist` to bypass trial mode and run the native launcher normally.

## Current Limits

- `dam connect` runs one background proxy target at a time. `--profile <id> --apply` can configure known harness profiles with rollback records, but DAM does not install system proxy settings yet.
- `dam integrations apply codex-api` edits Codex config with a backup; `dam integrations apply claude-code` edits Claude Code settings with a backup. Generic profiles write DAM-managed environment files.
- One launcher command starts one single-target proxy.
- Codex API-key mode is protected through the public Responses API. Codex ChatGPT-login model turns are not protected by the current launcher and are blocked.
- Codex WebSockets are disabled in the injected provider config until DAM has a WebSocket adapter.
- This is explicit base-URL routing, not transparent HTTPS interception.
- TLS interception, VPN/TUN routing, and integration-profile auto-configuration are still parked.

## Tests

```bash
cargo test -p dam
cargo test -p dam-daemon
cargo test -p dam-e2e dam_codex_launcher_fails_closed_until_transport_is_protected
cargo test -p dam-e2e dam_codex_api_launcher_sets_dam_model_provider
cargo test -p dam-e2e dam_claude_launcher_passes_anthropic_base_url_to_claude
```
