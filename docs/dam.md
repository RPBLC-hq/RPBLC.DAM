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
dam connect --apply [DAM_OPTIONS]
dam status [--json]
dam profile status [--json]
dam profile set <profile> [--json]
dam profile clear [--json]
dam trust generate-local-ca [--json]
dam trust delete-local-ca [--json]
dam trust install-local-ca [--dry-run|--yes] [--json]
dam trust remove-local-ca [--dry-run|--yes] [--json]
dam network install-system-proxy [--dry-run|--yes] [--json]
dam network remove-system-proxy [--dry-run|--yes] [--json]
dam disconnect
dam integrations list [--json]
dam integrations show <profile> [--json]
dam integrations apply <profile> [--write|--dry-run]
dam integrations rollback <profile>
dam codex --api [DAM_OPTIONS] [-- CODEX_ARGS...]
dam claude [DAM_OPTIONS] [-- CLAUDE_ARGS...]
```

DAM options:

```text
--profile <id>       Apply integration profile daemon defaults (connect only)
--apply              Apply the selected profile or enabled app profiles before connecting
--openai             Use the OpenAI-compatible daemon preset (default for connect)
--anthropic          Use the Anthropic daemon preset (connect only)
--api                Use Codex API-key mode through DAM (Codex only)
--config <path>      Load DAM config file before launcher overrides
--listen <addr>      Local proxy listen address (default: 127.0.0.1:7828)
--network-mode <mode> Control-plane network mode: explicit_proxy, system_proxy, or tun
--trust-mode <mode>  Control-plane trust mode: disabled or local_ca
--target-name <name> Proxy target name (connect only)
--provider <name>    Provider adapter: openai-compatible or anthropic (connect only)
--upstream <url>     Provider upstream
--target <spec>      Internal daemon target spec: name|provider|upstream
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
dam profile set claude-code
dam connect --apply
dam profile status
dam connect --anthropic
dam status
dam trust generate-local-ca
dam trust install-local-ca
dam network install-system-proxy
dam integrations show codex-api
dam integrations apply codex-api
dam integrations apply codex-api --write
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

- `dam connect` can start one daemon with multiple proxy targets when multiple app profiles are enabled. `--profile <id> --apply` still configures one explicit profile. `dam connect --apply` without `--profile` applies all enabled app profiles, falling back to the legacy active profile only when no enabled profile state exists.
- `dam profile set <id>` persists the legacy active local harness profile. The tray/web Settings flow persists enabled app profiles for simultaneous Codex API and Claude Code protection.
- `dam connect --network-mode system_proxy` refuses to start until DAM sees macOS PAC routing installed. Run `dam network install-system-proxy --yes` first after reviewing the preview.
- `dam connect --trust-mode local_ca` refuses to start until local CA trust is ready. Run `dam trust install-local-ca --yes` first after reviewing the preview.
- `dam trust generate-local-ca` creates local CA certificate/key artifacts only. It does not install them into system trust.
- `dam trust delete-local-ca` deletes uninstalled DAM-managed local CA artifacts only.
- `dam trust install-local-ca` and `dam trust remove-local-ca` preview by default. On macOS only, `--yes` applies the System keychain change and may require administrator approval.
- `dam network install-system-proxy` and `dam network remove-system-proxy` preview by default. On macOS, `--yes` applies or removes PAC routing for built-in and configured AI hosts with rollback state.
- `dam integrations apply <profile>` previews by default. Add `--write` to edit Codex config, Claude Code settings, or DAM-managed environment files with a rollback record.
- One launcher command still starts one single-target proxy. The background `dam connect --apply` flow can run multiple provider targets in one daemon.
- Codex API-key mode is protected through the public Responses API. Codex ChatGPT-login model turns are not protected by the current launcher and are blocked.
- Codex WebSockets are disabled in the injected provider config until DAM has a WebSocket adapter.
- Explicit base-URL routing remains the default local protection path.
- `--network-mode system_proxy` can report macOS PAC routing installed by `dam network install-system-proxy`. When system-proxy routing, local CA trust, and consent are ready, the daemon uses the first HTTP/1.1 CONNECT/TLS runtime for built-in and configured AI hosts. `dam connect` preflights routing/trust setup before starting transparent modes; transparent `CONNECT` traffic still fails closed if runtime readiness is lost after startup.
- VPN/TUN routing, HTTP/2 transparent interception, WebSockets, and arbitrary web traffic rewriting remain parked.

## Tests

```bash
cargo test -p dam
cargo test -p dam-daemon
cargo test -p dam-e2e dam_codex_launcher_fails_closed_until_transport_is_protected
cargo test -p dam-e2e dam_codex_api_launcher_sets_dam_model_provider
cargo test -p dam-e2e dam_claude_launcher_passes_anthropic_base_url_to_claude
```
