# dam

`dam` is the local UX entry point for running selected AI traffic through DAM with minimal setup.

It currently supports the background daemon UX, integration profiles, and fail-closed legacy launcher commands:

```bash
cargo run -p dam -- connect
cargo run -p dam -- status
cargo run -p dam -- disconnect
cargo run -p dam -- integrations list
cargo run -p dam -- connect --profile claude-code
cargo run -p dam -- connect --profile codex-api
cargo run -p dam -- connect --profile codex-chatgpt
```

`dam claude`, `dam codex`, and `dam codex --api` are legacy one-shot launchers and now fail closed. DAM no longer protects by rewriting `ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL`, or Codex `model_provider` / `base_url` settings. Use `dam connect`, tray Connect, and integration profiles so apps keep their normal provider endpoints while traffic routes through DAM.

`dam connect` starts a background local daemon that owns a `dam-proxy` until `dam disconnect`.

Background integration profiles configure tools to use the long-running daemon as an HTTP(S) proxy or rely on system proxy routing. The daemon can expose multiple provider targets for selected AI hosts while unknown traffic passes through untouched.

By default, the daemon proxy redacts outbound requests before they reach the provider and resolves known DAM references on inbound responses before the tool sees them. Inbound responses are not redetected or redacted. Set `proxy.resolve_inbound = false` or use `--no-resolve-inbound` to leave `[kind:id]` references unresolved.

## Auth Model

The local UX uses pass-through provider authentication by default.

- `dam claude` refuses to launch because the old one-shot path rewrote `ANTHROPIC_BASE_URL`.
- `dam codex --api` refuses to launch because the old one-shot path injected a custom Codex provider and base URL.
- `dam codex` without `--api` refuses to launch as a legacy one-shot. Use `dam connect --profile codex-chatgpt --network-mode tun --trust-mode local_ca` for the protected ChatGPT-login path.
- `dam connect --profile claude-code` selects the Anthropic target while Claude keeps its normal Anthropic endpoint and traffic routes through DAM.
- `dam connect --profile codex-api` selects the OpenAI-compatible target for Codex API-key mode while Codex keeps its normal OpenAI endpoint and own API-key configuration.
- `dam integrations apply <profile> --write` writes reversible explicit-proxy fallback files for source builds and unsupported environments. Network Extension capture is the primary installed-app path.
- Provider credentials stay with the tool. DAM forwards the caller's auth headers.
- DAM does not require `ANTHROPIC_API_KEY` or `OPENAI_API_KEY`; those stay in the selected tool or user shell.

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
dam network install-network-extension [--dry-run|--yes] [--json]
dam network remove-network-extension [--dry-run|--yes] [--json]
dam network status [--json]
dam disconnect
dam integrations list [--json]
dam integrations show <profile> [--json]
dam integrations apply <profile> [--write|--dry-run]
dam integrations rollback <profile>
dam codex [--api] [DAM_OPTIONS] [-- CODEX_ARGS...]   # legacy fail-closed
dam claude [DAM_OPTIONS] [-- CLAUDE_ARGS...]          # legacy fail-closed
```

DAM options:

```text
--profile <id>       Use integration profile daemon defaults (connect only)
--apply              Write selected or enabled profile setup before connecting
--openai             Use the OpenAI-compatible daemon preset (default for connect)
--anthropic          Use the Anthropic daemon preset (connect only)
--api                Parse legacy Codex API-key mode; launcher still fails closed
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
--no-resolve-inbound Leave DAM references unresolved in inbound responses
--resolve-inbound    Restore DAM references in inbound responses (default)
```

Examples:

```bash
dam connect
dam connect --profile xai-compatible
dam connect --profile claude-code
dam connect --profile codex-chatgpt --network-mode tun --trust-mode local_ca
dam profile set claude-code
dam connect --network-mode tun --trust-mode local_ca
dam profile status
dam connect --anthropic
dam status
dam trust generate-local-ca
dam trust install-local-ca
dam network install-network-extension
dam network install-system-proxy
dam integrations show codex-api
dam integrations apply codex-api
dam integrations apply codex-api --write
dam disconnect
```

## npm Wrapper

The npm package entry point is a small Node wrapper around native DAM binaries. It does not own protection behavior.

The previous one-shot `npx @rpblc/dam claude` and `npx @rpblc/dam codex --api` trial launchers are disabled with the native commands because they depended on provider base-url rewriting. Use the installed `dam connect` / tray flow for protected traffic interception.

## Current Limits

- `dam connect` can start one daemon with multiple proxy targets when multiple app profiles are enabled. `--profile <id>` selects one explicit profile. `--apply` writes reversible explicit-proxy fallback before connecting; tray/web Connect uses Network Extension capture as the primary path and keeps the fallback for source builds and unsupported environments.
- `dam profile set <id>` persists the legacy active local harness profile. The tray/web Settings flow persists enabled app profiles for simultaneous Codex API and Claude Code protection.
- `dam connect --network-mode system_proxy` refuses to start until DAM sees macOS PAC routing installed. Run `dam network install-system-proxy --yes` first after reviewing the preview.
- `dam connect --trust-mode local_ca` refuses to start until local CA trust is ready. Run `dam trust install-local-ca --yes` first after reviewing the preview. The `claude-code` integration profile uses `local_ca` because proxy-routed Anthropic HTTPS bodies require guarded TLS interception.
- `dam trust generate-local-ca` creates local CA certificate/key artifacts only. It does not install them into system trust.
- `dam trust delete-local-ca` deletes uninstalled DAM-managed local CA artifacts only.
- `dam trust install-local-ca` and `dam trust remove-local-ca` preview by default. On macOS only, `--yes` applies the System keychain change and may require administrator approval.
- `dam network install-network-extension` and `dam network remove-network-extension` preview by default. On macOS, `--yes` requires a signed helper from the app bundle or `DAM_MACOS_NE_HELPER` in source builds; without it, install fails closed. Packaged Connect submits System Extension activation only from `DAM.app`, then the helper configures `tun` capture and writes state only after success.
- `dam network install-system-proxy` and `dam network remove-system-proxy` preview by default. On macOS, `--yes` applies or removes PAC routing for proxy-capable traffic with rollback state; this remains a fallback and diagnostic mode.
- `dam integrations apply <profile>` previews by default. Add `--write` to edit Claude Code settings or DAM-managed proxy environment files with a rollback record.
- The one-shot `dam claude`, `dam codex`, and `dam codex --api` launchers fail closed; the background `dam connect` flow can run multiple provider targets in one daemon.
- Codex API-key mode is protected when Codex keeps its normal OpenAI endpoint and routes through DAM capture/proxy routing. Codex ChatGPT-login mode uses the `codex-chatgpt` profile and WebSocket adapter for `chatgpt.com`.
- DAM no longer has a default user-facing provider base-URL routing path. Generic SDK profiles use HTTP(S) proxy settings.
- `--network-mode tun` can report macOS Network Extension capture installed by `dam network install-network-extension`. When route capture, local CA trust, and consent are ready, the daemon uses HTTP/1.1 CONNECT/TLS plus WebSocket handling for built-in and configured AI hosts. `dam connect` preflights routing/trust setup before starting transparent modes; transparent traffic still fails closed if runtime readiness is lost after startup.
- HTTP/2 transparent interception, fragmented/compressed WebSocket payload protection, UDP, and arbitrary web traffic rewriting remain parked.

## Tests

```bash
cargo test -p dam
cargo test -p dam-daemon
cargo test -p dam-e2e dam_codex_launcher_fails_closed_until_transport_is_protected
cargo test -p dam-e2e dam_codex_api_launcher_fails_closed_without_custom_provider
cargo test -p dam-e2e dam_claude_launcher_fails_closed_without_base_url_rewrite
```
