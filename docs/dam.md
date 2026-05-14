# dam

`dam` is the local UX entry point for running selected AI traffic through DAM with minimal setup.

It currently supports the background daemon UX, integration profiles, and concise local log inspection:

```bash
cargo run -p dam -- connect
cargo run -p dam -- status
cargo run -p dam -- logs
cargo run -p dam -- disconnect
cargo run -p dam -- integrations list
cargo run -p dam -- connect --profile claude-code
cargo run -p dam -- connect --profile codex
```

The old `dam claude`, `dam codex`, and `dam codex --api` one-shot launchers have been removed. DAM no longer protects by rewriting `ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL`, or Codex `model_provider` / `base_url` settings. Use `dam connect`, tray Connect, and integration profiles so apps keep their normal provider endpoints while traffic routes through DAM.

`dam connect` starts a background local daemon that owns a `dam-proxy` until `dam disconnect`.

Background integration profiles configure tools to use the long-running daemon as an HTTP(S) proxy or rely on system proxy routing. The daemon can expose multiple provider targets for selected AI hosts while unknown traffic passes through untouched.

By default, the daemon proxy redacts outbound requests before they reach the provider. Agent traffic apps can keep inbound DAM references tokenized in the local transcript and can opt into raw inbound response redetection/tokenization through traffic profile `inbound.protect_sensitive_data`. Email-derived domains from the protected outbound request are carried into opted-in inbound redetection passes, including Anthropic/OpenAI `text/event-stream` responses, so a domain-only answer derived from a protected email can stay tokenized without rewriting generic browser/bootstrap responses. Set `proxy.resolve_inbound = false` or use `--no-resolve-inbound` to leave HTTP `[kind:id]` references unresolved for every app; explicit reveal/consent flows are separate from agent transcript protection.

## Auth Model

The local UX uses pass-through provider authentication by default.

- `dam connect --profile claude-code` selects the Anthropic target while Claude keeps its normal Anthropic endpoint and traffic routes through DAM.
- `dam connect --profile codex` selects Codex API-key traffic for `api.openai.com` and ChatGPT-login traffic for `chatgpt.com` and `ab.chatgpt.com` while Codex keeps its normal OpenAI endpoint or subscription login behavior.
- `dam integrations apply <profile> --write` ensures DAM-owned catalog profile JSON for source builds and unsupported environments. Use `--target-path` for rendered JSON exports with rollback support. Network Extension capture is the primary installed-app path.
- Provider credentials stay with the tool. DAM forwards the caller's auth headers.
- DAM does not require `ANTHROPIC_API_KEY` or `OPENAI_API_KEY`; those stay in the selected tool or user shell.

Proxy-managed API key injection still exists in `dam-proxy` for gateway-style deployments, but it is not the default local UX. Codex API-key and ChatGPT-login traffic are one user-facing profile with separate traffic app IDs under the hood.

## Commands

```bash
dam connect [--openai|--anthropic] [DAM_OPTIONS]
dam connect --profile <profile> [--apply] [DAM_OPTIONS]
dam connect --apply [DAM_OPTIONS]
dam status [--json]
dam logs [--limit N] [--after-id ID] [--operation OPERATION_ID] [--events] [--json]
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
dam startup status [--json]
dam startup skip-open-at-login [--json]
dam disconnect
dam integrations list [--json]
dam integrations show <profile> [--json]
dam integrations apply <profile> [--write|--dry-run]
dam integrations rollback <profile>
```

DAM options:

```text
--profile <id>       Use integration profile daemon defaults (connect only)
--apply              Ensure selected or enabled DAM profile files before connecting
--openai             Use the OpenAI-compatible daemon preset (default for connect)
--anthropic          Use the Anthropic daemon preset (connect only)
--config <path>      Load DAM config file before daemon overrides
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
dam connect --profile claude-code
dam connect --profile codex
dam profile set claude-code
dam connect --network-mode tun --trust-mode local_ca
dam profile status
dam connect --anthropic
dam status
dam logs
dam logs --operation <operation_id>
dam trust generate-local-ca
dam trust install-local-ca
dam network install-network-extension
dam network install-system-proxy
dam startup status
dam startup skip-open-at-login
dam integrations show codex
dam integrations apply codex
dam integrations apply codex --write
dam disconnect
```

## npm Wrapper

The npm package entry point is a small Node wrapper around native DAM binaries. It does not own protection behavior.

The previous one-shot `npx @rpblc/dam claude` and `npx @rpblc/dam codex --api` trial launchers have been removed because they depended on provider base-url rewriting. Use the installed `dam connect` / tray flow for protected traffic interception.

## Current Limits

- `dam connect` can start one daemon with multiple proxy targets when multiple app profiles are enabled. `--profile <id>` selects one explicit profile. `--apply` ensures selected DAM-owned catalog profile JSON before connecting; tray/web Connect uses Network Extension capture as the primary path and keeps explicit-proxy fallback commands for source builds and unsupported environments. If the enabled-profile state exists but contains no profiles, `dam connect` and `dam network install-*` use an explicit empty traffic scope instead of the bundled default routes.
- `dam logs` reads the local SQLite log and renders concise non-sensitive operation summaries by default. `--operation <id>` shows one operation's event timeline, and `--json` keeps the same data machine-readable for local debugging.
- `dam disconnect` pauses protection without stopping the daemon. `dam connect` resumes a paused daemon using its existing routing/trust setup. If the connected daemon was launched by a missing or different `dam` executable path/fingerprint, Connect restarts it from the current executable while preserving that setup, so source builds and app updates do not keep running stale proxy code. Use `dam disconnect --stop` before intentionally changing setup.
- `dam profile set <id>` persists the legacy active local harness profile. The tray/web Settings flow persists enabled app profiles; when no state exists, DAM defaults to Claude Code enabled only.
- `dam connect --network-mode system_proxy` refuses to start until DAM sees macOS PAC routing installed. Run `dam network install-system-proxy --yes` first after reviewing the preview.
- `dam connect --trust-mode local_ca` refuses to start until local CA trust is ready. Run `dam trust install-local-ca --yes` first after reviewing the preview. The `claude-code` integration profile uses `local_ca` because proxy-routed Anthropic HTTPS bodies require guarded TLS interception.
- `dam trust generate-local-ca` creates local CA certificate/key artifacts only. It does not install them into system trust.
- `dam trust delete-local-ca` deletes uninstalled DAM-managed local CA artifacts only.
- `dam trust install-local-ca` and `dam trust remove-local-ca` preview by default. On macOS only, `--yes` applies the System keychain change and may require administrator approval.
- `dam network install-network-extension` and `dam network remove-network-extension` preview by default. On macOS, `--yes` requires a signed helper from the app bundle or `DAM_MACOS_NE_HELPER` in source builds; without it, install fails closed. Packaged Connect submits System Extension activation only from `DAM.app`, then the helper configures `tun` capture and writes state only after success.
- `dam network install-system-proxy` and `dam network remove-system-proxy` preview by default. On macOS, `--yes` applies or removes PAC routing for proxy-capable traffic with rollback state; this remains a fallback and diagnostic mode.
- `dam startup status` reports whether the startup choice is registered, skipped, or unconfigured. `dam startup skip-open-at-login` records the same choice as the tray Skip button so scripted installs can continue without adding DAM to Open at Login.
- `dam integrations apply <profile>` previews by default. Add `--write` to ensure the DAM-managed catalog JSON file, or pass `--target-path` to write a rendered JSON export with rollback support. This profile-file setup is not part of the normal Connect onboarding path.
- The one-shot `dam claude`, `dam codex`, and `dam codex --api` launchers have been removed; the background `dam connect` flow can run multiple provider targets in one daemon.
- Codex API-key mode is protected when Codex keeps its normal OpenAI endpoint and routes through DAM capture/proxy routing. Codex ChatGPT-login mode uses the same `codex` profile and WebSocket adapter for `chatgpt.com` and `ab.chatgpt.com`.
- DAM no longer has a default user-facing provider base-URL routing path. Generic SDK profiles use HTTP(S) proxy settings.
- `--network-mode tun` can report macOS Network Extension capture installed by `dam network install-network-extension`. When route capture, local CA trust, and consent are ready, the daemon uses HTTP/1.1 CONNECT/TLS plus WebSocket handling for active traffic profile hosts. Decrypted transparent requests are target-selected from their authority/`Host` before provider API path hints, so ChatGPT backend HTTP paths use the `chatgpt-codex` target. `dam connect` preflights routing/trust setup before starting transparent modes and restarts a compatible running daemon when the enabled app traffic scope changes; if runtime readiness is lost after startup, configured traffic follows the routing failure policy (`fail_open` by default, `fail_closed` when configured).
- HTTP/2 transparent interception, fragmented/compressed WebSocket payload protection, UDP, and arbitrary web traffic rewriting remain parked. WebSocket protection state is frozen at connection start so enabling or pausing DAM does not mutate an already-established stream mid-flight.

## Tests

```bash
cargo test -p dam
cargo test -p dam-daemon
cargo test -p dam-e2e dam_tool_launchers_are_removed_from_cli
```
