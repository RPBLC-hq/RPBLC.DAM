# dam-net-macos

`dam-net-macos` is the first platform routing implementation for DAM's transparent-protection roadmap.

It manages macOS Auto Proxy Configuration through `networksetup` and a DAM-generated PAC file. The PAC routes only AI hosts from the merged `dam-net` route registry to the local DAM proxy and returns `DIRECT` for all other traffic.

## Commands

The user-facing commands live under `dam network`:

```bash
dam network install-system-proxy [--config PATH] [--dry-run|--yes] [--json]
dam network remove-system-proxy [--dry-run|--yes] [--json]
```

Both commands preview by default. `--yes` is required before DAM changes macOS network settings.

Without `--config`, PAC generation uses DAM's built-in AI hosts: `api.openai.com`, `api.anthropic.com`, `api.x.ai`, and `chatgpt.com`. With `--config`, PAC generation also includes `[[network.ai_routes]]` entries and route overrides from that config file.

## State

DAM writes routing state under:

```text
$DAM_STATE_DIR/network/macos-system-proxy/latest.json
$DAM_STATE_DIR/network/macos-system-proxy/dam-ai-proxy.pac
```

The rollback record is written before any `networksetup` mutation. It stores the previous Auto Proxy URL and enabled state for each active macOS network service. Removal restores those values and deletes the DAM rollback/PAC files after successful restoration.

## Safety Boundary

This module installs routing only. It does not implement CONNECT handling, TLS interception, detection, redaction, or provider forwarding.

HTTPS AI traffic routed by the PAC file is protected only when daemon routing mode, local CA trust, explicit consent, and the transparent TLS adapter are all ready. Outside that ready state, DAM fails closed instead of tunneling encrypted AI traffic opaquely. That is intentional: routing without inspection must not be reported as protected content handling.

## Tests

```bash
cargo test -p dam-net-macos
```
