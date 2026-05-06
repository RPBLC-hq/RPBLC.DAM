# dam-net-macos

`dam-net-macos` is the macOS platform routing implementation for DAM's local traffic mediation roadmap.

It manages macOS Auto Proxy Configuration through `networksetup` and a DAM-generated PAC file. The PAC routes proxy-capable HTTP and HTTPS traffic to the local DAM proxy, while bypassing localhost, plain hostnames, `.local`, loopback, IPv4 and IPv6 link-local, IPv4 private LAN, and IPv6 ULA ranges.

It also owns the macOS Network Extension control-plane used by `tun` mode. `dam-tray` owns the app-process System Extension activation request for packaged builds, because macOS keeps user approval pending only while the requesting app is alive. The tray refreshes `systemextensionsctl` before activation so `activated waiting for user` maps to the System Settings approval action and `activated enabled` proceeds to setup. `dam network install-network-extension` then plans configuration through the native Swift helper/provider package under `native/macos` (`DAM_MACOS_NE_HELPER` in source builds, or the signed helper app bundle in release builds). The helper configures `NETransparentProxyManager`; it does not submit System Extension activation. The app/helper process that writes Network Extension preferences must also carry the Network Extension entitlement, not only `system-extension.install`, and the embedded provisioning profiles must authorize the signed Network Extension and App Group entitlements. The packaged helper is wrapped as an app-like bundle so AMFI can validate those restricted entitlements. Without that helper, install fails closed instead of recording false active capture.

## Commands

The user-facing commands live under `dam network`:

```bash
dam network install-system-proxy [--config PATH] [--dry-run|--yes] [--json]
dam network remove-system-proxy [--dry-run|--yes] [--json]
dam network install-network-extension [--config PATH] [--dry-run|--yes] [--json]
dam network remove-network-extension [--dry-run|--yes] [--json]
dam network status [--json]
```

Both commands preview by default. `--yes` is required before DAM changes macOS network settings.

Without `--config`, the protected-host comments in the generated PAC and the Network Extension provider configuration are derived from the bundled LLM MVP traffic profile: `api.openai.com`, `api.anthropic.com`, `api.x.ai`, and `chatgpt.com`. With `--config`, those comments and provider configuration use the effective `[traffic]` profile plus `[[network.ai_routes]]` legacy overlays from that config file. PAC routing scope is still all proxy-capable HTTP/HTTPS traffic. Network Extension routing uses a broad outbound rule and relies on traffic-profile classification to pass non-target flows through.

## State

DAM writes routing state under:

```text
$DAM_STATE_DIR/network/macos-system-proxy/latest.json
$DAM_STATE_DIR/network/macos-system-proxy/dam-ai-proxy.pac
$DAM_STATE_DIR/network/macos-network-extension/latest.json
```

The rollback record is written only after all `networksetup` mutations succeed. It stores the previous Auto Proxy URL and enabled state for each active macOS network service. Removal restores those values and deletes the DAM rollback/PAC files after successful restoration.

The Network Extension state record stores the activated bundle identifier, optional team identifier, configured AI hosts, and activation/configuration method. It is only written after app-process activation is approved and the native helper succeeds. Status checks ask the native helper for live `NETransparentProxyManager.connection.status` when a record exists and reconcile the local `active` flag before reporting.

## Safety Boundary

This module installs routing only. The native provider forwards configured TCP flows to the local transparent proxy, but CONNECT handling, TLS interception, detection, redaction, and protocol-adapter policy remain in `dam-proxy` and the shared DAM pipeline.

Unknown traffic routed by the PAC file is passed through without TLS decryption, body inspection, or redaction. HTTPS AI traffic is protected only when daemon routing mode, local CA trust, explicit consent, and the transparent TLS adapter are all ready. When protection is paused, selected AI hosts also pass through without redaction.

## Tests

```bash
cargo test -p dam-net-macos
swift build --package-path native/macos
```
