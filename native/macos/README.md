# macOS Native Capture

This package contains the macOS Network Extension pieces used by DAM `tun` mode:

- `DAMTransparentProxyProvider`: a transparent proxy provider that receives outbound flows, bypasses non-target traffic, and forwards configured TCP targets to the local DAM transparent proxy.
- `dam-macos-ne-helper`: a small helper executable that installs, removes, starts, and reports the `NETransparentProxyManager` configuration after the signed DAM app has activated the System Extension.

Build-time validation:

```bash
swift build --package-path native/macos
```

Release packaging:

```bash
native/macos/scripts/package-dam-app.sh --mode developer-id
```

The package script builds the Rust binaries and Swift helper/provider, stages `DAM.app`, embeds the app and Network Extension provisioning profiles, substitutes the Team ID and App Group ID into the generated entitlements and system extension `NetworkExtension` Info.plist dictionary, signs the app, signs the helper with `com.apple.developer.system-extension.install`, signs the bundled system extension with `app-proxy-provider-systemextension`, and fails if the system extension usage description, provider class mapping, App-Group-prefixed Mach service name, or signed entitlement blobs are missing.

Current DAM package identifiers are:

- App bundle ID: `com.rpblc.dam`
- Network Extension bundle ID: `com.rpblc.dam.network-extension`
- Default macOS App Group ID: `TEAMID.com.rpblc.dam`
- Developer ID profile names: `DAM Developer ID App` and `DAM Developer ID Network Extension`

The Team ID is inferred from the installed provisioning profiles. Set `DAM_MACOS_TEAM_ID` only when you need to force a specific team during local packaging.

The App Group ID defaults to the macOS Team-ID-prefixed form, for example `2T6856RWGV.com.rpblc.dam`. This form is valid for macOS IPC and does not require registering a separate `group.*` identifier. Set `DAM_MACOS_APP_GROUP_ID` only if the Apple Developer account is configured to use a different registered App Group. The system extension Mach service name is generated as `APP_GROUP_ID.network-extension`, because macOS rejects Network Extension system extensions whose `NEMachServiceName` is not prefixed by one of their `com.apple.security.application-groups` entitlements.

The Developer ID artifact still needs notarization before normal Gatekeeper distribution. Local development can use System Extension developer mode for path checks, or copy the app into `/Applications` for closer release-path testing.

Source builds can point at a helper with:

```bash
export DAM_MACOS_NE_HELPER=/path/to/dam-macos-ne-helper
```

The helper contract is intentionally small:

```text
dam-macos-ne-helper install --bundle-id com.rpblc.dam.network-extension [--team-id TEAMID] [--proxy-host 127.0.0.1] [--proxy-port 7828] [--protect-host HOST...] [--exclude-signing-id ID...]
dam-macos-ne-helper remove  --bundle-id com.rpblc.dam.network-extension [--team-id TEAMID]
dam-macos-ne-helper status  --bundle-id com.rpblc.dam.network-extension [--team-id TEAMID]
```

`dam-tray` refreshes `systemextensionsctl` and submits `OSSystemExtensionRequest` from the real `DAM.app` process before invoking the helper. If macOS requires approval, the tray keeps that request alive while the user approves DAM Network Protection in System Settings, and the user clicks Connect/Resume again after approval. If macOS already reports `activated waiting for user`, Resume shows the approval action instead of retrying a stale activation request. The helper fails closed if it sees approval is still required or if macOS does not register activation promptly; DAM writes active capture state only after the helper exits successfully. Without the helper, install fails closed so the UI cannot report `tun` protection when macOS is not actually capturing flows.

The Network Extension provider installs a broad outbound rule so DAM can classify flows at metadata level. It returns pass-through for unknown traffic and for DAM's own signed binaries, which avoids proxy loops. For configured TCP targets, it opens a loopback connection to the daemon and synthesizes an HTTP `CONNECT host:port` preface from the flow metadata. DAM then applies its existing CONNECT/TLS and protocol-adapter readiness gates.

Unknown or unsupported traffic must pass through without payload inspection. Configured traffic must fail closed when route, trust, consent, or adapter readiness is missing.

The provider bundle is linked as an executable with `NSExtensionMain` as the entry point. Do not link it as a Mach-O bundle/library: that shape can verify as a nested bundle while failing to carry the Network Extension entitlement blob.
