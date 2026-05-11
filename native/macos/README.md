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
scripts/dam-build.sh release-macos --mode developer-id
```

`scripts/dam-build.sh` is the standard local/CI wrapper for checks, signed app packaging, notarization, release zipping, and local deploys. Its `macos-app` and `release-macos` commands delegate app assembly to `native/macos/scripts/package-dam-app.sh`.

The package script builds the Rust binaries and Swift helper/provider, stages `DAM.app`, embeds the app and Network Extension provisioning profiles, substitutes the Team ID and App Group ID into the generated entitlements and system extension `NetworkExtension` Info.plist dictionary, wraps the helper as `Contents/Helpers/DAMMacosNEHelper.app`, embeds a copy of the provider system extension in both `DAM.app` and the helper app, signs the app/helper with `com.apple.developer.system-extension.install` and `app-proxy-provider-systemextension`, signs both bundled system extension copies with `app-proxy-provider-systemextension`, and fails if the system extension usage description, provider class mapping, App-Group-prefixed Mach service name, signed entitlement blobs, or profile-authorized entitlements are missing.

Current DAM package identifiers are:

- App bundle ID: `com.rpblc.dam`
- Network Extension bundle ID: `com.rpblc.dam.network-extension`
- Default macOS App Group ID: `TEAMID.com.rpblc.dam`
- Developer ID profile names: `DAM Developer ID App` and `DAM Developer ID Network Extension`

The Team ID is inferred from the installed provisioning profiles. Set `DAM_MACOS_TEAM_ID` only when you need to force a specific team during local packaging.

The App Group ID defaults to the macOS Team-ID-prefixed form, for example `2T6856RWGV.com.rpblc.dam`. This form is valid for macOS IPC and does not require registering a separate `group.*` identifier. Set `DAM_MACOS_APP_GROUP_ID` if the provisioning profiles are configured to authorize a registered `group.*` App Group instead. The system extension Mach service name is generated as `APP_GROUP_ID.network-extension`, because macOS rejects Network Extension system extensions whose `NEMachServiceName` is not prefixed by one of their `com.apple.security.application-groups` entitlements.

Both installed provisioning profiles must authorize the exact App Group and Network Extension values that DAM signs. The app profile for `com.rpblc.dam` must include `com.apple.developer.system-extension.install`, `com.apple.security.application-groups = TEAMID.com.rpblc.dam`, and `com.apple.developer.networking.networkextension = app-proxy-provider-systemextension`; it authorizes both the tray app and the helper app wrapper. The extension profile for `com.rpblc.dam.network-extension` must include the same App Group and `app-proxy-provider-systemextension`. If a restricted entitlement is signed but not profile-authorized, AMFI kills the helper/provider at launch.

The helper must run as an app bundle so AMFI can validate its restricted entitlements, and that helper app must embed the provider system extension. `NETransparentProxyManager` persists the provider designated requirement by resolving the provider system extension from `Bundle.main`. If the preferences writer runs from a nested helper app that does not embed `Contents/Library/SystemExtensions/com.rpblc.dam.network-extension.systemextension`, macOS can save a manager that later fails to start with a missing designated-requirement error.

The Developer ID artifact still needs notarization before normal Gatekeeper distribution. Local development can use System Extension developer mode for path checks, or copy the app into `/Applications` for closer release-path testing.

Source builds can point at a helper with:

```bash
export DAM_MACOS_NE_HELPER=/path/to/dam-macos-ne-helper
```

The helper contract is intentionally small:

```text
dam-macos-ne-helper install --bundle-id com.rpblc.dam.network-extension [--team-id TEAMID] [--proxy-host 127.0.0.1] [--proxy-port 7828] [--routing-failure-policy fail_open|fail_closed] [--protect-host HOST...|--no-protected-hosts] [--exclude-signing-id ID...]
dam-macos-ne-helper remove  --bundle-id com.rpblc.dam.network-extension [--team-id TEAMID]
dam-macos-ne-helper status  --bundle-id com.rpblc.dam.network-extension [--team-id TEAMID]
```

`dam-tray` refreshes `systemextensionsctl` and submits `OSSystemExtensionRequest` from the real `DAM.app` process before invoking the helper. If macOS requires approval, the tray keeps that request alive while the user approves DAM Network Protection in System Settings, and the user clicks Connect/Resume again after approval. If macOS already reports `activated waiting for user`, Resume opens System Settings when possible and shows the approval action instead of retrying a stale activation request. After app-owned activation is approved, the helper configures and starts `NETransparentProxyManager`; it does not submit another System Extension activation request. DAM writes active capture state only after the helper exits successfully. `--no-protected-hosts` is an explicit empty runtime scope used when all app profiles are disabled; the helper persists the manager disabled instead of starting a no-op tunnel. Omitting both host flags keeps the helper's built-in default MVP hosts. Without the helper, install fails closed so the UI cannot report `tun` protection when macOS is not actually capturing flows.

The provider applies DAM's routing failure policy for configured targets. The default `fail_open` policy passes traffic outside DAM when the local proxy is unreachable or reports anything other than `protected`; this keeps manager start safe during onboarding and keeps normal traffic working when DAM is paused/off. The provider also polls local proxy health while running and closes already-captured configured flows when protection stops being ready, so clients reconnect through the current policy instead of staying pinned through an old protected tunnel. `fail_closed` is available for strict or managed installs that prefer configured traffic to stop when DAM cannot verify protection.

The Network Extension provider installs a broad outbound rule so DAM can classify flows at metadata level. It returns pass-through for unknown traffic, for an empty protected-host runtime scope, and for DAM's own signed binaries, which avoids proxy loops and keeps disabled apps unmediated. For configured TCP targets, it opens a loopback connection to the daemon and synthesizes an HTTP `CONNECT host:port` preface from the flow metadata. DAM then applies its existing CONNECT/TLS and protocol-adapter readiness gates. If the helper updates the runtime configuration while the manager is connected, it restarts the tunnel so the provider reloads the new host scope.

Unknown or unsupported traffic must pass through without payload inspection. Configured traffic must fail closed when route, trust, consent, or adapter readiness is missing.

The provider bundle is linked as an executable and starts Network Extension system-extension mode from `Sources/DAMTransparentProxyProvider/main.swift` with `NEProvider.startSystemExtensionMode()`. Do not link it as a Mach-O bundle/library: that shape can verify as a nested bundle while failing to carry the Network Extension entitlement blob. Do not use the app-extension `_NSExtensionMain` entry point for the Developer ID System Extension path; macOS can activate the system extension while the `NETransparentProxyManager` never reaches `connected`.
