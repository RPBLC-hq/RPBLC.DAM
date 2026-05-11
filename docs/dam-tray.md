# dam-tray

`dam-tray` is the first native desktop shell for DAM's local Connect UX.

The first slice is macOS-focused. It starts a local `dam-web` child process, prepares `/connect` in a hidden native WebView, and opens that WebView as a borderless popover anchored under the `[R:]` menu-bar item only when the user clicks the item. Popover positioning uses the current native window size and clamps to the active monitor; the hosted React app fills whatever viewport it receives.

The macOS menu-bar item is text-only and renders `[R:]` as its native title. It does not attach a native tray menu; clicking the item opens the hosted Connect surface. `tray-icon` does not expose custom font styling for that title, so the menu-bar item uses the platform's default menu-bar font and color rather than a custom image.

Inside the tray-hosted frame, clicking the `[R:]` brand mark opens `https://rpblc.com` in the user's default browser through the native shell instead of navigating inside the WebView. Clicking the tray `DAM` product stamp posts `dam-tray:open-dam-web` so the native shell opens the hosted DAM web view in the user's default browser. The WebView navigation and IPC handlers are pinned to the hosted loopback origin, and new-window requests are denied inside the embedded view.

The tray-hosted Connect button posts a native IPC event instead of letting the `dam-web` child process run privileged setup. The native shell reads `dam-diagnostics::setup_plan` and advances only the first outstanding step, matching the checklist the user sees. It first refreshes the installed System Extension state with `systemextensionsctl`, then submits the macOS System Extension activation request from the real `DAM.app` process when activation is not already pending or enabled. If the installed System Extension is disabled or its build is older than the bundled build, the tray treats it as not ready and submits activation so macOS can enable or replace it. It keeps pending approval requests alive until the user approves or quits the app. While macOS reports `activated waiting for user`, Resume submits and retains a fresh app-owned activation request, opens System Settings to the Network Extensions section when macOS accepts that deep link, then falls back to the Login Items & Extensions extension section and finally the generic Login Items & Extensions page. This matters after app restarts: the registry can still say "waiting" even though no live `OSSystemExtensionRequest` is retained. When macOS reports any reboot-gated System Extension transition, including removal of a prior extension, the tray reports reboot as its own setup action and stops before Network Extension install. The reboot marker is valid only for the current macOS boot; after restart, DAM re-checks launch-at-login, System Extension activation, Network Extension manager status, local CA trust, and daemon state from the live system before continuing. After activation is approved, the tray records that the System Extension is ready and returns to the setup checklist before asking macOS to add the `NETransparentProxyManager` network configuration. Later Connect/Resume clicks advance one setup state at a time: add manager configuration, enable it in System Settings when macOS requires approval, start/verify it until live status reaches `connected`, install local CA trust, then `dam connect --network-mode tun --trust-mode local_ca`. The add-configuration step does not open the enablement Settings pane; that belongs to the separate enable step. The helper configures and starts `NETransparentProxyManager` on retries once macOS reports the manager is enabled; it does not submit a second System Extension activation request. If an already-enabled manager fails to reach `connected`, DAM treats that as a protection-layer start failure, disables the manager again to preserve normal networking, and does not reopen System Settings for that condition.

Before Network Extension setup, the tray asks the user to either add DAM to Open at Login or skip that startup behavior for this install. Add registers the installed app with `SMAppService.mainApp` so DAM appears under System Settings > General > Login Items > Open at Login. Skip writes a non-sensitive local marker and advances without changing login items. Markers under the DAM state directory let the hosted setup plan resume after the native choice completes. Older LaunchAgent registration is removed when the Add path migrates the install.

Scripted installs can inspect the same startup choice with `dam startup status --json` and record the Skip path with `dam startup skip-open-at-login --json`. Platform-specific startup steps may diverge on Linux and Windows as native shells are added.

`dam-tray` gives the hosted `dam-web` process a random per-session POST token through `DAM_WEB_TRAY_POST_TOKEN`. Tray-mode pages attach that token to same-origin form actions so macOS WebView form submits can mutate local state even when the WebView omits browser `Origin` / `Referer` headers. Browser-hosted `dam-web` keeps the normal local-origin POST guard.

It does not implement protection logic. Connect, pause, app/profile selection, setup sequencing, vault/log viewing, consent, and diagnostics continue to live in `dam`, `dam-daemon`, `dam-diagnostics`, `dam-integrations`, and `dam-web`. Native Quit exits the tray shell and stops only the hosted `dam-web` child. It does not restore DAM-managed routing, change enabled app selection, roll back explicit profile setup, or stop the daemon, so active clients keep their local DAM endpoint.

## Usage

From a source checkout:

```bash
cargo build -p dam -p dam-web -p dam-tray
cargo run -p dam-tray
```

With explicit binaries:

```bash
cargo run -p dam-tray -- \
  --dam-bin target/debug/dam \
  --dam-web-bin target/debug/dam-web
```

Optional flags:

```text
--addr <addr>          Local dam-web listen address. Defaults to 127.0.0.1:2896 or the next free loopback port.
--config <path>        Pass a DAM config file to dam-web.
--db <path>            Vault SQLite path for the hosted web UI and connect flow.
--log <path>           Log SQLite path for the hosted web UI and connect flow.
--dam-bin <path>       DAM CLI binary used by /connect for one-click connect.
--dam-web-bin <path>   dam-web binary hosted by the tray shell.
```

`DAM_BIN` and `DAM_WEB_BIN` can also point at custom binaries. Binary discovery order is explicit flag, matching environment variable, sibling binary next to `dam-tray`, then `PATH`.

## Local State

When paths are not provided, `dam-tray` uses DAM's user-local state directory:

```text
$DAM_STATE_DIR
```

or, when unset:

```text
$HOME/.dam
```

Default files under that directory:

```text
vault.db
log.db
consent.db
daemon.json
```

`dam-tray` sets `DAM_STATE_DIR` and `DAM_CONSENT_PATH` for the hosted `dam-web` process so the visual app and `dam connect` agree on local state.

## Boundary

- `dam-tray` owns the native shell and the hosted `dam-web` child process.
- On macOS, `dam-tray` owns the app-process System Extension activation request for packaged Connect.
- Starting `dam-tray` creates the menu-bar item without opening the popover.
- Losing focus hides the popover; the app remains available from the menu-bar item.
- The native shell owns the initial popover window and positioning. The hosted app must stay responsive to the WebView viewport.
- Native Quit exits the tray shell and stops the hosted web UI without changing DAM routing, enabled app selection, explicit profile setup, protection state, or the daemon. The current frame-only React slice does not render a Quit control yet.
- Non-macOS platforms currently return a clear unsupported-platform message; users can run `dam-web` directly until native shells are added.

## Packaging Notes

A click-and-play package must include at least:

```text
dam-tray
dam-web
dam
signed macOS Network Extension helper/app bundle for tun mode
```

The tray binary discovers explicit `--dam-web-bin` / `--dam-bin` paths first, then `DAM_WEB_BIN` / `DAM_BIN`, then sibling binaries next to `dam-tray`, then `PATH`.

## Tests

```bash
cargo test -p dam-tray
```
