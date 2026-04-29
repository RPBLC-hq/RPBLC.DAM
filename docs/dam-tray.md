# dam-tray

`dam-tray` is the first native desktop shell for DAM's local Connect UX.

The first slice is macOS-focused. It starts a local `dam-web` child process, prepares `/connect` in a hidden native WebView, and opens that WebView as a borderless popover anchored under the `[R:]` menu-bar item only when the user clicks the item.

The macOS menu-bar item is text-only and renders `[R:]` as its native title. It does not attach a native tray menu; clicking the item opens the hosted Connect surface. `tray-icon` does not expose custom font styling for that title, so the menu-bar item uses the platform's default menu-bar font and color rather than a custom image.

Inside the tray-hosted page, clicking the `[R:]` brand mark opens `https://rpblc.com` in the user's default browser through the native shell instead of navigating inside the WebView. The WebView navigation and IPC handlers are pinned to the hosted loopback origin, and new-window requests are denied inside the embedded view.

It does not implement protection logic. Connect, disconnect, profile selection, setup apply/rollback, vault/log viewing, consent, and diagnostics continue to live in `dam`, `dam-daemon`, `dam-integrations`, and `dam-web`.

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
- Starting `dam-tray` creates the menu-bar item without opening the popover.
- Losing focus hides the popover; the app remains available from the menu-bar item.
- The tray-hosted page renders a Quit DAM button. It runs `dam disconnect`, then stops the hosted web UI and exits the tray shell.
- Non-macOS platforms currently return a clear unsupported-platform message; users can run `dam-web` directly until native shells are added.

## Packaging Notes

A click-and-play package must include at least:

```text
dam-tray
dam-web
dam
```

The tray binary discovers explicit `--dam-web-bin` / `--dam-bin` paths first, then `DAM_WEB_BIN` / `DAM_BIN`, then sibling binaries next to `dam-tray`, then `PATH`.

## Tests

```bash
cargo test -p dam-tray
```
