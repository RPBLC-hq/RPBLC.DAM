# dam-web

`dam-web` is the local web UI.

It is being rebuilt from the architecture specs and `RPBLC.Design`. The current React slice includes the shared web/tray app frame, the pinned brand/navigation bar, Connect, Wallet, Allowed, Activity, Insights, System, Health, and Settings.

The app frame is a React shell served from embedded `/assets/bundle.js`, `/assets/bundle.css`, and `/assets/index.html` build output.

## Current Routes

```text
/                 Connect surface
/connect          Connect surface
/allowed          active, expired, and revoked consent grants
/activity         dam-log derived activity feed
/settings         local preferences, integrations, and daemon controls
/*                frame fallback
```

The backend `/api/v1/*` routes remain available for upcoming page slices. Connect fetches `/api/v1/connect`, posts setup/action requests to `/api/v1/connect/action`, reads `/api/v1/requests/pending` while protected, and can use the local QA-only `/api/v1/requests/trigger` endpoint to simulate an inbound consent request. The protected-state view reads `protected_since_unix` from `/api/v1/connect` and renders a live elapsed timer from that backend timestamp rather than keeping a client-side checkpoint. The Connect counts row is backed by live local stores: active consent grants from `dam-consent`, redaction rows for the current UTC day from `dam-log`, and enabled integration profiles from `dam-integrations`. The Connect page re-fetches `/api/v1/connect` on a short interval while mounted because proxy-written `dam-log` rows are outside `dam-web`'s in-process event bus; SSE still invalidates in-process connect state changes immediately. The tiles link to `/allowed`, `/activity?decision=sealed&since=today`, and `/settings#apps`.

When `DAM_WEB_SHELL=tray`, `dam-web` renders the tray brand bar and the same Connect page inside the hosted WebView. Browser mode renders the same app navbar. Both surfaces show `[R:] DAM`, the divider line, and the connection status mark.

The `[R:]` brand mark uses `data-tray-external="rpblc"` in tray mode so `dam-tray` can open `https://rpblc.com` through the native shell. The tray `DAM` product stamp uses `data-tray-external="dam-web-tab"` and posts `dam-tray:open-dam-web` to the native shell. If `DAM_WEB_TRAY_POST_TOKEN` is set, React API calls include it as `x-dam-web-tray-token`.

Connect action wiring is intentionally narrow in this slice: browser-hosted `connect`, `resume`, and `pause` toggle the local protected state for the current process, while tray-hosted Connect posts native IPC so `dam-tray` can own privileged setup. The setup checklist distinguishes macOS System Extension approval (`ne_install`), reboot (`ne_reboot`), Network Extension manager configuration (`ne_config`), manager enablement (`ne_enable`), manager start/connection verification (`ne_start`), local CA trust, optional system-proxy fallback setup (`system_proxy`), and daemon start. Explicit-proxy profile apply is available from integrations/settings but is not part of Connect onboarding. Linux and Windows use separate stable setup ids (`linux_capture`, `windows_capture`) so their future onboarding can diverge without reusing macOS Network Extension copy. Unknown setup/recovery step ids still return `not_implemented`, and the frontend maps stable error codes to localized English and French copy instead of showing raw backend text.

## Activity

`GET /api/v1/activity?since=&decision=&q=` reads `dam-log` and maps person-facing events into the CTZN activity feed. The mapper currently includes:

- `policy_decision.allow` → `granted`
- `policy_decision.tokenize` / `policy_decision.redact` / `redaction.*` → `sealed`
- `policy_decision.block` → `denied`
- `proxy_forward.request_protection` → `granted`, `sealed`, or `denied` from the protection counts in the log message
- `proxy_failure.provider_down` → `denied`

When a proxy protection event does not carry an actor itself, `dam-web` derives the actor from another log row with the same operation id, such as `route_decision target=...` or `provider_forward_start provider=...`.

The Activity page polls this endpoint and uses catalog-driven English/French labels. The `[add]` and `[allow once]` row actions remain disabled until their wallet/consent semantics are implemented.

## Allowed

`GET /api/v1/allowed?q=&sort=&dir=` reads `dam-consent`, groups grants into active, expired, and revoked buckets, and joins each grant to `dam-vault` when the grant has a vault key. Grants without a resolvable vault value render a safe bracketed grant label instead of exposing the stored fingerprint.

The Allowed page uses the same English/French catalog as the rest of the React slice and is the destination for the Connect row's active-grants tile.

## Settings

`GET /api/v1/settings` builds a live view from `dam-daemon`, `dam-config`, and `dam-integrations`. The Apps section is wired: enabling an app records its profile as enabled; disabling clears that enabled state. The custom profile creator is parked, so Settings only shows catalog JSON profiles from `$DAM_STATE_DIR/integrations/profiles/`. When a running daemon exists, app toggles reconcile the platform capture scope from the enabled profiles and invoke `dam connect` with explicit `--traffic-app` and route-derived `--target` arguments so the daemon's active traffic routes match the new app selection. Turning every app off leaves an explicit empty enabled state, reconfigures macOS Network Extension capture with no protected hosts, and keeps unrelated traffic outside DAM.

The Network section is read-only and reflects the latest daemon state on disk. `ready` is true only when protection is enabled and every transparent AI interception route reports `ready`.

Defaults are shown as disabled controls in this slice. `POST /api/v1/settings/defaults`, reset, and uninstall still return `not_implemented` until the runtime settings store and destructive flows are designed end to end.

## Local Request Trigger

`POST /api/v1/requests/trigger` creates an in-memory pending consent request and marks the current `dam-web` process protected. It is for local QA and screenshots until request delivery moves to `dam-notify`.

```bash
curl -sS -X POST http://127.0.0.1:2896/api/v1/requests/trigger \
  -H 'Content-Type: application/json' \
  -H 'Origin: http://127.0.0.1:2896' \
  -d '{
    "actor": "anthropic",
    "value_label": "mobile phone",
    "value_preview": "+1 415 555 0142",
    "purpose": "send the verification code from your bank to confirm the wire",
    "expires_in_sec": 18000
  }'
```

Each `dam-web` process has its own request store. When web and tray are running on separate local ports, trigger the request on both ports to test both surfaces.

## Usage

```bash
dam web --config dam.example.toml
cargo run -p dam-web -- --config dam.example.toml
```

With explicit paths:

```bash
cargo run -p dam-web -- \
  --db vault.db \
  --log log.db \
  --addr 127.0.0.1:2896
```

Default address:

```text
127.0.0.1:2896
```

`--addr` must be loopback in the current local build.

## Config Requirements

`dam-web` currently requires:

- `vault.backend = "sqlite"`
- `consent.backend = "sqlite"` when consent is enabled
- `log.backend = "sqlite"`

Remote vault/consent/log views are not implemented yet.

## Localization

All visible text in the current React slice is catalog-driven in English and French. Runtime locale defaults to the system language and can be overridden with `localStorage["rpblc.dam.locale"] = "en"` or `"fr"`.

The full Lingui catalog flow in the architecture is not wired yet. The current UI keeps a small local typed catalog in `ui/src/lib/i18n.ts` so no visible text is hardcoded in page components.

## Security Posture

This UI displays vault values in clear text and can allow/protect canonical values. Treat it as a local development/admin tool, not a public-facing service.

Connect/settings mutation routes are POST-only and use the same local Host and Origin/Referer guardrails as consent mutation routes.

## Branding

The UI follows `RPBLC.Design`:

- Inlined RPBLC design tokens for color, type, spacing, motion, and geometry.
- Theme defaults to the system preference. Persisted System, Light, and Dark settings return with the Settings page.
- Warm gold accent.
- `[R:]` brand mark.
- Product stamp: `DAM`.
- Web frame: pinned top app navbar with `[R:] DAM`.
- Tray frame: same pinned app navbar with `[R:] DAM`; `DAM` opens the hosted browser view.
- App chrome uses the reversed bar treatment from `RPBLC.Design` so logged-in/local product surfaces are distinct from the public website while preserving the same mark size and glyph behavior.
- `@rpblc/design/fonts.css` is imported so the app uses the design-system faces everywhere: Manrope for reading text and JetBrains Mono for marks, labels, counters, and controls.
- `/favicon.svg` served from the same SVG as `RPBLC.public/public/favicon.svg`.
- External link to `https://rpblc.com`.

The local UI vendors the current `RPBLC.Design/src` under `ui/src/design-system` and aliases `@rpblc/design` to that copy. This keeps call sites aligned with the future package import while the generated design-system library is not available yet.

## React Shell

Source lives in:

```text
crates/dam-web/ui
```

Build the embedded asset with:

```bash
cd crates/dam-web/ui
npm install
npm run build
```

The build writes `crates/dam-web/assets/index.html`, `crates/dam-web/assets/bundle.js`, and `crates/dam-web/assets/bundle.css`, which are embedded into `dam-web` with `include_str!` and served locally. Runtime does not fetch React or app scripts from a CDN. Font loading follows `@rpblc/design/fonts.css` so DAM matches the public-site typography.

## Tests

```bash
npm run build --prefix crates/dam-web/ui
cargo test -p dam-web
```
