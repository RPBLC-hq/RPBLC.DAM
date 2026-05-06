# Build And Release

`scripts/dam-build.sh` is the standard local and CI entry point for DAM builds.

## Commands

```bash
scripts/dam-build.sh check
scripts/dam-build.sh dev
scripts/dam-build.sh macos-app --mode developer-id
scripts/dam-build.sh notarize --app target/dam-build/macos/DAM.app --notary-profile DAM-notary
scripts/dam-build.sh release-macos --mode developer-id
scripts/dam-build.sh deploy-local --mode development
```

`check` runs the repository verification suite: React/Vite UI dependency install and build for the embedded `dam-web` asset, Rust formatting, workspace clippy, workspace tests, and macOS Swift package tests when running on macOS.

`dev` builds the source-tree binaries used by local daemon/tray runs: `dam`, `damctl`, `dam-web`, and `dam-tray`.

`macos-app` delegates signed app assembly to `native/macos/scripts/package-dam-app.sh`, keeping entitlement and provisioning validation in the native macOS packaging script.

`notarize` zips an existing `DAM.app`, submits it with `xcrun notarytool`, staples the ticket, and validates the stapled app.

`release-macos` runs `check`, builds a signed Developer ID app by default, notarizes/staples it, and writes a release zip under `target/dam-build/macos`.

`deploy-local` builds or accepts an existing `DAM.app` and copies it to `/Applications` by default.

## Environment

- `DAM_BUILD_OUT`: artifact root, default `target/dam-build`.
- `DAM_SIGN_MODE`: `development` or `developer-id`, default `developer-id`.
- `DAM_NOTARY_PROFILE`: notarytool keychain profile, default `DAM-notary`.
- `DAM_MACOS_TEAM_ID`: optional Team ID override passed through to macOS packaging.
- `DAM_MACOS_APP_GROUP_ID`: optional App Group override passed through to macOS packaging.
- `DAM_INSTALL_DIR`: local deploy destination, default `/Applications`.

The script intentionally keeps signing, provisioning, and notarization inputs in environment variables or keychain profiles. It must not require secrets in repository files.
