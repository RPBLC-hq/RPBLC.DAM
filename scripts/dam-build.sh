#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${DAM_BUILD_OUT:-$ROOT/target/dam-build}"
MACOS_OUT="${DAM_MACOS_OUT:-$OUT_DIR/macos}"
SIGN_MODE="${DAM_SIGN_MODE:-developer-id}"
NOTARY_PROFILE="${DAM_NOTARY_PROFILE:-DAM-notary}"
INSTALL_DIR="${DAM_INSTALL_DIR:-/Applications}"

usage() {
  cat <<EOF
Usage: scripts/dam-build.sh <command> [options]

Commands:
  check          Run the standard local/CI verification suite
  dev           Build source-tree debug binaries used by local DAM runs
  macos-app     Build signed DAM.app through native/macos packaging
  notarize      Notarize and staple an existing DAM.app
  release-macos Run checks, build signed DAM.app, notarize, staple, and zip it
  deploy-local  Build signed DAM.app and copy it to /Applications or --install-dir

Options:
  --mode development|developer-id  Signing mode for macOS app packaging
  --out DIR                        Build artifact output directory
  --app PATH                       Existing DAM.app for notarize/deploy-local
  --notary-profile NAME            notarytool keychain profile name
  --install-dir DIR                Destination for deploy-local
  --skip-checks                    Skip check phase in release-macos
  -h, --help                       Show this help

Environment:
  DAM_BUILD_OUT             Default artifact root, currently target/dam-build
  DAM_SIGN_MODE             development or developer-id, currently developer-id
  DAM_NOTARY_PROFILE        notarytool keychain profile, currently DAM-notary
  DAM_MACOS_TEAM_ID         Optional Team ID override for macOS packaging
  DAM_MACOS_APP_GROUP_ID    Optional App Group override for macOS packaging
EOF
}

run() {
  printf '+'
  printf ' %q' "$@"
  printf '\n'
  "$@"
}

require_macos() {
  if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "macOS packaging/notarization requires Darwin" >&2
    exit 1
  fi
}

dam_app_path() {
  printf '%s/DAM.app\n' "$MACOS_OUT"
}

zip_path_for_app() {
  local app="$1"
  local base
  base="$(basename "$app" .app)"
  printf '%s/%s-notary.zip\n' "$(dirname "$app")" "$base"
}

cmd_check() {
  if [[ -f "$ROOT/crates/dam-web/ui/package.json" ]]; then
    run npm ci --prefix "$ROOT/crates/dam-web/ui"
    run npm run build --prefix "$ROOT/crates/dam-web/ui"
  fi
  run cargo fmt --all --check
  run cargo clippy --workspace -- -D warnings
  run cargo test --workspace
  if [[ -f "$ROOT/native/macos/Package.swift" && "$(uname -s)" == "Darwin" ]]; then
    run swift test --package-path "$ROOT/native/macos"
  fi
}

cmd_dev() {
  run cargo build -p dam -p damctl -p dam-web -p dam-tray
}

cmd_macos_app() {
  require_macos
  run "$ROOT/native/macos/scripts/package-dam-app.sh" --mode "$SIGN_MODE" --out "$MACOS_OUT"
}

cmd_notarize() {
  require_macos
  local app="${APP_PATH:-$(dam_app_path)}"
  if [[ ! -d "$app" ]]; then
    echo "missing app bundle: $app" >&2
    exit 1
  fi
  local zip
  zip="$(zip_path_for_app "$app")"
  rm -f "$zip"
  run ditto -c -k --keepParent "$app" "$zip"
  run xcrun notarytool submit "$zip" --keychain-profile "$NOTARY_PROFILE" --wait
  run xcrun stapler staple "$app"
  run xcrun stapler validate "$app"
  printf 'Notarized app: %s\n' "$app"
  printf 'Notary zip: %s\n' "$zip"
}

cmd_release_macos() {
  require_macos
  if [[ "${SKIP_CHECKS:-0}" != "1" ]]; then
    cmd_check
  fi
  cmd_macos_app
  APP_PATH="$(dam_app_path)" cmd_notarize
  local app release_zip
  app="$(dam_app_path)"
  release_zip="$MACOS_OUT/DAM-macos-${SIGN_MODE}.zip"
  rm -f "$release_zip"
  run ditto -c -k --keepParent "$app" "$release_zip"
  printf 'Release app: %s\n' "$app"
  printf 'Release zip: %s\n' "$release_zip"
}

cmd_deploy_local() {
  require_macos
  local app="${APP_PATH:-}"
  if [[ -z "$app" ]]; then
    cmd_macos_app
    app="$(dam_app_path)"
  fi
  if [[ ! -d "$app" ]]; then
    echo "missing app bundle: $app" >&2
    exit 1
  fi
  local destination="$INSTALL_DIR/DAM.app"
  rm -rf "$destination"
  run ditto "$app" "$destination"
  printf 'Installed local app: %s\n' "$destination"
}

COMMAND="${1:-}"
if [[ -z "$COMMAND" || "$COMMAND" == "-h" || "$COMMAND" == "--help" ]]; then
  usage
  exit 0
fi
shift

APP_PATH=""
SKIP_CHECKS=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)
      SIGN_MODE="${2:?--mode requires development or developer-id}"
      shift 2
      ;;
    --out)
      OUT_DIR="${2:?--out requires a directory}"
      MACOS_OUT="$OUT_DIR/macos"
      shift 2
      ;;
    --app)
      APP_PATH="${2:?--app requires a path}"
      shift 2
      ;;
    --notary-profile)
      NOTARY_PROFILE="${2:?--notary-profile requires a name}"
      shift 2
      ;;
    --install-dir)
      INSTALL_DIR="${2:?--install-dir requires a directory}"
      shift 2
      ;;
    --skip-checks)
      SKIP_CHECKS=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

case "$SIGN_MODE" in
  development|developer-id) ;;
  *)
    echo "invalid signing mode: $SIGN_MODE" >&2
    exit 2
    ;;
esac

mkdir -p "$OUT_DIR" "$MACOS_OUT"

case "$COMMAND" in
  check) cmd_check ;;
  dev) cmd_dev ;;
  macos-app) cmd_macos_app ;;
  notarize) cmd_notarize ;;
  release-macos) cmd_release_macos ;;
  deploy-local) cmd_deploy_local ;;
  *)
    echo "unknown command: $COMMAND" >&2
    usage >&2
    exit 2
    ;;
esac
