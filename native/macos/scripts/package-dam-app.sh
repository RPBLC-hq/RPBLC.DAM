#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
NATIVE="$ROOT/native/macos"
PROFILE_DIR="$HOME/Library/Developer/Xcode/UserData/Provisioning Profiles"
OUT_DIR="$ROOT/target/macos-package"
APP_NAME="DAM"
APP_BUNDLE_ID="com.rpblc.dam"
EXT_BUNDLE_ID="com.rpblc.dam.network-extension"
TEAM_ID="${DAM_MACOS_TEAM_ID:-}"
APP_GROUP_ID="${DAM_MACOS_APP_GROUP_ID:-}"
MODE="developer-id"
SIGN_OPTIONS=()

usage() {
  cat <<EOF
Usage: native/macos/scripts/package-dam-app.sh [--mode development|developer-id] [--out DIR]

Builds a signed DAM.app bundle with the macOS Network Extension system extension embedded.

Environment:
  DAM_MACOS_TEAM_ID       Optional Team ID override. Inferred from profiles by default.
  DAM_MACOS_APP_GROUP_ID  Optional App Group override. Defaults to TEAMID.com.rpblc.dam.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)
      MODE="${2:?--mode requires development or developer-id}"
      shift 2
      ;;
    --out)
      OUT_DIR="${2:?--out requires a directory}"
      shift 2
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

case "$MODE" in
  development)
    APP_PROFILE_NAME="DAM macOS App Development"
    EXT_PROFILE_NAME="DAM Network Extension Development"
    APP_ENTITLEMENTS_TEMPLATE="$NATIVE/Entitlements/DAM.app.development.entitlements"
    EXT_ENTITLEMENTS_TEMPLATE="$NATIVE/Entitlements/DAM.network-extension.development.entitlements"
    EXT_NETWORK_ENTITLEMENT="app-proxy-provider"
    SIGN_OPTIONS=()
    ;;
  developer-id)
    APP_PROFILE_NAME="DAM Developer ID App"
    EXT_PROFILE_NAME="DAM Developer ID Network Extension"
    APP_ENTITLEMENTS_TEMPLATE="$NATIVE/Entitlements/DAM.app.developer-id.entitlements"
    EXT_ENTITLEMENTS_TEMPLATE="$NATIVE/Entitlements/DAM.network-extension.developer-id.entitlements"
    EXT_NETWORK_ENTITLEMENT="app-proxy-provider-systemextension"
    SIGN_OPTIONS=(--options runtime --timestamp)
    ;;
  *)
    echo "invalid --mode: $MODE" >&2
    exit 2
    ;;
esac

decode_profile() {
  local profile="$1"
  local output="$2"
  openssl cms -verify -noverify -inform DER -in "$profile" -out "$output" >/dev/null 2>&1
}

profile_name() {
  /usr/libexec/PlistBuddy -c "Print :Name" "$1"
}

find_profile() {
  local wanted="$1"
  local profile plist
  while IFS= read -r profile; do
    plist="$(mktemp)"
    if decode_profile "$profile" "$plist" && [[ "$(profile_name "$plist")" == "$wanted" ]]; then
      rm -f "$plist"
      printf '%s\n' "$profile"
      return 0
    fi
    rm -f "$plist"
  done < <(find "$PROFILE_DIR" -maxdepth 1 -type f \( -name '*.mobileprovision' -o -name '*.provisionprofile' \) | sort)
  return 1
}

profile_certificate_sha1() {
  local profile="$1"
  local plist cert_xml cert_der fingerprint
  plist="$(mktemp)"
  cert_xml="$(mktemp)"
  cert_der="$(mktemp)"
  decode_profile "$profile" "$plist"
  /usr/libexec/PlistBuddy -x -c "Print :DeveloperCertificates:0" "$plist" > "$cert_xml"
  perl -0777 -ne 'if (m{<data>\s*(.*?)\s*</data>}s) { $x=$1; $x=~s/\s+//g; print $x; }' "$cert_xml" | base64 -D > "$cert_der"
  fingerprint="$(openssl x509 -inform DER -in "$cert_der" -noout -fingerprint -sha1 | sed 's/^.*=//; s/://g')"
  rm -f "$plist" "$cert_xml" "$cert_der"
  printf '%s\n' "$fingerprint"
}

identity_for_profile() {
  local profile="$1"
  local fingerprint
  fingerprint="$(profile_certificate_sha1 "$profile")"
  if security find-identity -v -p codesigning | grep -q "$fingerprint"; then
    printf '%s\n' "$fingerprint"
    return 0
  fi
  echo "no local signing identity matches profile certificate $fingerprint for $profile" >&2
  return 1
}

team_identifier_for_profile() {
  local profile="$1"
  local plist team
  plist="$(mktemp)"
  decode_profile "$profile" "$plist"
  team="$(/usr/libexec/PlistBuddy -c "Print :TeamIdentifier:0" "$plist")"
  rm -f "$plist"
  printf '%s\n' "$team"
}

require_profile_entitlement_contains() {
  local profile="$1"
  local profile_name="$2"
  local key="$3"
  local expected="$4"
  local plist actual
  plist="$(mktemp)"
  decode_profile "$profile" "$plist"
  if ! actual="$(/usr/libexec/PlistBuddy -c "Print :Entitlements:$key" "$plist" 2>/dev/null)"; then
    echo "provisioning profile $profile_name is missing entitlement $key" >&2
    echo "profile: $profile" >&2
    rm -f "$plist"
    exit 1
  fi
  rm -f "$plist"
  if ! grep -q "$expected" <<<"$actual"; then
    echo "provisioning profile $profile_name entitlement $key did not contain $expected" >&2
    echo "profile: $profile" >&2
    echo "$actual" >&2
    exit 1
  fi
}

require_signed_entitlement_contains() {
  local signed="$1"
  local key="$2"
  local expected="$3"
  local entitlements actual
  entitlements="$(mktemp)"
  if ! codesign --display --entitlements :- "$signed" > "$entitlements" 2>/dev/null; then
    echo "failed to read signed entitlements from $signed" >&2
    rm -f "$entitlements"
    exit 1
  fi
  if [[ ! -s "$entitlements" ]]; then
    echo "missing signed entitlements on $signed" >&2
    rm -f "$entitlements"
    exit 1
  fi
  if ! actual="$(/usr/libexec/PlistBuddy -c "Print :$key" "$entitlements" 2>/dev/null)"; then
    echo "missing signed entitlement $key on $signed" >&2
    rm -f "$entitlements"
    exit 1
  fi
  rm -f "$entitlements"
  if ! grep -q "$expected" <<<"$actual"; then
    echo "signed entitlement $key on $signed did not contain $expected" >&2
    echo "$actual" >&2
    exit 1
  fi
}

require_plist_nonempty() {
  local plist="$1"
  local key="$2"
  local value
  if ! value="$(/usr/libexec/PlistBuddy -c "Print :$key" "$plist" 2>/dev/null)"; then
    echo "missing Info.plist key $key in $plist" >&2
    exit 1
  fi
  if [[ -z "${value//[[:space:]]/}" ]]; then
    echo "empty Info.plist key $key in $plist" >&2
    exit 1
  fi
}

require_plist_value_prefixed_by() {
  local plist="$1"
  local key="$2"
  local prefix="$3"
  local value
  if ! value="$(/usr/libexec/PlistBuddy -c "Print :$key" "$plist" 2>/dev/null)"; then
    echo "missing Info.plist key $key in $plist" >&2
    exit 1
  fi
  if [[ "$value" != "$prefix"* ]]; then
    echo "Info.plist key $key in $plist must be prefixed with $prefix" >&2
    echo "actual: $value" >&2
    exit 1
  fi
}

sign_code() {
  local identity="$1"
  shift
  if [[ ${#SIGN_OPTIONS[@]} -gt 0 ]]; then
    codesign --force --sign "$identity" "${SIGN_OPTIONS[@]}" "$@"
  else
    codesign --force --sign "$identity" "$@"
  fi
}

materialize_template() {
  local template="$1"
  local output="$2"
  if [[ ! "$TEAM_ID" =~ ^[A-Z0-9]+$ ]]; then
    echo "invalid Team ID: $TEAM_ID" >&2
    exit 1
  fi
  if [[ ! "$APP_GROUP_ID" =~ ^(group|[A-Z0-9]+)\.[A-Za-z0-9.-]+$ ]]; then
    echo "invalid App Group ID: $APP_GROUP_ID" >&2
    echo "expected group.<name> or TEAMID.<name>" >&2
    exit 1
  fi
  sed \
    -e "s/__TEAM_ID__/$TEAM_ID/g" \
    -e "s/__APP_GROUP_ID__/$APP_GROUP_ID/g" \
    "$template" > "$output"
  plutil -lint "$output" >/dev/null
}

require_profile() {
  local name="$1"
  local profile
  if ! profile="$(find_profile "$name")"; then
    echo "missing provisioning profile: $name" >&2
    echo "install it under: $PROFILE_DIR" >&2
    exit 1
  fi
  printf '%s\n' "$profile"
}

APP_PROFILE="$(require_profile "$APP_PROFILE_NAME")"
EXT_PROFILE="$(require_profile "$EXT_PROFILE_NAME")"
APP_PROFILE_TEAM_ID="$(team_identifier_for_profile "$APP_PROFILE")"
EXT_PROFILE_TEAM_ID="$(team_identifier_for_profile "$EXT_PROFILE")"
TEAM_ID="${TEAM_ID:-$APP_PROFILE_TEAM_ID}"
if [[ "$EXT_PROFILE_TEAM_ID" != "$TEAM_ID" ]]; then
  echo "profile Team ID mismatch: app=$TEAM_ID extension=$EXT_PROFILE_TEAM_ID" >&2
  exit 1
fi
APP_GROUP_ID="${APP_GROUP_ID:-$TEAM_ID.$APP_BUNDLE_ID}"
APP_IDENTITY="$(identity_for_profile "$APP_PROFILE")"
EXT_IDENTITY="$(identity_for_profile "$EXT_PROFILE")"
require_profile_entitlement_contains "$APP_PROFILE" "$APP_PROFILE_NAME" "com.apple.developer.system-extension.install" "true"
require_profile_entitlement_contains "$APP_PROFILE" "$APP_PROFILE_NAME" "com.apple.security.application-groups" "$APP_GROUP_ID"
require_profile_entitlement_contains "$APP_PROFILE" "$APP_PROFILE_NAME" "com.apple.developer.networking.networkextension" "$EXT_NETWORK_ENTITLEMENT"
require_profile_entitlement_contains "$EXT_PROFILE" "$EXT_PROFILE_NAME" "com.apple.security.application-groups" "$APP_GROUP_ID"
require_profile_entitlement_contains "$EXT_PROFILE" "$EXT_PROFILE_NAME" "com.apple.developer.networking.networkextension" "$EXT_NETWORK_ENTITLEMENT"

ENTITLEMENTS_DIR="$OUT_DIR/entitlements/$MODE"
mkdir -p "$ENTITLEMENTS_DIR"
APP_ENTITLEMENTS="$ENTITLEMENTS_DIR/$(basename "$APP_ENTITLEMENTS_TEMPLATE")"
EXT_ENTITLEMENTS="$ENTITLEMENTS_DIR/$(basename "$EXT_ENTITLEMENTS_TEMPLATE")"
materialize_template "$APP_ENTITLEMENTS_TEMPLATE" "$APP_ENTITLEMENTS"
materialize_template "$EXT_ENTITLEMENTS_TEMPLATE" "$EXT_ENTITLEMENTS"

export CLANG_MODULE_CACHE_PATH="${CLANG_MODULE_CACHE_PATH:-$ROOT/target/macos-clang-module-cache}"
mkdir -p "$CLANG_MODULE_CACHE_PATH"

echo "Building Rust binaries..."
cargo build --release -p dam -p dam-web -p dam-proxy -p dam-mcp -p dam-daemon -p dam-tray

echo "Building native Swift helper/provider objects..."
swift build --package-path "$NATIVE" -c release

APP="$OUT_DIR/$APP_NAME.app"
CONTENTS="$APP/Contents"
MACOS="$CONTENTS/MacOS"
HELPERS="$CONTENTS/Helpers"
RESOURCES="$CONTENTS/Resources"
SYSTEM_EXTENSIONS="$CONTENTS/Library/SystemExtensions"
HELPER_APP="$HELPERS/DAMMacosNEHelper.app"
HELPER_CONTENTS="$HELPER_APP/Contents"
HELPER_MACOS="$HELPER_CONTENTS/MacOS"
HELPER_BIN="$HELPER_MACOS/dam-macos-ne-helper"
EXT="$SYSTEM_EXTENSIONS/$EXT_BUNDLE_ID.systemextension"
EXT_CONTENTS="$EXT/Contents"
EXT_MACOS="$EXT_CONTENTS/MacOS"
SWIFT_BUILD="$NATIVE/.build/arm64-apple-macosx/release"

rm -rf "$APP"
mkdir -p "$MACOS" "$RESOURCES" "$HELPER_MACOS" "$EXT_MACOS"

cp "$NATIVE/InfoPlists/DAM.Info.plist" "$CONTENTS/Info.plist"
cp "$NATIVE/InfoPlists/DAMMacosNEHelper.Info.plist" "$HELPER_CONTENTS/Info.plist"
materialize_template "$NATIVE/InfoPlists/DAMTransparentProxyProvider.Info.plist" "$EXT_CONTENTS/Info.plist"
plutil -lint "$HELPER_CONTENTS/Info.plist" >/dev/null
plutil -lint "$EXT_CONTENTS/Info.plist" >/dev/null
require_plist_nonempty "$EXT_CONTENTS/Info.plist" "NSSystemExtensionUsageDescription"
require_plist_nonempty "$EXT_CONTENTS/Info.plist" "NetworkExtension:NEMachServiceName"
require_plist_nonempty "$EXT_CONTENTS/Info.plist" "NetworkExtension:NEProviderClasses:com.apple.networkextension.app-proxy"
require_plist_value_prefixed_by "$EXT_CONTENTS/Info.plist" "NetworkExtension:NEMachServiceName" "$APP_GROUP_ID."
cp "$APP_PROFILE" "$CONTENTS/embedded.provisionprofile"
cp "$APP_PROFILE" "$HELPER_CONTENTS/embedded.provisionprofile"
cp "$EXT_PROFILE" "$EXT_CONTENTS/embedded.provisionprofile"

for bin in dam dam-web dam-proxy dam-mcp dam-daemon dam-tray; do
  cp "$ROOT/target/release/$bin" "$MACOS/$bin"
done
cp "$SWIFT_BUILD/dam-macos-ne-helper" "$HELPER_BIN"

echo "Linking transparent proxy provider bundle executable..."
xcrun swiftc \
  -emit-executable \
  -parse-as-library \
  -module-name DAMTransparentProxyProvider \
  -I "$SWIFT_BUILD/Modules" \
  "$NATIVE/Sources/DAMTransparentProxyProvider/DAMTransparentProxyProvider.swift" \
  "$NATIVE/Sources/DAMTransparentProxyProvider/FlowEndpoint.swift" \
  "$NATIVE/Sources/DAMTransparentProxyProvider/TCPFlowProxy.swift" \
  "$SWIFT_BUILD/DAMNetworkExtensionSupport.build/HelperOptions.swift.o" \
  "$SWIFT_BUILD/DAMNetworkExtensionSupport.build/RuntimeConfiguration.swift.o" \
  -framework Network \
  -framework NetworkExtension \
  -Xlinker -e \
  -Xlinker _NSExtensionMain \
  -o "$EXT_MACOS/DAMTransparentProxyProvider"

echo "Signing nested executables..."
for bin in dam dam-web dam-proxy dam-mcp dam-daemon; do
  sign_code "$APP_IDENTITY" "$MACOS/$bin"
done
sign_code "$APP_IDENTITY" --identifier "$APP_BUNDLE_ID" --entitlements "$APP_ENTITLEMENTS" "$HELPER_BIN"
sign_code "$APP_IDENTITY" --entitlements "$APP_ENTITLEMENTS" "$HELPER_APP"
sign_code "$APP_IDENTITY" --entitlements "$APP_ENTITLEMENTS" "$MACOS/dam-tray"

echo "Signing system extension..."
sign_code "$EXT_IDENTITY" --entitlements "$EXT_ENTITLEMENTS" "$EXT"

echo "Signing app bundle..."
sign_code "$APP_IDENTITY" --entitlements "$APP_ENTITLEMENTS" "$APP"

echo "Verifying signatures..."
codesign --verify --deep --strict --verbose=2 "$APP"
require_signed_entitlement_contains "$APP" "com.apple.developer.system-extension.install" "true"
require_signed_entitlement_contains "$APP" "com.apple.security.application-groups" "$APP_GROUP_ID"
require_signed_entitlement_contains "$APP" "com.apple.developer.networking.networkextension" "$EXT_NETWORK_ENTITLEMENT"
require_signed_entitlement_contains "$HELPER_APP" "com.apple.developer.system-extension.install" "true"
require_signed_entitlement_contains "$HELPER_APP" "com.apple.security.application-groups" "$APP_GROUP_ID"
require_signed_entitlement_contains "$HELPER_APP" "com.apple.developer.networking.networkextension" "$EXT_NETWORK_ENTITLEMENT"
require_signed_entitlement_contains "$HELPER_BIN" "com.apple.developer.system-extension.install" "true"
require_signed_entitlement_contains "$HELPER_BIN" "com.apple.security.application-groups" "$APP_GROUP_ID"
require_signed_entitlement_contains "$HELPER_BIN" "com.apple.developer.networking.networkextension" "$EXT_NETWORK_ENTITLEMENT"
require_signed_entitlement_contains "$MACOS/dam-tray" "com.apple.security.application-groups" "$APP_GROUP_ID"
require_signed_entitlement_contains "$MACOS/dam-tray" "com.apple.developer.networking.networkextension" "$EXT_NETWORK_ENTITLEMENT"
require_signed_entitlement_contains "$EXT" "com.apple.developer.networking.networkextension" "$EXT_NETWORK_ENTITLEMENT"
require_signed_entitlement_contains "$EXT" "com.apple.security.application-groups" "$APP_GROUP_ID"

cat <<EOF

Packaged:
  $APP

Mode:
  $MODE

Team:
  $TEAM_ID

App Group:
  $APP_GROUP_ID

EOF
