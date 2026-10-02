#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright the Karst contributors.
#
# Build one architecture's Mac App Store client package — a sibling to
# scripts/build-macos-pkg.sh (the Developer-ID build), not a variant of it.
# docs/adr/0040-mac-app-store-needs-a-sandboxed-app-extension.md,
# docs/adr/0043-mac-app-store-sandboxed-app-extension-target.md.
#
# ## Why this is a separate script, not a flag on build-macos-pkg.sh
#
# The two builds differ in almost everything that script does: a different
# host app (KarstAppStore, sandboxed) and extension
# (KarstPacketTunnelAppExtension, an `.appex` staged at
# `Contents/PlugIns/`, not a System Extension at
# `Contents/Library/SystemExtensions/`), a different signing identity type
# ("Apple Distribution", not "Developer ID Application" — unverified naming,
# see the codesign step below), no `karst` CLI or LaunchAgent component (this
# target's minimal-viable scope, ADR-0043, has no exit-node menu to need
# either), and no notarization step at all: Mac App Store submissions go
# through App Review, not `notarytool` — only `appstore-submit-macos.sh`'s
# own final `productsign` with the Store installer certificate remains after
# this script runs. Folding both into one script with a mode flag would make
# every one of those differences conditional, which is harder to read than
# two scripts sharing a shape.
#
# ## Signing is conditional, same reasoning as build-macos-pkg.sh
#
# No Apple Developer Program Mac App Store certificates/App ID/provisioning
# profiles exist in this environment — same position the Developer-ID build
# was in before its own certificates arrived. This builds an unsigned
# package and says so loudly unless `--require-signing` is passed, exactly
# like build-macos-pkg.sh.
#
# ## Credentials
#
#   KARST_APPSTORE_APP_CODESIGN_IDENTITY        "Apple Distribution: ..." —
#                                                 the binaries/app/extension
#   KARST_APPSTORE_PROVISION_PROFILE_HOST        path to KarstAppStore's
#                                                 "Mac App Store"/"Apple
#                                                 Distribution" .provisionprofile
#                                                 (dev.karst.appstore)
#   KARST_APPSTORE_PROVISION_PROFILE_EXTENSION   as above, for
#                                                 dev.karst.appstore.packettunnel
#
# Restricted entitlements (com.apple.developer.networking.networkextension,
# com.apple.security.application-groups) need an embedded provisioning
# profile to validate under AMFI even once signing/notarization succeed —
# see build-macos-pkg.sh's own header comment for the real-hardware failure
# this same requirement caused on the Developer-ID build (#159): the same
# class of failure applies here, unverified only because no real App Store
# certificates exist yet to hit it against.
#
# `KARST_APPSTORE_APP_CODESIGN_IDENTITY` may be left unset and will then be
# looked up in the keychain. The final installer-level signature
# (`appstore-submit-macos.sh`'s own `productsign` with
# `KARST_APPSTORE_IDENTITY`, a *different*, "3rd Party Mac Developer
# Installer"-type certificate) is deliberately not done here — this script's
# `.pkg` output is unsigned at the installer level, same division of labor
# build-macos-pkg.sh already has between its own `codesign`/`productsign`
# steps and this document's separate submission script.

set -euo pipefail

arch=""
require_signing=0
while [ $# -gt 0 ]; do
  case "$1" in
    --arch)
      arch="${2:-}"
      shift 2
      ;;
    --arch=*)
      arch="${1#--arch=}"
      shift
      ;;
    --require-signing)
      require_signing=1
      shift
      ;;
    *)
      echo "usage: $0 --arch <arm64|x86_64> [--require-signing]" >&2
      exit 2
      ;;
  esac
done

case "$arch" in
  arm64)  rust_target=aarch64-apple-darwin ;;
  x86_64) rust_target=x86_64-apple-darwin ;;
  *)
    echo "usage: $0 --arch <arm64|x86_64> [--require-signing]" >&2
    echo "error: --arch is required and must be arm64 or x86_64" >&2
    exit 2
    ;;
esac

# Same "Swift Build" backend workaround as build-macos-pkg.sh — see that
# script's own comment (#159): the header-only CKarstFFI target fails to
# link under Apple's newer default backend on a recent enough toolchain.
swift_build_flags=(--build-system native)

if [ "$(uname -s)" != "Darwin" ]; then
  echo "error: this builds a macOS package and needs macOS — pkgbuild," >&2
  echo "       productbuild, codesign and lipo have no Linux equivalents." >&2
  exit 1
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
version="${VERSION:-0.0.0+git.$(git -C "$root" rev-parse --short HEAD 2>/dev/null || echo unknown)}"
pkg_version="${version%%[-+]*}"
bundle_version="$(date -u +%Y%m%d%H%M%S)"

dist="$root/dist/macos"
stage="$dist/root-appstore-$arch"
rm -rf "$stage"
mkdir -p "$dist" "$stage/Applications"

# ── the host app (Swift) ─────────────────────────────────────────────────
echo "==> building KarstAppStore ($arch)"
(cd "$root/packaging/macos/KarstAppStore" && swift build -c release --arch "$arch" "${swift_build_flags[@]}")
host_bin_dir="$(cd "$root/packaging/macos/KarstAppStore" && swift build -c release --arch "$arch" "${swift_build_flags[@]}" --show-bin-path)"
host_bin="$host_bin_dir/KarstAppStore"
[ -x "$host_bin" ] \
  || { echo "error: KarstAppStore build did not produce $host_bin" >&2; exit 1; }
lipo -info "$host_bin"

app="$stage/Applications/Karst.app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources" "$app/Contents/PlugIns"
cp "$host_bin" "$app/Contents/MacOS/KarstAppStore"
chmod 0755 "$app/Contents/MacOS/KarstAppStore"
cp "$root/packaging/macos/KarstAppStore/Info.plist" "$app/Contents/Info.plist"
plutil -replace CFBundleShortVersionString -string "$pkg_version" "$app/Contents/Info.plist"
plutil -replace CFBundleVersion -string "$bundle_version" "$app/Contents/Info.plist"

# ── the app icon ─────────────────────────────────────────────────────────
# Reuses KarstStatus's own source icon — one visual identity for Karst
# across both distribution channels, same `sips`/`iconutil` pipeline
# build-macos-pkg.sh already uses (see that script's own comment for why
# this step is macOS-only and so cannot happen earlier than this).
echo "==> building AppIcon.icns"
iconset="$dist/AppIcon-appstore-$arch.iconset"
rm -rf "$iconset"
mkdir -p "$iconset"
icon_src="$root/packaging/macos/KarstStatus/Resources/AppIcon.png"
for size in 16 32 128 256 512; do
  sips -z "$size" "$size" "$icon_src" --out "$iconset/icon_${size}x${size}.png" >/dev/null
  double=$((size * 2))
  sips -z "$double" "$double" "$icon_src" --out "$iconset/icon_${size}x${size}@2x.png" >/dev/null
done
iconutil -c icns "$iconset" -o "$app/Contents/Resources/AppIcon.icns"
rm -rf "$iconset"

# ── the packet-tunnel App Extension (Swift) ─────────────────────────────
#
# `.appex`, staged at Contents/PlugIns/ — Apple's required location for an
# App Extension, distinct from the System Extension's
# Contents/Library/SystemExtensions/ (build-macos-pkg.sh's own comment).
echo "==> building karst-ffi ($arch)"
(cd "$root" && MACOSX_DEPLOYMENT_TARGET=13.0 cargo build --locked --release \
    --target "$rust_target" --package karst-ffi --features network-extension)
export KARST_FFI_LIB_DIR="$root/target/$rust_target/release"

echo "==> building KarstPacketTunnelAppExtension ($arch)"
(cd "$root/packaging/macos/KarstPacketTunnelAppExtension" && swift build -c release --arch "$arch" "${swift_build_flags[@]}")
appex_bin_dir="$(cd "$root/packaging/macos/KarstPacketTunnelAppExtension" && swift build -c release --arch "$arch" "${swift_build_flags[@]}" --show-bin-path)"
appex_bin="$appex_bin_dir/KarstPacketTunnelAppExtension"
[ -x "$appex_bin" ] \
  || { echo "error: KarstPacketTunnelAppExtension build did not produce $appex_bin" >&2; exit 1; }
lipo -info "$appex_bin"

appex="$app/Contents/PlugIns/dev.karst.appstore.packettunnel.appex"
mkdir -p "$appex/Contents/MacOS"
cp "$appex_bin" "$appex/Contents/MacOS/KarstPacketTunnelAppExtension"
chmod 0755 "$appex/Contents/MacOS/KarstPacketTunnelAppExtension"
cp "$root/packaging/macos/KarstPacketTunnelAppExtension/Info.plist" "$appex/Contents/Info.plist"
plutil -replace CFBundleShortVersionString -string "$pkg_version" "$appex/Contents/Info.plist"
plutil -replace CFBundleVersion -string "$bundle_version" "$appex/Contents/Info.plist"

# ── signing ──────────────────────────────────────────────────────────────
find_identity() {
  security find-identity -v -p "$2" 2>/dev/null \
    | grep "$1" | head -1 | sed 's/.*"\(.*\)"/\1/'
}

codesign_with_timestamp() {
  local attempt=1
  local maximum_attempts=3

  while ! codesign --force --options runtime --timestamp "$@"; do
    if [ "$attempt" -ge "$maximum_attempts" ]; then
      echo "error: codesign could not obtain a secure timestamp after $attempt attempts" >&2
      return 1
    fi
    echo "warning: codesign timestamp attempt $attempt failed; retrying" >&2
    attempt=$((attempt + 1))
    sleep 5
  done
}

# "Apple Distribution" — the unified cert type covering Mac App Store
# distribution since Xcode 11 (older tooling calls the same role "3rd Party
# Mac Developer Application"). Not verified against a real certificate in
# this environment; flagged rather than asserted, same honesty convention
# as the rest of this target (ADR-0043).
codesign_identity="${KARST_APPSTORE_APP_CODESIGN_IDENTITY:-$(find_identity 'Apple Distribution' codesigning || true)}"

if [ -n "$codesign_identity" ]; then
  if [ -n "${KARST_APPSTORE_PROVISION_PROFILE_EXTENSION:-}" ]; then
    echo "==> embedding the App Extension's provisioning profile"
    cp "$KARST_APPSTORE_PROVISION_PROFILE_EXTENSION" "$appex/Contents/embedded.provisionprofile"
  else
    echo "==> no KARST_APPSTORE_PROVISION_PROFILE_EXTENSION: the extension's" \
      "restricted entitlements will not validate under AMFI even fully signed"
  fi
  echo "==> codesign KarstPacketTunnelAppExtension.appex"
  codesign_with_timestamp \
    --entitlements "$root/packaging/macos/KarstPacketTunnelAppExtension/PacketTunnelAppExtension.entitlements" \
    --sign "$codesign_identity" "$appex"
  codesign --verify --strict --verbose=2 "$appex"

  if [ -n "${KARST_APPSTORE_PROVISION_PROFILE_HOST:-}" ]; then
    echo "==> embedding Karst.app's provisioning profile"
    cp "$KARST_APPSTORE_PROVISION_PROFILE_HOST" "$app/Contents/embedded.provisionprofile"
  else
    echo "==> no KARST_APPSTORE_PROVISION_PROFILE_HOST: the host app's" \
      "restricted entitlements will not validate under AMFI even fully signed"
  fi
  echo "==> codesign Karst.app"
  codesign_with_timestamp \
    --entitlements "$root/packaging/macos/KarstAppStore/Karst-AppStore.entitlements" \
    --sign "$codesign_identity" "$app"
  codesign --verify --strict --verbose=2 "$app"
else
  echo "==> no Apple Distribution identity: KarstPacketTunnelAppExtension.appex and Karst.app will be UNSIGNED"
  [ "$require_signing" -eq 0 ] || { echo "error: --require-signing" >&2; exit 1; }
fi

# ── the package ──────────────────────────────────────────────────────────
#
# Deliberately left unsigned at the installer level — see this script's own
# header comment on the division of labor with appstore-submit-macos.sh,
# which productsigns with the Store's own installer certificate before
# upload. No notarization section: App Store submissions go through App
# Review instead.
component_dir="$dist/components-appstore-$arch"
rm -rf "$component_dir"
mkdir -p "$component_dir"
product="$dist/karst-appstore-macos-$arch.pkg"

echo "==> pkgbuild (Karst App Store, $arch)"
echo "==> staged tree before pkgbuild:"
find "$stage" | sort

# Same `--analyze`/force-unrelocatable fix as build-macos-pkg.sh — see that
# script's own comment on why pkgbuild's default relocation heuristic can
# silently skip placing the payload.
component_plist="$component_dir/karst-appstore-component.plist"
pkgbuild --analyze --root "$stage" "$component_plist"
bundle_index=0
while plutil -extract "$bundle_index.BundleIsRelocatable" raw "$component_plist" >/dev/null 2>&1; do
  plutil -replace "$bundle_index.BundleIsRelocatable" -bool NO "$component_plist"
  plutil -replace "$bundle_index.BundleIsVersionChecked" -bool NO "$component_plist"
  bundle_index=$((bundle_index + 1))
done
[ "$bundle_index" -ge 1 ] \
  || { echo "error: pkgbuild --analyze found no bundle components under $stage, expected 1 (Karst.app)" >&2; exit 1; }

component="$component_dir/karst-appstore-component.pkg"
pkgbuild \
  --root "$stage" \
  --component-plist "$component_plist" \
  --identifier dev.karst.appstore \
  --version "$pkg_version" \
  --install-location / \
  --ownership recommended \
  "$component"

echo "==> productbuild ($arch)"
productbuild \
  --package "$component" \
  "$product"

rm -rf "$component_dir"
shasum -a 256 "$product" | tee "$product.sha256"
echo "==> $product"
