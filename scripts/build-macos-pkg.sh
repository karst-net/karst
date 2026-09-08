#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright the Karst contributors.
#
# Build one architecture's macOS client package: a native .pkg for arm64 or
# x86_64, and — when the Apple credentials are present — signing,
# notarization and stapling.
#
# ## Why arch-specific rather than universal
#
# An earlier version of this script joined both architectures with `lipo`
# into one fat binary and shipped a single `karst-client-macos.pkg`. A
# universal binary's arm64 slice runs natively — it does not invoke Rosetta —
# but every download carries the other architecture's bytes too, whichever
# machine it lands on. Building one architecture at a time and shipping
# `karst-client-macos-<arch>.pkg` separately halves the download for the
# common case. The cost is running this script twice — once per `--arch` — and
# signing/notarizing twice; `just macos-package` and the `deliverables.yml`
# `macos-package` matrix both do that so nobody has to remember to.
#
# ## Why the signing is conditional rather than required
#
# The Developer ID certificates come from an Apple Developer Program
# organization membership, which takes weeks to obtain and can stall on a
# legal-entity mismatch (plans/phase-5/06-macos-client.md §7). Until it lands,
# and on every pull request from a fork afterwards, there are no secrets to
# sign with. Two ways to handle that:
#
#   - refuse to build, which means nobody can build a macOS package at all
#     until the paperwork clears; or
#   - build an unsigned package and say so.
#
# This does the second, loudly. An unsigned .pkg is exactly as useful as it
# sounds — Gatekeeper refuses it on any machine that did not build it — but it
# proves the packaging works, which is the thing CI is for. Pass
# `--require-signing` to make the absence fatal instead; the release pipeline
# does, so a tag can never quietly produce an unsigned artifact.
#
# ## Credentials
#
#   KARST_CODESIGN_IDENTITY    "Developer ID Application: ..."  — the binaries
#   KARST_INSTALLER_IDENTITY   "Developer ID Installer: ..."    — the .pkg
#   KARST_NOTARY_KEY           path to the App Store Connect .p8 private key
#   KARST_NOTARY_KEY_ID        its key id
#   KARST_NOTARY_ISSUER        the issuer UUID
#
# Either identity may be left unset and will then be looked up in the keychain.
# Notarization runs only if all three notary variables are set: it is slow and
# rate-limited, so a per-push notarization queue is a per-push wait.

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

if [ "$(uname -s)" != "Darwin" ]; then
  echo "error: this builds a macOS package and needs macOS — pkgbuild," >&2
  echo "       productbuild, codesign and lipo have no Linux equivalents." >&2
  exit 1
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
version="${VERSION:-0.0.0+git.$(git -C "$root" rev-parse --short HEAD 2>/dev/null || echo unknown)}"
# pkgbuild's --version must be a plain dotted number; the full version with its
# git metadata or pre-release label (e.g. "0.1.0-rc.1") goes in the filename
# and in `karst --version`, which is where anyone actually looks for it.
pkg_version="${version%%[-+]*}"

# Everything below is namespaced by $arch and lives under one shared
# dist/macos, rather than each build wiping the directory: building both
# architectures in sequence (as a developer running `just macos-package`
# would) must leave both .pkg files behind, not just the second one.
dist="$root/dist/macos"
stage="$dist/root-$arch"
stage_status="$dist/root-status-$arch"
rm -rf "$stage" "$stage_status"
mkdir -p "$dist" \
  "$stage/usr/local/bin" "$stage/Library/LaunchDaemons" "$stage/etc/karst" \
  "$stage_status/Applications" "$stage_status/Library/LaunchAgents"

# ── the native binaries ─────────────────────────────────────────────────────
echo "==> building $rust_target"
rustup target add "$rust_target" >/dev/null
(cd "$root" && cargo build --locked --release --target "$rust_target" \
    --package karstd --package karst-cli)

for binary in karstd karst; do
  install -m 0755 "$root/target/$rust_target/release/$binary" "$stage/usr/local/bin/$binary"
done
lipo -info "$stage/usr/local/bin/karstd"

cp "$root/packaging/macos/dev.karst.karstd.plist" "$stage/Library/LaunchDaemons/"
chmod 0644 "$stage/Library/LaunchDaemons/dev.karst.karstd.plist"
cp "$root/docs/karstd-example.toml" "$stage/etc/karst/karstd.toml.example"
cp "$root/packaging/macos/uninstall.sh" "$stage/usr/local/bin/karst-uninstall"
chmod 0755 "$stage/usr/local/bin/karst-uninstall"

# ── the menu-bar status app (Swift) ─────────────────────────────────────────
#
# One `--arch` rather than two: a single-arch `swift build` lands its binary
# under `.build/<arch>-apple-macosx/release/`, not the `.build/apple/...`
# layout a multi-arch (`--arch` passed twice) build uses for its fat binary.
# `--show-bin-path` asks SwiftPM for that directory directly instead of this
# script hardcoding a path that is a SwiftPM implementation detail.
echo "==> building KarstStatus ($arch)"
(cd "$root/packaging/macos/KarstStatus" && swift build -c release --arch "$arch")
status_bin_dir="$(cd "$root/packaging/macos/KarstStatus" && swift build -c release --arch "$arch" --show-bin-path)"
status_bin="$status_bin_dir/KarstStatus"
[ -x "$status_bin" ] \
  || { echo "error: KarstStatus build did not produce $status_bin" >&2; exit 1; }
lipo -info "$status_bin"

app="$stage_status/Applications/Karst.app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
cp "$status_bin" "$app/Contents/MacOS/KarstStatus"
chmod 0755 "$app/Contents/MacOS/KarstStatus"
cp "$root/packaging/macos/KarstStatus/Info.plist" "$app/Contents/Info.plist"
# The template ships "0.0.0" — see its own comment. Both keys, because
# Gatekeeper and Spotlight read `CFBundleShortVersionString` but some
# tooling (and a `defaults read`) expects `CFBundleVersion` too, and a
# mismatch between them is worse than redundancy.
plutil -replace CFBundleShortVersionString -string "$pkg_version" "$app/Contents/Info.plist"
plutil -replace CFBundleVersion -string "$pkg_version" "$app/Contents/Info.plist"

cp "$root/packaging/macos/dev.karst.karststatus.plist" "$stage_status/Library/LaunchAgents/"
chmod 0644 "$stage_status/Library/LaunchAgents/dev.karst.karststatus.plist"

# ── the guided-enrollment prompt (shell + osascript) ────────────────────────
#
# Karst's Linux counterpart, packaging/desktop/karst-setup, is a regular file
# on $PATH launched by a .desktop entry; this one instead ships as a resource
# inside Karst.app, run by AppDelegate.swift's "Setup…" menu item
# (Process + /bin/bash) rather than opened directly — a plain resource file
# needs no Info.plist, no CFBundleExecutable, and no second `pkgutil` receipt
# of its own the way a standalone Karst Setup.app once did.
echo "==> staging Karst Setup"
cp "$root/packaging/macos/karst-setup" "$app/Contents/Resources/karst-setup"
chmod 0755 "$app/Contents/Resources/karst-setup"

# ── signing the binaries ────────────────────────────────────────────────────
# The policy argument is not decoration. `-p codesigning` lists only identities
# valid for signing *code*, and a Developer ID Installer certificate is not one
# — it signs installer packages, `productsign` is its only consumer, and it is
# absent from that list even when it is sitting in the keychain. Looking it up
# under the codesigning policy therefore finds nothing, and a tag build, which
# passes --require-signing, fails at productsign with the certificate present
# and correct. The installer identity is looked up under `basic`, which is the
# plain "is this certificate valid" policy.
find_identity() {
  security find-identity -v -p "$2" 2>/dev/null \
    | grep "$1" | head -1 | sed 's/.*"\(.*\)"/\1/'
}

codesign_identity="${KARST_CODESIGN_IDENTITY:-$(find_identity 'Developer ID Application' codesigning || true)}"
installer_identity="${KARST_INSTALLER_IDENTITY:-$(find_identity 'Developer ID Installer' basic || true)}"

if [ -n "$codesign_identity" ]; then
  for binary in karstd karst; do
    echo "==> codesign $binary"
    # `--options runtime` is the hardened runtime, and notarization rejects a
    # binary without it. `--timestamp` gets a secure timestamp from Apple, and
    # notarization rejects a binary without that too. Both are the first
    # rejections to expect, which is why neither is optional here.
    codesign --force --options runtime --timestamp \
      --sign "$codesign_identity" "$stage/usr/local/bin/$binary"
    codesign --verify --strict --verbose=2 "$stage/usr/local/bin/$binary"
  done
  echo "==> codesign Karst.app"
  # Signs the whole bundle in one pass, karst-setup resource included —
  # `codesign` seals everything under Contents/ into one bundle signature;
  # a plain (non-executable-Mach-O) resource file needs no signature of its
  # own to be covered by it.
  codesign --force --options runtime --timestamp \
    --sign "$codesign_identity" "$app"
  codesign --verify --strict --verbose=2 "$app"
else
  echo "==> no Developer ID Application identity: binaries and Karst.app will be UNSIGNED"
  [ "$require_signing" -eq 0 ] || { echo "error: --require-signing" >&2; exit 1; }
fi

# ── the packages ─────────────────────────────────────────────────────────────
#
# Two `pkgbuild` components from the two staging roots, one `productbuild`
# distribution over both — plans/phase-6/13-macos-status-indicators.md:
# users should not have to download two files for one feature. Separate
# components rather than one merged root because they need different
# install scripts (status-scripts/ never touches /etc/karst or the daemon's
# config) and because separate `pkgutil` receipts mean either can be
# inspected, upgraded or removed without the other — see uninstall.sh, which
# removes both from one place but treats them as two things throughout.
#
# The component files themselves keep the plain names `Distribution.xml`
# refers to (`karst-component.pkg`, `karst-status-component.pkg`) — that XML
# is shared across both architectures rather than templated per-arch — so
# they are staged in an arch-namespaced directory instead of being renamed;
# `productbuild --package-path` just points at that directory.
component_dir="$dist/components-$arch"
rm -rf "$component_dir"
mkdir -p "$component_dir"
component="$component_dir/karst-component.pkg"
status_component="$component_dir/karst-status-component.pkg"
product="$dist/karst-client-macos-$arch.pkg"

echo "==> pkgbuild (karstd, $arch)"
pkgbuild \
  --root "$stage" \
  --identifier dev.karst.karstd \
  --version "$pkg_version" \
  --scripts "$root/packaging/macos/scripts" \
  --install-location / \
  --ownership recommended \
  "$component"

echo "==> pkgbuild (Karst, $arch)"
echo "==> staged tree before pkgbuild:"
find "$stage_status" | sort

# `pkgbuild` infers a "bundle component" for any .app in `--root` and, by
# default, makes it relocatable and version-checked: at install time it goes
# looking for an existing copy anywhere Launch Services knows about, by
# bundle identifier, and can decide the payload does not need to be placed
# at all — silently. `installer` still reports success; nothing under
# /Applications ever appears. That is exactly what a first version of this
# script hit: "The install was successful," and no app. `--analyze` plus
# forcing both flags off makes pkgbuild treat this bundle like every other
# file in the payload — always placed at the literal root-relative path.
component_plist="$component_dir/karst-status-component.plist"
pkgbuild --analyze --root "$stage_status" "$component_plist"
# `--analyze` emits one array entry per .app bundle it found under --root.
# Karst Setup used to be a second one here, which is why this loop forces
# both flags off for every entry rather than hardcoding index 0 — kept as a
# loop, not simplified back to a single index, so a future second bundle
# under $stage_status does not silently reintroduce the exact "installed
# successfully, no app present" failure the paragraph above describes.
bundle_index=0
while plutil -extract "$bundle_index.BundleIsRelocatable" raw "$component_plist" >/dev/null 2>&1; do
  plutil -replace "$bundle_index.BundleIsRelocatable" -bool NO "$component_plist"
  plutil -replace "$bundle_index.BundleIsVersionChecked" -bool NO "$component_plist"
  bundle_index=$((bundle_index + 1))
done
[ "$bundle_index" -ge 1 ] \
  || { echo "error: pkgbuild --analyze found no bundle components under $stage_status, expected 1 (Karst.app)" >&2; exit 1; }

pkgbuild \
  --root "$stage_status" \
  --component-plist "$component_plist" \
  --identifier dev.karst.karststatus \
  --version "$pkg_version" \
  --scripts "$root/packaging/macos/status-scripts" \
  --install-location / \
  --ownership recommended \
  "$status_component"
echo "==> payload pkgbuild actually recorded:"
pkgutil --payload-files "$status_component"

echo "==> productbuild ($arch)"
productbuild \
  --distribution "$root/packaging/macos/Distribution.xml" \
  --package-path "$component_dir" \
  "$product"

if [ -n "$installer_identity" ]; then
  echo "==> productsign"
  productsign --sign "$installer_identity" "$product" "$product.signed"
  mv "$product.signed" "$product"
  pkgutil --check-signature "$product"
else
  echo "==> no Developer ID Installer identity: the .pkg will be UNSIGNED"
  [ "$require_signing" -eq 0 ] || { echo "error: --require-signing" >&2; exit 1; }
fi

# ── notarization ────────────────────────────────────────────────────────────
if [ -n "${KARST_NOTARY_KEY:-}" ] && [ -n "${KARST_NOTARY_KEY_ID:-}" ] \
   && [ -n "${KARST_NOTARY_ISSUER:-}" ]; then
  echo "==> notarytool submit (this takes minutes, not seconds)"
  # `--wait` rather than polling: the submission is worthless without the
  # staple that follows it, so there is nothing useful to do in the meantime.
  xcrun notarytool submit "$product" \
    --key "$KARST_NOTARY_KEY" \
    --key-id "$KARST_NOTARY_KEY_ID" \
    --issuer "$KARST_NOTARY_ISSUER" \
    --wait

  echo "==> stapler"
  # Stapling attaches the notarization ticket to the package itself, so a
  # machine that installs it offline can still verify it. Without this the
  # first install on a machine with no network shows the warning the whole
  # exercise was meant to remove.
  xcrun stapler staple "$product"
  xcrun stapler validate "$product"

  # `spctl` is what Gatekeeper actually consults. It passes here on the build
  # machine for reasons that have nothing to do with a user's — the real check
  # is on a machine that has never seen the artifact, and that is a manual step
  # in the release walkthrough (plans/phase-5/09-exit-criteria.md).
  spctl --assess --type install -vv "$product" || true
else
  echo "==> no notarytool credentials: the .pkg is NOT notarized"
  echo "    Gatekeeper will refuse it on any machine that did not build it."
  [ "$require_signing" -eq 0 ] || { echo "error: --require-signing" >&2; exit 1; }
fi

rm -rf "$component_dir"
shasum -a 256 "$product" | tee "$product.sha256"
echo "==> $product"
