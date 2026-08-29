#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright the Karst contributors.
#
# Build the macOS client package: universal binaries, a .pkg, and — when the
# Apple credentials are present — signing, notarization and stapling.
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

require_signing=0
for arg in "$@"; do
  case "$arg" in
    --require-signing) require_signing=1 ;;
    *) echo "usage: $0 [--require-signing]" >&2; exit 2 ;;
  esac
done

if [ "$(uname -s)" != "Darwin" ]; then
  echo "error: this builds a macOS package and needs macOS — pkgbuild," >&2
  echo "       productbuild, codesign and lipo have no Linux equivalents." >&2
  exit 1
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
version="${VERSION:-0.0.0+git.$(git -C "$root" rev-parse --short HEAD 2>/dev/null || echo unknown)}"
# pkgbuild's --version must be a plain dotted number; the full version with its
# git metadata goes in the filename and in `karst --version`, which is where
# anyone actually looks for it.
pkg_version="${version%%+*}"

dist="$root/dist/macos"
stage="$dist/root"
rm -rf "$dist"
mkdir -p "$dist" "$stage/usr/local/bin" "$stage/Library/LaunchDaemons" "$stage/etc/karst"

# ── universal binaries ──────────────────────────────────────────────────────
#
# Both architectures, not just Apple Silicon. Self-hosters run old Intel Macs
# as always-on boxes, and that is exactly this project's audience.
targets=(aarch64-apple-darwin x86_64-apple-darwin)
for target in "${targets[@]}"; do
  echo "==> building $target"
  rustup target add "$target" >/dev/null
  (cd "$root" && cargo build --locked --release --target "$target" \
      --package karstd --package karst-cli)
done

for binary in karstd karst; do
  echo "==> lipo $binary"
  inputs=()
  for target in "${targets[@]}"; do
    inputs+=("$root/target/$target/release/$binary")
  done
  lipo -create -output "$stage/usr/local/bin/$binary" "${inputs[@]}"
  chmod 0755 "$stage/usr/local/bin/$binary"
done
lipo -info "$stage/usr/local/bin/karstd"

cp "$root/packaging/macos/dev.karst.karstd.plist" "$stage/Library/LaunchDaemons/"
chmod 0644 "$stage/Library/LaunchDaemons/dev.karst.karstd.plist"
cp "$root/docs/karstd-example.toml" "$stage/etc/karst/karstd.toml.example"
cp "$root/packaging/macos/uninstall.sh" "$stage/usr/local/bin/karst-uninstall"
chmod 0755 "$stage/usr/local/bin/karst-uninstall"

# ── signing the binaries ────────────────────────────────────────────────────
find_identity() {
  security find-identity -v -p codesigning 2>/dev/null \
    | grep "$1" | head -1 | sed 's/.*"\(.*\)"/\1/'
}

codesign_identity="${KARST_CODESIGN_IDENTITY:-$(find_identity 'Developer ID Application' || true)}"
installer_identity="${KARST_INSTALLER_IDENTITY:-$(find_identity 'Developer ID Installer' || true)}"

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
else
  echo "==> no Developer ID Application identity: binaries will be UNSIGNED"
  [ "$require_signing" -eq 0 ] || { echo "error: --require-signing" >&2; exit 1; }
fi

# ── the package ─────────────────────────────────────────────────────────────
component="$dist/karst-component.pkg"
product="$dist/karst-macos-universal.pkg"

echo "==> pkgbuild"
pkgbuild \
  --root "$stage" \
  --identifier dev.karst.karstd \
  --version "$pkg_version" \
  --scripts "$root/packaging/macos/scripts" \
  --install-location / \
  --ownership recommended \
  "$component"

echo "==> productbuild"
productbuild \
  --distribution "$root/packaging/macos/Distribution.xml" \
  --package-path "$dist" \
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

rm -f "$component"
shasum -a 256 "$product" | tee "$product.sha256"
echo "==> $product"
