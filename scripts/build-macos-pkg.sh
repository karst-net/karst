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
#   KARST_PROVISION_PROFILE_KARSTSTATUS    path to Karst.app's "Developer ID"
#                                           .provisionprofile (dev.karst.karststatus)
#   KARST_PROVISION_PROFILE_PACKETTUNNEL   path to the system extension's
#                                           "Developer ID" .provisionprofile
#                                           (dev.karst.packettunnel)
#
# The two provisioning-profile variables exist because Karst.app and the
# packet-tunnel system extension both carry *restricted* entitlements
# (com.apple.developer.system-extension.install,
# com.apple.developer.networking.vpn.api,
# com.apple.developer.networking.networkextension) — unlike an ordinary
# Developer ID app, restricted entitlements are not validated by signing and
# notarization alone. Discovered the hard way on a real Mac: a build signed
# with real Developer ID certificates AND successfully notarized still would
# not launch, refused by AMFI with "No matching profile found" — notarization
# answers Gatekeeper's question ("is this trustworthy code"), not AMFI's
# separate one ("is this specific restricted capability authorized for this
# specific App ID"), and only an embedded provisioning profile answers that
# second question. Each `.provisionprofile` here is the "Developer ID" profile
# type (not "Mac App Distribution", which is for the App Store) generated in
# the Developer Portal for the matching App ID, after enabling its
# capabilities there.
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

# `swift build` defaults to Apple's newer "Swift Build" backend on a recent
# enough toolchain (`swift build --help` shows it as the `--build-system`
# default). Found on real hardware, not anticipated (#159): that backend
# fails linking `CKarstFFI` — a header-only C target, no `.c` source at
# all — with "Build input file cannot be found: '.../CKarstFFI.o'", since
# it expects an object file a header-only target never produces. `native`
# (the classic SwiftPM/llbuild backend, deprecated but still functional)
# does not have this bug. CI's pinned runner toolchains predate the new
# backend's default flip entirely, so this only bites a local build on a
# newer Xcode/Swift install — exactly this VM's case.
swift_build_flags=(--build-system native)

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

# `pkg_version` above is the human-readable marketing version
# pkgbuild/productbuild need in their own strict plain-dotted-number
# format — it collapses to a fixed "0.0.0" on every non-tag build, since
# the git-sha suffix that would otherwise vary it is exactly what that
# strict format can't hold. `CFBundleVersion` has a different job:
# it's what `sysextd` itself compares to decide whether an
# already-activated system extension needs replacing at all. Found on
# real hardware, not anticipated (#159): a `CFBundleVersion` that never
# changes build to build means sysextd treats every rebuild as "the same
# version, nothing to do" and keeps running the *first* build it ever
# staged — no error, just silently stale code, until the extension is
# fully removed and the Mac rebooted. A build timestamp is monotonically
# increasing and numeric-only (`CFBundleVersion`'s own safe format),
# independent of `pkg_version`'s own intentional stability.
bundle_version="$(date -u +%Y%m%d%H%M%S)"

# Everything below is namespaced by $arch and lives under one shared
# dist/macos, rather than each build wiping the directory: building both
# architectures in sequence (as a developer running `just macos-package`
# would) must leave both .pkg files behind, not just the second one.
#
# One component root, not two: the `karstd` LaunchDaemon component this
# used to build alongside Karst.app is gone (ADR-0026's amended decision —
# NetworkExtension is the sole macOS backend now, not one of two shipped
# "indefinitely"). Real device testing this session found no gap in
# Bedrock's actual cryptographic guarantee from making that switch — it
# runs in the same shared Rust engine either way — only in full-tunnel
# routing lockdown, tracked as its own follow-up rather than blocking this.
dist="$root/dist/macos"
stage_status="$dist/root-status-$arch"
rm -rf "$stage_status"
mkdir -p "$dist" \
  "$stage_status/Applications" "$stage_status/Library/LaunchAgents" \
  "$stage_status/usr/local/bin"

cp "$root/packaging/macos/uninstall.sh" "$stage_status/usr/local/bin/karst-uninstall"
chmod 0755 "$stage_status/usr/local/bin/karst-uninstall"

# ── the menu-bar status app (Swift) ─────────────────────────────────────────
#
# One `--arch` rather than two: a single-arch `swift build` lands its binary
# under `.build/<arch>-apple-macosx/release/`, not the `.build/apple/...`
# layout a multi-arch (`--arch` passed twice) build uses for its fat binary.
# `--show-bin-path` asks SwiftPM for that directory directly instead of this
# script hardcoding a path that is a SwiftPM implementation detail.
echo "==> building KarstStatus ($arch)"
(cd "$root/packaging/macos/KarstStatus" && swift build -c release --arch "$arch" "${swift_build_flags[@]}")
status_bin_dir="$(cd "$root/packaging/macos/KarstStatus" && swift build -c release --arch "$arch" "${swift_build_flags[@]}" --show-bin-path)"
status_bin="$status_bin_dir/KarstStatus"
[ -x "$status_bin" ] \
  || { echo "error: KarstStatus build did not produce $status_bin" >&2; exit 1; }
lipo -info "$status_bin"

app="$stage_status/Applications/Karst.app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
cp "$status_bin" "$app/Contents/MacOS/KarstStatus"
chmod 0755 "$app/Contents/MacOS/KarstStatus"
cp "$root/packaging/macos/KarstStatus/Info.plist" "$app/Contents/Info.plist"
# The template ships "0.0.0" — see its own comment.
# CFBundleShortVersionString is the human-readable marketing version
# (Gatekeeper/Spotlight read this one); CFBundleVersion is the
# always-increasing build identifier sysextd's own replace-logic needs —
# see bundle_version's own comment for why these can't share a value.
plutil -replace CFBundleShortVersionString -string "$pkg_version" "$app/Contents/Info.plist"
plutil -replace CFBundleVersion -string "$bundle_version" "$app/Contents/Info.plist"

cp "$root/packaging/macos/dev.karst.karststatus.plist" "$stage_status/Library/LaunchAgents/"
chmod 0644 "$stage_status/Library/LaunchAgents/dev.karst.karststatus.plist"

# ── the packet-tunnel system extension (Swift) ───────────────────────────────
#
# ADR-0026 item 7. A system extension ships embedded inside its host app's
# bundle — Apple's own distribution requirement, not a Karst layout choice —
# at Contents/Library/SystemExtensions/<bundle-id>.systemextension/, which is
# why this stages into $app rather than a component of its own. Built and
# staged the same way KarstStatus is above: single-`--arch` swift build,
# `--show-bin-path` for the binary, the Info.plist template version-patched
# with `plutil -replace`.
#
# `karst-ffi` first (ADR-0029/ADR-0030): KarstPacketTunnel's own Package.swift
# links `libkarst_ffi.a` via `KARST_FFI_LIB_DIR`
# (Sources/KarstFFI/karst_ffi.swift's own header comment has the full
# reasoning), which `swift build` below needs already built and pointed at,
# not produced as a side effect of building the Swift target itself.
# `--features network-extension` even though the *committed* Swift bindings
# (generated on Linux, without it — same file's header comment again) only
# cover `enroll_invitation` today: the extra compiled symbols this adds
# (`EngineHandle`) are simply unreferenced until a future regeneration adds
# their Swift side, and an unreferenced symbol in a static library links
# fine — only a *missing* one would break this build.
#
# `MACOSX_DEPLOYMENT_TARGET` matches Package.swift's `.macOS(.v13)` and
# Distribution.xml's `<os-version min="13.0"/>` — without it, `rustc`/`cc`
# target whichever SDK version this runner's Xcode happens to default to
# (14.5 as of the runner this was first verified against), and `swift
# build`'s own link step warns, once per object file in `libkarst_ffi.a`,
# that each one "was built for newer 'macOS' version ... than being linked."
# Harmless — nothing here actually requires macOS 14 API surface — but
# noisy enough (500+ lines, one per compilation unit `aws-lc-sys` produces)
# to bury a real warning if one ever appears alongside it.
echo "==> building karst-ffi ($arch)"
(cd "$root" && MACOSX_DEPLOYMENT_TARGET=13.0 cargo build --locked --release \
    --target "$rust_target" --package karst-ffi --features network-extension)
export KARST_FFI_LIB_DIR="$root/target/$rust_target/release"

echo "==> building KarstPacketTunnel ($arch)"
(cd "$root/packaging/macos/KarstPacketTunnel" && swift build -c release --arch "$arch" "${swift_build_flags[@]}")
packettunnel_bin_dir="$(cd "$root/packaging/macos/KarstPacketTunnel" && swift build -c release --arch "$arch" "${swift_build_flags[@]}" --show-bin-path)"
packettunnel_bin="$packettunnel_bin_dir/KarstPacketTunnel"
[ -x "$packettunnel_bin" ] \
  || { echo "error: KarstPacketTunnel build did not produce $packettunnel_bin" >&2; exit 1; }
lipo -info "$packettunnel_bin"

# `dev.karst.packettunnel` — KarstPacketTunnel/Info.plist's own
# `CFBundleIdentifier` — is this bundle's directory name too: macOS requires
# a system extension's bundle to be named `<bundle-id>.systemextension`
# exactly, not merely to declare that identifier inside its Info.plist.
systemextension="$app/Contents/Library/SystemExtensions/dev.karst.packettunnel.systemextension"
mkdir -p "$systemextension/Contents/MacOS"
cp "$packettunnel_bin" "$systemextension/Contents/MacOS/KarstPacketTunnel"
chmod 0755 "$systemextension/Contents/MacOS/KarstPacketTunnel"
cp "$root/packaging/macos/KarstPacketTunnel/Info.plist" "$systemextension/Contents/Info.plist"
plutil -replace CFBundleShortVersionString -string "$pkg_version" "$systemextension/Contents/Info.plist"
plutil -replace CFBundleVersion -string "$bundle_version" "$systemextension/Contents/Info.plist"

# ── the app icon ─────────────────────────────────────────────────────────
#
# `sips` and `iconutil` are macOS-only (no Linux equivalent, hence this
# runs here rather than at asset-creation time) — every size an .icns can
# hold, generated from the one 1024x1024 master rather than committing all
# ten as separate files. `CFBundleIconFile` (Info.plist) names the result
# without its extension; Launch Services appends .icns itself.
echo "==> building AppIcon.icns"
iconset="$dist/AppIcon-$arch.iconset"
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

# ── the menu-bar state icons ─────────────────────────────────────────────
#
# One flat PNG per `AppDelegate.swift` `MarkState` case
# (`Bundle.main.path(forResource: "menu-<state>", ofType: "png")`) — a
# plain bundled resource, not a SwiftPM `resources:` entry: `Bundle.module`'s
# lookup differs depending on whether this is running from inside an .app
# bundle or a bare `swift build` binary, and this sidesteps that entirely.
# Hand-designed assets, not something this script or AppDelegate.swift
# generates: a composited/vector-drawn menu bar icon was tried and
# rejected on real hardware for reading poorly at menu bar size.
echo "==> staging menu bar state icons"
for state in loading not-running no-peers relayed direct; do
  cp "$root/packaging/macos/KarstStatus/Resources/menu-$state.png" \
    "$app/Contents/Resources/menu-$state.png"
done

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
  # A provisioning profile must land inside Contents/ *before* `codesign`
  # runs, same reasoning as the signing order comment below: codesign seals
  # whatever is already present, so embedding it after signing would leave
  # the profile outside what the signature covers, and AMFI would reject the
  # bundle exactly as if no profile were embedded at all.
  if [ -n "${KARST_PROVISION_PROFILE_PACKETTUNNEL:-}" ]; then
    echo "==> embedding KarstPacketTunnel.systemextension's provisioning profile"
    cp "$KARST_PROVISION_PROFILE_PACKETTUNNEL" "$systemextension/Contents/embedded.provisionprofile"
  else
    echo "==> no KARST_PROVISION_PROFILE_PACKETTUNNEL: the system extension's" \
      "restricted entitlements (com.apple.developer.networking.networkextension)" \
      "will not validate — AMFI refuses to launch it even fully signed and notarized"
  fi
  # The system extension first, Karst.app last: `codesign` on a bundle seals
  # everything already inside Contents/ at the moment it runs, so a nested
  # bundle signed *after* its container would leave the container's
  # signature covering an unsigned inner one, and the extension's own
  # `--entitlements` grant would never take effect (Apple's own signing
  # order requirement, not a Karst convention).
  echo "==> codesign KarstPacketTunnel.systemextension"
  codesign --force --options runtime --timestamp \
    --entitlements "$root/packaging/macos/KarstPacketTunnel/PacketTunnel.entitlements" \
    --sign "$codesign_identity" "$systemextension"
  codesign --verify --strict --verbose=2 "$systemextension"
  if [ -n "${KARST_PROVISION_PROFILE_KARSTSTATUS:-}" ]; then
    echo "==> embedding Karst.app's provisioning profile"
    cp "$KARST_PROVISION_PROFILE_KARSTSTATUS" "$app/Contents/embedded.provisionprofile"
  else
    echo "==> no KARST_PROVISION_PROFILE_KARSTSTATUS: Karst.app's restricted" \
      "entitlements (system-extension.install, networking.vpn.api) will not" \
      "validate — AMFI refuses to launch it even fully signed and notarized"
  fi
  echo "==> codesign Karst.app"
  # Signs the whole bundle in one pass, the already-signed system extension
  # included — `codesign` seals everything under Contents/ into one bundle
  # signature, and the extension's own nested signature (above) survives
  # being sealed into the outer one, the same as any other signed nested
  # bundle would.
  codesign --force --options runtime --timestamp \
    --entitlements "$root/packaging/macos/Karst.entitlements" \
    --sign "$codesign_identity" "$app"
  codesign --verify --strict --verbose=2 "$app"
else
  echo "==> no Developer ID Application identity: binaries, KarstPacketTunnel.systemextension and Karst.app will be UNSIGNED"
  [ "$require_signing" -eq 0 ] || { echo "error: --require-signing" >&2; exit 1; }
fi

# ── the package ──────────────────────────────────────────────────────────────
#
# One `pkgbuild` component from the one staging root now that `karstd`'s
# own component is gone — still wrapped in a `productbuild`/`Distribution.xml`
# rather than shipping this `pkgbuild` output directly, since that costs
# nothing and keeps re-adding a second component (e.g. a real App Store
# variant) cheap later.
#
# The component file itself keeps the plain name `Distribution.xml` refers
# to (`karst-status-component.pkg`) — that XML is shared across both
# architectures rather than templated per-arch — so it is staged in an
# arch-namespaced directory instead of being renamed; `productbuild
# --package-path` just points at that directory.
component_dir="$dist/components-$arch"
rm -rf "$component_dir"
mkdir -p "$component_dir"
status_component="$component_dir/karst-status-component.pkg"
product="$dist/karst-client-macos-$arch.pkg"

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
