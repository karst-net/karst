#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright the Karst contributors.
#
# Submit the macOS client to the Mac App Store — **a stub, deliberately.**
#
# ## Read this before wiring it up
#
# `scripts/build-macos-appstore-pkg.sh` now builds a real, sandboxed App
# Extension artifact (`KarstPacketTunnelAppExtension.appex`, embedded in
# `KarstAppStore`'s container app) — docs/adr/0040 and
# docs/adr/0043-mac-app-store-sandboxed-app-extension-target.md. That answers
# the architectural blocker this comment used to describe (a System
# Extension cannot be made App-Store-eligible by any entitlement change; it
# needs a second, sandboxed Xcode-less target, which now exists). What it
# does **not** answer is whether that artifact actually works: no Apple
# Developer Program Mac App Store certificates, App ID, or provisioning
# profiles exist in this environment, so nothing has installed, activated,
# or enrolled this target on real hardware. "Written and reviewed, not run"
# — the same posture ADR-0029/ADR-0030 already hold themselves to.
#
# So what is this for? Three things:
#
#   1. The credential plumbing is real and is exercised the moment the
#      certificates exist, rather than being written for the first time under
#      release pressure.
#   2. The preconditions are checked and reported precisely, so whoever picks
#      up real Store Connect credentials learns what is missing in one run
#      instead of by reading Apple's documentation twice.
#   3. The command shapes below are the ones that will actually be used, so the
#      remaining work is verifying the artifact against real credentials and
#      real hardware — not discovering how to upload one.
#
# It therefore refuses unless KARST_APPSTORE_READY=1 is set, which nobody
# should set until the artifact `build-macos-appstore-pkg.sh` produces has
# actually been verified (installed, activated, enrolled) against a real Mac
# App Store provisioning profile on real hardware. Setting it today uploads a
# package that has never run, and a rejected submission is a slower way to
# learn what this script already says.
#
# ## Credentials, when the time comes
#
#   KARST_APPSTORE_IDENTITY   "3rd Party Mac Developer Installer: ..."
#   KARST_NOTARY_KEY          App Store Connect .p8 private key
#   KARST_NOTARY_KEY_ID       its key id
#   KARST_NOTARY_ISSUER       the issuer UUID
#
# The App Store Connect API key is the same one notarization uses; the
# *installer certificate* is a different one from the Developer ID installer
# certificate, and that is the distinction most easily got wrong.

set -euo pipefail

package="${1:-dist/macos/karst-appstore-macos-arm64.pkg}"

missing=0
note() { echo "  - $1"; missing=1; }

echo "==> Mac App Store submission preconditions"

[ -f "$package" ] || note "no package at $package — run scripts/build-macos-appstore-pkg.sh first"
[ -n "${KARST_APPSTORE_IDENTITY:-}" ] \
  || note "KARST_APPSTORE_IDENTITY unset (3rd Party Mac Developer Installer certificate)"
[ -n "${KARST_NOTARY_KEY:-}" ] || note "KARST_NOTARY_KEY unset (App Store Connect .p8)"
[ -n "${KARST_NOTARY_KEY_ID:-}" ] || note "KARST_NOTARY_KEY_ID unset"
[ -n "${KARST_NOTARY_ISSUER:-}" ] || note "KARST_NOTARY_ISSUER unset"

if [ "$missing" -ne 0 ]; then
  echo
  echo "Nothing was submitted: the credentials above are not available."
  echo "This is the expected outcome until the Apple Developer Program"
  echo "enrollment completes — see plans/phase-5/06-macos-client.md §7."
  exit 0
fi

if [ "${KARST_APPSTORE_READY:-0}" != "1" ]; then
  cat >&2 <<'EOF'

Credentials are present, and the submission is still blocked — on
verification, not on the artifact or the paperwork.

scripts/build-macos-appstore-pkg.sh now builds a real sandboxed App
Extension artifact: KarstPacketTunnelAppExtension.appex (the standard
packet-tunnel-provider entitlement value, com.apple.security.app-sandbox,
App Group-based config/socket paths) embedded in KarstAppStore's container
app. Per docs/adr/0043-mac-app-store-sandboxed-app-extension-target.md, this
is written and reviewed against Apple's App Extension/App Sandbox
documentation and compiled/tested in CI on a real macos-14 runner — but
nothing has installed, activated, or enrolled it on real hardware, because
no Apple Developer Program Mac App Store certificates, App ID, or
provisioning profiles exist in this environment to test against.

Set KARST_APPSTORE_READY=1 only once that real-hardware verification has
actually happened against a real Mac App Store provisioning profile — not
merely once the artifact exists.
EOF
  exit 1
fi

# ── the real submission, for when there is something to submit ──────────────
#
# Everything below runs today if KARST_APPSTORE_READY=1. It is not
# pseudocode — it is the sequence, in order, and it is here so the remaining
# work is producing the artifact rather than working this out.

echo "==> productsign with the App Store installer certificate"
productsign --sign "$KARST_APPSTORE_IDENTITY" "$package" "$package.appstore"

echo "==> validate before uploading"
# Validation catches the rejections that are mechanical — a missing
# entitlement, a wrong bundle id, an unsigned nested binary — in seconds,
# where a review catches them in days.
xcrun altool --validate-app \
  --type macos \
  --file "$package.appstore" \
  --apiKey "$KARST_NOTARY_KEY_ID" \
  --apiIssuer "$KARST_NOTARY_ISSUER"

echo "==> upload"
xcrun altool --upload-app \
  --type macos \
  --file "$package.appstore" \
  --apiKey "$KARST_NOTARY_KEY_ID" \
  --apiIssuer "$KARST_NOTARY_ISSUER"

echo "==> uploaded; the build appears in App Store Connect after processing"
