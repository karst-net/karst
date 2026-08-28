#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright the Karst contributors.
#
# Submit the macOS client to the Mac App Store — **a stub, deliberately.**
#
# ## Read this before wiring it up
#
# The artefact `scripts/build-macos-pkg.sh` produces **cannot be accepted by
# the Mac App Store**, and no amount of credentials changes that. The App Store
# requires a sandboxed application; Karst's macOS client is a root LaunchDaemon
# that opens a `utun` device, which is neither sandboxed nor an application.
# That is a deliberate architectural choice, not an oversight —
# plans/phase-5/06-macos-client.md §3 has the reasoning, and the short version
# is that the App Store route needs the
# `com.apple.developer.networking.networkextension` entitlement, which Apple
# grants by application with a review turnaround measured in weeks and no
# committed SLA. Making the release depend on that would put shipping behind
# somebody else's queue.
#
# So what is this for? Three things:
#
#   1. The credential plumbing is real and is exercised the moment the
#      certificates exist, rather than being written for the first time under
#      release pressure.
#   2. The preconditions are checked and reported precisely, so whoever picks
#      up the NetworkExtension variant learns what is missing in one run
#      instead of by reading Apple's documentation twice.
#   3. The command shapes below are the ones that will actually be used, so the
#      remaining work is building an App Store-eligible artefact — not
#      discovering how to upload one.
#
# It therefore refuses unless KARST_APPSTORE_READY=1 is set, which nobody
# should set until there is a signed, sandboxed `.pkg` built from a
# `NEPacketTunnelProvider` target. Setting it today uploads a package the App
# Store will reject, and a rejected submission is a slower way to learn what
# this script already says.
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

package="${1:-dist/macos/karst-macos-universal.pkg}"

missing=0
note() { echo "  - $1"; missing=1; }

echo "==> Mac App Store submission preconditions"

[ -f "$package" ] || note "no package at $package — run scripts/build-macos-pkg.sh first"
[ -n "${KARST_APPSTORE_IDENTITY:-}" ] \
  || note "KARST_APPSTORE_IDENTITY unset (3rd Party Mac Developer Installer certificate)"
[ -n "${KARST_NOTARY_KEY:-}" ] || note "KARST_NOTARY_KEY unset (App Store Connect .p8)"
[ -n "${KARST_NOTARY_KEY_ID:-}" ] || note "KARST_NOTARY_KEY_ID unset"
[ -n "${KARST_NOTARY_ISSUER:-}" ] || note "KARST_NOTARY_ISSUER unset"

if [ "$missing" -ne 0 ]; then
  echo
  echo "Nothing was submitted: the credentials above are not available."
  echo "This is the expected outcome until the Apple Developer Program"
  echo "enrolment completes — see plans/phase-5/06-macos-client.md §7."
  exit 0
fi

if [ "${KARST_APPSTORE_READY:-0}" != "1" ]; then
  cat >&2 <<'EOF'

Credentials are present, and the submission is still blocked — on the artefact,
not on the paperwork.

The .pkg built by this repository installs a root LaunchDaemon. The Mac App
Store accepts only sandboxed applications, so this package would be rejected on
review whatever it is signed with. Shipping through the App Store needs a
different build entirely:

  - a NEPacketTunnelProvider system extension, requiring the
    com.apple.developer.networking.networkextension entitlement (applied for
    separately, granted by Apple on review);
  - an App Sandbox entitlement, and a datapath that works inside it;
  - a containing .app, since an extension cannot ship on its own.

None of those exist yet. See plans/phase-5/06-macos-client.md §3.

Set KARST_APPSTORE_READY=1 only once an App Store-eligible artefact is being
built, and change $package above to point at it.
EOF
  exit 1
fi

# ── the real submission, for when there is something to submit ──────────────
#
# Everything below runs today if KARST_APPSTORE_READY=1. It is not
# pseudocode — it is the sequence, in order, and it is here so the remaining
# work is producing the artefact rather than working this out.

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
