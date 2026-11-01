#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright the Karst contributors.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
for ref in refs/tags/v0.1.0-rc.32 refs/tags/v0.1.0 refs/heads/main; do
  while IFS='=' read -r key value; do export "$key=$value"; done < <(
    GITHUB_REF="$ref" GITHUB_SHA=0123456789abcdef "$root/scripts/release-version.sh"
  )
  cp "$root/packaging/macos/KarstStatus/Info.plist" "$work/Info.plist"
  "$root/scripts/macos-app-version.sh" "$work/Info.plist" "$VERSION" 20261101000000
  test "$(plutil -extract KarstReleaseVersion raw "$work/Info.plist")" = "$KARST_VERSION"
  test "$(plutil -extract CFBundleShortVersionString raw "$work/Info.plist")" = "${VERSION%%[-+]*}"
  test "$(plutil -extract CFBundleVersion raw "$work/Info.plist")" = 20261101000000
  echo "Verified app metadata for $ref: $KARST_VERSION"
done
# Local packaging without release CI retains its caller-provided version.
unset KARST_VERSION
cp "$root/packaging/macos/KarstStatus/Info.plist" "$work/Info.plist"
"$root/scripts/macos-app-version.sh" "$work/Info.plist" 0.1.0-rc.32 20261101000000
test "$(plutil -extract KarstReleaseVersion raw "$work/Info.plist")" = 0.1.0-rc.32
