#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright the Karst contributors.
#
# Generate the static portal manifest only from release artifacts already
# produced by the release pipeline. This avoids copying a checksum into the UI
# by hand, which is exactly how a download page becomes wrong at release time.
set -euo pipefail

release_dir=${1:?usage: scripts/release-manifest.sh RELEASE_DIR OUTPUT_JSON}
output=${2:?usage: scripts/release-manifest.sh RELEASE_DIR OUTPUT_JSON}

asset() {
  platform=$1
  name=$2
  path="$release_dir/$name"
  test -f "$path"
  checksum=$(sha256sum "$path" | awk '{print $1}')
  printf '    {"platform":"%s","name":"%s","url":"/releases/%s","sha256":"%s"}' "$platform" "$name" "$name" "$checksum"
}

mkdir -p "$(dirname "$output")"
{
  printf '{\n  "assets": [\n'
  asset windows karst-windows-amd64.msi; printf ',\n'
  asset macos karst-macos-universal.pkg; printf ',\n'
  asset linux karst-linux-amd64.deb; printf '\n  ]\n}\n'
} > "$output"
