#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright the Karst contributors.
# Keep Apple's numeric marketing version separate from the full release tag.
set -euo pipefail
plist=${1:?provide the app Info.plist}
version=${2:?provide the package version}
build=${3:?provide the bundle build}
plutil -insert KarstReleaseVersion -string "${KARST_VERSION:-$version}" "$plist"
plutil -replace CFBundleShortVersionString -string "${version%%[-+]*}" "$plist"
plutil -replace CFBundleVersion -string "$build" "$plist"
