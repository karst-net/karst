#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright the Karst contributors.
#
# Generate the portal's download manifest from release artifacts that exist.
#
#   scripts/release-manifest.sh RELEASE_DIR OUTPUT_JSON
#
# The portal reads this at /releases/manifest.json and shows a user the
# installer for their platform with its checksum. Deriving both from the files
# themselves is the point: a checksum copied into the UI by hand is a checksum
# that is wrong at the next release, and a download page that is wrong about a
# checksum teaches people to skip verifying it.
#
# ## Why this discovers rather than lists
#
# The first version named three exact files, one of them
# `karst-windows-amd64.msi`. There is no Windows client — it is Phase 8 — so
# the script could not succeed against any real release directory, and nothing
# ran it. Meanwhile the portal's fixture served that same invented filename, so
# its download test passed against a manifest describing artifacts that have
# never been built.
#
# Discovery also handles the thing the fixed list could not express: there is
# no single "the Linux download" any more. Packages ship as .deb and .rpm for
# amd64 and arm64, and a user on an arm64 Fedora box needs to be offered the
# one that will install.
#
# Only the *client* is listed. karst-relay and karst-control are operator
# artifacts installed from the docs on a server, and offering them on an
# end-user download page invites somebody to install a coordination server on
# their laptop.

set -euo pipefail

release_dir=${1:?usage: scripts/release-manifest.sh RELEASE_DIR OUTPUT_JSON}
output=${2:?usage: scripts/release-manifest.sh RELEASE_DIR OUTPUT_JSON}

emit_asset() {
  local path=$1 platform=$2 arch=$3 format=$4
  local name checksum
  name=$(basename "$path")
  checksum=$(sha256sum "$path" | awk '{print $1}')
  printf '    {"platform":"%s","arch":"%s","format":"%s","name":"%s","url":"/releases/%s","sha256":"%s"}' \
    "$platform" "$arch" "$format" "$name" "$name" "$checksum"
}

assets=()
while IFS= read -r path; do
  [ -n "$path" ] || continue
  name=$(basename "$path")
  case "$name" in
    # Debian names the architecture amd64/arm64; RPM says x86_64/aarch64. The
    # manifest normalizes to the Debian spelling so the portal has one word per
    # architecture rather than two.
    karst-client-linux_*_amd64.deb)   assets+=("$(emit_asset "$path" linux amd64 deb)") ;;
    karst-client-linux_*_arm64.deb)   assets+=("$(emit_asset "$path" linux arm64 deb)") ;;
    karst-client-linux-*.x86_64.rpm)  assets+=("$(emit_asset "$path" linux amd64 rpm)") ;;
    karst-client-linux-*.aarch64.rpm) assets+=("$(emit_asset "$path" linux arm64 rpm)") ;;
    karst-client-macos.pkg)           assets+=("$(emit_asset "$path" macos universal pkg)") ;;
    karst-*-x64.msi | karst-windows-*.msi)
                                   assets+=("$(emit_asset "$path" windows amd64 msi)") ;;
  esac
done < <(find "$release_dir" -maxdepth 2 -type f | sort)

if [ "${#assets[@]}" -eq 0 ]; then
  echo "release-manifest: no client artifacts found under $release_dir" >&2
  echo "release-manifest: the portal's download page would offer nothing" >&2
  exit 1
fi

mkdir -p "$(dirname "$output")"
{
  printf '{\n  "assets": [\n'
  for index in "${!assets[@]}"; do
    printf '%s' "${assets[$index]}"
    if [ "$index" -lt $((${#assets[@]} - 1)) ]; then printf ',\n'; else printf '\n'; fi
  done
  printf '  ]\n}\n'
} > "$output"

echo "release-manifest: ${#assets[@]} asset(s) -> $output"
