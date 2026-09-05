#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright the Karst contributors.
#
# Compute the package VERSION and RELEASE from the ref this workflow runs on,
# and print them as KEY=VALUE lines for $GITHUB_ENV:
#
#   scripts/release-version.sh >> "$GITHUB_ENV"
#
# A tag `vX.Y.Z` is a plain release: VERSION=X.Y.Z, RELEASE=1. A tag
# `vX.Y.Z-somelabel` (a beta, an rc, ...) is a pre-release: VERSION=X.Y.Z,
# RELEASE=0.somelabel, with the label's own hyphens turned to dots (neither
# dpkg nor rpm allow a hyphen inside a release field). The leading "0." on a
# pre-release's RELEASE is the Fedora packaging convention for exactly this —
# it sorts *below* the eventual "1" of the real release, so upgrading from an
# rc to the final release is still an upgrade, in both dpkg's and rpm's
# version comparison: "0" < "1" as the leading revision component, and every
# rc for the same upstream version sorts by its label after that.
#
# Every push that is not a tag gets a version nothing will ever collide with:
# 0.0.0+git.<sha>. It does not need a meaningful RELEASE — it identifies a
# commit, not something anyone upgrades to — so RELEASE is just "1" there,
# satisfying nfpm's requirement that the field be non-empty.

set -euo pipefail

ref=${GITHUB_REF:?GITHUB_REF is not set}
sha=${GITHUB_SHA:?GITHUB_SHA is not set}

if [[ "$ref" == refs/tags/v* ]]; then
  tag=${ref#refs/tags/v}
  version=${tag%%-*}
  if [[ "$tag" == *-* ]]; then
    label=${tag#*-}
    release="0.${label//-/.}"
  else
    release="1"
  fi
else
  version="0.0.0+git.${sha}"
  release="1"
fi

echo "VERSION=$version"
echo "RELEASE=$release"
