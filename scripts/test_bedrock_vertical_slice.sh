#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright the Karst contributors.

# Builds the air-gapped signer and makes the management API hand it its actual
# export bytes. The Go test imports the signer's response, checks coverage, and
# enables enforcing mode, so this is the cross-process Bedrock vertical slice.
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"
cargo build -p karst-bedrock-cli
cd server
KARST_BEDROCK_BIN="$root/target/debug/karst-bedrock" \
  GOCACHE="${GOCACHE:-/tmp/mycelium-go-build}" \
  go test ./management/internals/karst/api -run '^TestBedrockOfflineCeremonyCoversEnrollmentBeforeEnforcing$' -count=1
