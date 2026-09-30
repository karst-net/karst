#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright the Karst contributors.
#
# Run the full issue #201 mesh-VPN comparison: every setup-*.sh in this
# directory, in sequence, sharing one results TSV (lib.sh's $RESULTS_TSV).
# One reproducible command for the whole matrix — see
# docs/measurements/vpn-comparison-2026-09-30.md for how to read the
# output and docs/measurements/README.md for this project's convention on
# committing the raw data alongside the write-up.
#
# Usage:
#     scripts/vpn-compare/run-all.sh HOST_A HOST_B [--out FILE]
#
# `tailscale` (the real, already-authenticated production tunnel) is
# measured only if both hosts already show BackendState=Running — see
# setup-tailscale.sh's own header. It is never brought up or torn down by
# this harness; a host that isn't logged in needs a one-time, interactive
# `sudo tailscale up` first, outside this script.

set -uo pipefail   # not -e: one tool's failure shouldn't cancel the rest
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./lib.sh

[ $# -ge 2 ] || die "usage: run-all.sh HOST_A HOST_B [--out FILE]"
HOST_A=$1; HOST_B=$2; shift 2
[ "${1:-}" = --out ] && { export RESULTS_TSV=$2; shift 2; }

rm -f "$RESULTS_TSV"
say "run-all: results -> $RESULTS_TSV"

run() {
    local script=$1; shift
    say "run-all: === $script ==="
    if ! ./"$script" "$HOST_A" "$HOST_B" "$@"; then
        say "run-all: $script FAILED — continuing with the rest (see its output above)"
    fi
}

run setup-wireguard.sh
run setup-karst.sh
run setup-nebula.sh
run setup-headscale.sh
run setup-tailscale.sh

say "run-all: done"
column -t -s"$(printf '\t')" "$RESULTS_TSV" >&2 || cat "$RESULTS_TSV" >&2
