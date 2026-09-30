#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright the Karst contributors.
#
# Measure the *production* Tailscale tunnel already running between these
# two hosts — the "tailscale" row of scripts/vpn-compare/run-all.sh
# (issue #201). Unlike every other setup-*.sh here, this script brings
# nothing up and tears nothing down: turing is already logged into the
# user's real personal tailnet, and this just verifies both peers are
# online with a direct path and measures it. lovelace needs a one-time
# interactive login (`tailscale up` prints a login URL — that step is
# manual, outside this script) before this will pass.
#
# Usage:
#     scripts/vpn-compare/setup-tailscale.sh HOST_A HOST_B

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./lib.sh

[ $# -ge 2 ] || die "usage: setup-tailscale.sh HOST_A HOST_B"
HOST_A=$1; HOST_B=$2

say "tailscale: checking production login state"
for h in "$HOST_A" "$HOST_B"; do
    fn=sh_a; [ "$h" = "$HOST_B" ] && fn=sh_b
    st=$($fn "sudo -n tailscale status --json 2>/dev/null" || echo '{}')
    backend=$(echo "$st" | python3 -c "import json,sys
try: print(json.load(sys.stdin).get('BackendState','Unknown'))
except Exception: print('Unknown')" 2>/dev/null)
    [ "$backend" = Running ] || \
        die "tailscale: $h is not logged in (BackendState=$backend) — run 'sudo tailscale up' on it and complete the printed login URL, then re-run this script. Skipping this comparator for now."
done

say "tailscale: resolving overlay addresses"
TS_IP_A=$(sh_a "sudo -n tailscale ip -4" | head -1)
TS_IP_B=$(sh_b "sudo -n tailscale ip -4" | head -1)
[ -n "$TS_IP_A" ] && [ -n "$TS_IP_B" ] || die "tailscale: could not resolve an IP on both peers"

say "tailscale: connection type (want direct, not DERP)"
PING_OUT=$(sh_a "sudo -n tailscale ping -c 1 $TS_IP_B" 2>&1) || true
echo "$PING_OUT"

# Setup time isn't meaningful here — this is an already-established
# production tunnel, not a cold enroll — so it's left NA rather than
# measuring "how long until ping succeeds" against a link that's been up
# for days, which would understate every other tool's number for the wrong
# reason.
read -r IDLE_CPU IDLE_RSS <<< "$(idle_sample "$HOST_A" "tailscaled --state")"
collect_metrics tailscale lan-direct "$TS_IP_A" "$TS_IP_B" NA "$IDLE_CPU" "$IDLE_RSS"
