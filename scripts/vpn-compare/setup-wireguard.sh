#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright the Karst contributors.
#
# Bring plain point-to-point WireGuard up between two hosts, measure it,
# tear it down — the "wireguard" (floor/reference) row of
# scripts/vpn-compare/run-all.sh (issue #201). No control plane: keys and
# endpoints are exchanged directly, the way `wg-quick` expects.
#
# Usage:
#     scripts/vpn-compare/setup-wireguard.sh HOST_A HOST_B [--keep]

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./lib.sh

[ $# -ge 2 ] || die "usage: setup-wireguard.sh HOST_A HOST_B [--keep]"
HOST_A=$1; HOST_B=$2; shift 2
KEEP=0
[ "${1:-}" = --keep ] && KEEP=1

PORT=$((VC_PORT_BASE + 10))
SUBNET=10.202.0
IFACE=vc-wg0
RUN="$RUN_DIR/wireguard"

cleanup() {
    [ "$KEEP" -eq 1 ] && { say "wireguard: left running (--keep)"; return; }
    sh_a "sudo -n ip link del $IFACE 2>/dev/null; true" || true
    sh_b "sudo -n ip link del $IFACE 2>/dev/null; true" || true
}
trap cleanup EXIT

say "wireguard: addresses"
ADDR_A=$(sh_a "hostname -I" | cut -d' ' -f1)
ADDR_B=$(sh_b "hostname -I" | cut -d' ' -f1)

say "wireguard: keys"
for h in "$HOST_A" "$HOST_B"; do
    ssh -n -o BatchMode=yes "$h" "mkdir -p $RUN && chmod 700 $RUN && \
        wg genkey | tee $RUN/priv | wg pubkey > $RUN/pub && chmod 600 $RUN/priv"
done
A_PUB=$(sh_a "cat $RUN/pub"); B_PUB=$(sh_b "cat $RUN/pub")

bring_up() {
    local host=$1 os_ip=$2 me_ip=$3 peer_pub=$4 peer_endpoint=$5
    ssh -n -o BatchMode=yes "$host" "
        sudo -n ip link add $IFACE type wireguard && \
        sudo -n ip addr add $me_ip/24 dev $IFACE && \
        sudo -n wg set $IFACE listen-port $PORT private-key $RUN/priv \
            peer $peer_pub endpoint $peer_endpoint:$PORT allowed-ips $os_ip/32 persistent-keepalive 25 && \
        sudo -n ip link set $IFACE up"
}

say "wireguard: bringing tunnel up"
START=$(date +%s.%N)
bring_up "$HOST_B" "$SUBNET.1" "$SUBNET.2" "$A_PUB" "$ADDR_A"
bring_up "$HOST_A" "$SUBNET.2" "$SUBNET.1" "$B_PUB" "$ADDR_B"

say "wireguard: waiting for handshake"
for _ in $(seq 1 15); do
    sh_a "ping -c1 -W1 $SUBNET.2 >/dev/null 2>&1" && break
    sleep 1
done
END=$(date +%s.%N)
SETUP_S=$(python3 -c "print(round($END-$START,2))")
sh_a "ping -c1 -W1 $SUBNET.2 >/dev/null 2>&1" || die "wireguard tunnel never came up"

# No control-plane process to sample idle CPU/RSS for (wg is an in-kernel
# interface, not a userspace daemon) — idle cost here is the kernel's, which
# this harness has no comparable per-tool instrument for. Left NA, and noted
# in the report rather than guessed at.
collect_metrics wireguard lan-direct "$SUBNET.1" "$SUBNET.2" "$SETUP_S" NA NA
