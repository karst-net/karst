#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright the Karst contributors.
#
# Measure PHREATIC handshake latency between two real hosts on a real LAN —
# karst-net/karst#119's "LAN handshake <3 ms" criterion.
#
# scripts/two-host-test.sh proves the tunnel works and measures steady-state
# throughput; it says nothing about how long a fresh handshake takes. This
# script isolates that: A is configured as the sole initiator (B never dials —
# its peer entry for A carries no endpoint, exactly the NAT arrangement
# two-host-test.sh already supports), so the first UDP datagram on the wire is
# always A's `HandshakeInit`. A `tcpdump` capture taken on A alone then needs
# only A's clock: the timestamp of that first outbound datagram and the
# timestamp of the first inbound datagram after it (B's `CookieReply` or
# `HandshakeResponse`) bound the network-plus-responder-crypto half of the
# round trip without any cross-host clock sync.
#
# What this does NOT measure: the moment A's *own* handshake completes after
# processing that reply, since that happens inside karstd with no packet on
# the wire. Untangling that from the capture would need instrumentation this
# script does not have, so it reports the measured wire latency and says so —
# a lower bound on full handshake completion time, not the whole thing.
#
# Usage:
#     scripts/handshake-latency-bench.sh HOST_A HOST_B [OPTIONS]
#
#     HOST_A, HOST_B    ssh destinations, Linux only (uses tcpdump on A).
#                       Both need passwordless sudo, a Rust toolchain, and a
#                       checkout at ~/karst.
#
# Options:
#     --addr-a IP       underlay address of A, as B should dial it back
#                       (default: resolved from `hostname -I`)
#     --addr-b IP       underlay address of B, as A should dial it
#     --port PORT       UDP port                       (default: 51820)
#     --subnet PREFIX   tunnel /24, first three octets (default: 10.89.0)
#     --iface NAME      interface name                 (default: karst0)
#     --trials N        fresh handshakes to time        (default: 20)
#     --keep            leave the daemons running on exit

set -euo pipefail

PORT=51820
SUBNET=10.89.0
IFACE=karst0
TRIALS=20
KEEP=0

die() { echo "handshake-latency-bench: $*" >&2; exit 1; }
say() { printf '\n\033[1m%s\033[0m\n' "$*"; }

[ $# -ge 2 ] || die "need two hosts; see the comment at the top of this file"
HOST_A=$1; HOST_B=$2; shift 2
ADDR_A=""; ADDR_B=""

while [ $# -gt 0 ]; do
    case $1 in
        --addr-a)  ADDR_A=$2;   shift 2 ;;
        --addr-b)  ADDR_B=$2;   shift 2 ;;
        --port)    PORT=$2;     shift 2 ;;
        --subnet)  SUBNET=$2;   shift 2 ;;
        --iface)   IFACE=$2;    shift 2 ;;
        --trials)  TRIALS=$2;   shift 2 ;;
        --keep)    KEEP=1;      shift ;;
        *) die "unknown option $1" ;;
    esac
done

RUN='~/karst-hs-run'
BIN='~/karst/target/release'

sh_a() { ssh -n -o BatchMode=yes "$HOST_A" "$@"; }
sh_b() { ssh -n -o BatchMode=yes "$HOST_B" "$@"; }

cleanup() {
    [ "$KEEP" -eq 1 ] && { say "left running (--keep); stop with: pkill -x karstd"; return; }
    sh_a "sudo -n pkill -x karstd 2>/dev/null; sudo -n pkill -x tcpdump 2>/dev/null; true" || true
    sh_b "sudo -n pkill -x karstd 2>/dev/null; true" || true
}
trap cleanup EXIT

[ -n "$ADDR_A" ] || ADDR_A=$(sh_a "hostname -I" | cut -d' ' -f1)
[ -n "$ADDR_B" ] || ADDR_B=$(sh_b "hostname -I" | cut -d' ' -f1)
[ -n "$ADDR_A" ] && [ -n "$ADDR_B" ] || die "could not resolve an address; pass --addr-a/--addr-b"
say "A=$HOST_A ($ADDR_A, initiator) B=$HOST_B ($ADDR_B, waits) over $ADDR_A<->$ADDR_B, $TRIALS trials"

say "Building on both hosts"
for h in "$HOST_A" "$HOST_B"; do
    ssh -n -o BatchMode=yes "$h" \
        'cd ~/karst && PATH=$HOME/.cargo/bin:$PATH cargo build --release --workspace 2>&1 | tail -1'
done

sh_a "sudo -n pkill -x karstd 2>/dev/null; true"
sh_b "sudo -n pkill -x karstd 2>/dev/null; true"
sh_a "mkdir -p $RUN && chmod 700 $RUN"
sh_b "mkdir -p $RUN && chmod 700 $RUN"

say "Generating identities"
for h in "$HOST_A" "$HOST_B"; do
    ssh -n -o BatchMode=yes "$h" "$BIN/karstd genkey > $RUN/node.key 2>/dev/null && chmod 600 $RUN/node.key &&
        printf '[node]\nlisten = \"0.0.0.0:$PORT\"\naddresses = [\"$SUBNET.1/24\"]\nprivate_key_file = \"node.key\"\n' > $RUN/stub.toml"
done
pub() { ssh -n -o BatchMode=yes "$1" "$BIN/karstd pubkey --config $RUN/stub.toml"; }
A_PUB=$(pub "$HOST_A"); B_PUB=$(pub "$HOST_B")
field() { printf '%s\n' "$2" | sed -n "s/$1 = \"\(.*\)\"/\1/p"; }
A_KEM=$(field kem_public_key "$A_PUB")
B_KEM=$(field kem_public_key "$B_PUB")
PSK=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')

say "Writing rosters (A dials B; B never dials A)"
ssh -n -o BatchMode=yes "$HOST_A" "cat > $RUN/karstd.toml <<CFG
[node]
listen = \"0.0.0.0:$PORT\"
interface = \"$IFACE\"
addresses = [\"$SUBNET.1/24\"]
private_key_file = \"node.key\"
psk_epoch = 1

[[peer]]
name = \"b\"
kem_public_key = \"$B_KEM\"
psk = \"$PSK\"
endpoint = \"$ADDR_B:$PORT\"
allowed_ips = [\"$SUBNET.2/32\"]
CFG
chmod 600 $RUN/karstd.toml && $BIN/karstd check --config $RUN/karstd.toml"
ssh -n -o BatchMode=yes "$HOST_B" "cat > $RUN/karstd.toml <<CFG
[node]
listen = \"0.0.0.0:$PORT\"
interface = \"$IFACE\"
addresses = [\"$SUBNET.2/24\"]
private_key_file = \"node.key\"
psk_epoch = 1

[[peer]]
name = \"a\"
kem_public_key = \"$A_KEM\"
psk = \"$PSK\"
allowed_ips = [\"$SUBNET.1/32\"]
CFG
chmod 600 $RUN/karstd.toml && $BIN/karstd check --config $RUN/karstd.toml"

say "Capture interface on A"
CAP_IFACE=$(sh_a "ip route get $ADDR_B | sed -n 's/.* dev \\([^ ]*\\).*/\\1/p' | head -1")
[ -n "$CAP_IFACE" ] || die "could not determine A's outbound interface to $ADDR_B"
say "A reaches B via $CAP_IFACE"

one_trial() {
    sh_a "sudo -n pkill -x karstd 2>/dev/null; sudo -n pkill -x tcpdump 2>/dev/null; true"
    sh_b "sudo -n pkill -x karstd 2>/dev/null; true"
    sleep 0.3

    # B first and given time to bind its socket — it must be listening before
    # A's first datagram arrives, or this trial measures A's retry timer
    # instead of the handshake.
    sh_b "cd $RUN && sudo -n setsid --fork $BIN/karstd \
        --config $RUN/karstd.toml --socket $RUN/karstd.sock \
        < /dev/null > $RUN/karstd.log 2>&1"
    sleep 1

    # -tt: seconds.microseconds since epoch, one clock (A's), so the two
    # timestamps this trial cares about are directly subtractable regardless
    # of what B's clock reads.
    sh_a "sudo -n timeout 5 tcpdump -i $CAP_IFACE -tt -n udp port $PORT \
        > $RUN/cap.txt 2>/dev/null &"
    sleep 0.3

    sh_a "cd $RUN && sudo -n setsid --fork $BIN/karstd \
        --config $RUN/karstd.toml --socket $RUN/karstd.sock \
        < /dev/null > $RUN/karstd.log 2>&1"

    sleep 2
    sh_a "sudo -n pkill -x karstd 2>/dev/null; true"
    sh_b "sudo -n pkill -x karstd 2>/dev/null; true"
    wait_cap=0
    while [ "$wait_cap" -lt 10 ]; do
        sh_a "pgrep -x tcpdump >/dev/null 2>&1" || break
        sleep 0.5; wait_cap=$((wait_cap + 1))
    done

    cap=$(sh_a "cat $RUN/cap.txt")
    t_out=$(printf '%s\n' "$cap" | awk -v me="$ADDR_A" '$3 ~ me"." {print $1; exit}')
    t_in=$(printf '%s\n' "$cap" | awk -v me="$ADDR_A" -v t0="$t_out" \
        '$3 !~ me"." {if ($1 > t0) {print $1; exit}}')
    [ -n "${t_out:-}" ] && [ -n "${t_in:-}" ] || { echo "  trial: no reply captured"; return; }
    awk -v a="$t_out" -v b="$t_in" 'BEGIN{printf "  trial: %.3f ms\n", (b-a)*1000}'
    awk -v a="$t_out" -v b="$t_in" 'BEGIN{printf "%.6f\n", (b-a)*1000}' >> /tmp/hs-latencies.$$
}

: > /tmp/hs-latencies.$$
say "Running $TRIALS fresh handshakes"
for i in $(seq 1 "$TRIALS"); do
    printf 'trial %d/%d:\n' "$i" "$TRIALS"
    one_trial
done

say "Summary"
if [ -s /tmp/hs-latencies.$$ ]; then
    sort -n /tmp/hs-latencies.$$ > /tmp/hs-latencies-sorted.$$
    n=$(wc -l < /tmp/hs-latencies-sorted.$$)
    median=$(sed -n "$(( (n + 1) / 2 ))p" /tmp/hs-latencies-sorted.$$)
    awk -v n="$n" -v med="$median" '
        {sum += $1; if (min == "" || $1 < min) min = $1; if ($1 > max) max = $1}
        END {printf "n=%d mean=%.3fms min=%.3fms max=%.3fms median=%.3fms\n", n, sum/n, min, max, med}
    ' /tmp/hs-latencies-sorted.$$
    rm -f /tmp/hs-latencies-sorted.$$
else
    echo "no successful trials"
fi
rm -f /tmp/hs-latencies.$$
