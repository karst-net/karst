#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright the Karst contributors.
#
# Bring up a Karst tunnel between two real hosts and measure it.
#
# The netns tests in bins/karstd/tests/two_nodes.rs prove the datapath works
# between two daemons. They cannot tell you what it does over a real NIC: no
# driver, no interrupts, no queue discipline, and a loopback-ish path whose
# throughput means nothing. This script is the other half — PLAN.md's Phase 2
# exit criterion is stated in Mbps over a LAN, and that has to be measured.
#
# Usage:
#     scripts/two-host-test.sh HOST_A HOST_B [OPTIONS]
#
#     HOST_A, HOST_B    ssh destinations. Both need passwordless sudo, a Rust
#                       toolchain, and a checkout at ~/karst.
#
# Options:
#     --addr-a IP       underlay address of A, as B should dial it
#     --addr-b IP       underlay address of B, as A should dial it
#                       (default: resolved from each host's hostname)
#     --port PORT       UDP port                       (default: 51820)
#     --subnet PREFIX   tunnel /24, first three octets (default: 10.88.0)
#     --iface NAME      interface name                 (default: karst0)
#     --duration SECS   iperf3 run length              (default: 10)
#     --no-bench        set the tunnel up and stop; do not measure
#     --keep            leave the daemons running on exit
#
# One host may be behind NAT: pass its peer no address and it will be learned
# from the handshake. Pass --addr-a "" to say A is unreachable inbound.

set -euo pipefail

PORT=51820
SUBNET=10.88.0
IFACE=karst0
DURATION=10
BENCH=1
KEEP=0
ADDR_A=""
ADDR_B=""
ADDR_A_SET=0
ADDR_B_SET=0

die() { echo "two-host-test: $*" >&2; exit 1; }
say() { printf '\n\033[1m%s\033[0m\n' "$*"; }

[ $# -ge 2 ] || die "need two hosts; see the comment at the top of this file"
HOST_A=$1; HOST_B=$2; shift 2

while [ $# -gt 0 ]; do
    case $1 in
        --addr-a)    ADDR_A=${2:-}; ADDR_A_SET=1; shift 2 ;;
        --addr-b)    ADDR_B=${2:-}; ADDR_B_SET=1; shift 2 ;;
        --port)      PORT=$2;     shift 2 ;;
        --subnet)    SUBNET=$2;   shift 2 ;;
        --iface)     IFACE=$2;    shift 2 ;;
        --duration)  DURATION=$2; shift 2 ;;
        --no-bench)  BENCH=0;     shift ;;
        --keep)      KEEP=1;      shift ;;
        *) die "unknown option $1" ;;
    esac
done

# Single-quoted, so the tilde travels to the remote shell unexpanded. Bare
# `~/karst-run` would expand against *this* machine's home directory and then be
# sent as an absolute path that does not exist over there.
RUN='~/karst-run'
BIN='~/karst/target/release'

# `ssh -n` throughout: without it a backgrounded remote command inherits the
# session's stdin and the connection never closes.
sh_a() { ssh -n -o BatchMode=yes "$HOST_A" "$@"; }
sh_b() { ssh -n -o BatchMode=yes "$HOST_B" "$@"; }

cleanup() {
    [ "$KEEP" -eq 1 ] && { say "left running (--keep); stop with: pkill -x karstd"; return; }
    sh_a "sudo -n pkill -x karstd 2>/dev/null; pkill -x iperf3 2>/dev/null; true" || true
    sh_b "sudo -n pkill -x karstd 2>/dev/null; pkill -x iperf3 2>/dev/null; true" || true
}
trap cleanup EXIT

# ── build ───────────────────────────────────────────────────────────────────
say "Building on both hosts"
for h in "$HOST_A" "$HOST_B"; do
    ssh -n -o BatchMode=yes "$h" \
        'cd ~/karst && PATH=$HOME/.cargo/bin:$PATH cargo build --release --workspace 2>&1 | tail -1'
done

# ── addresses ───────────────────────────────────────────────────────────────
# Default to whatever each host's hostname resolves to locally. Override for a
# dedicated link — a bonded or 10G interface is usually not what DNS returns.
[ "$ADDR_A_SET" -eq 1 ] || ADDR_A=$(sh_a "hostname -I | awk '{print \$1}'")
[ "$ADDR_B_SET" -eq 1 ] || ADDR_B=$(sh_b "hostname -I | awk '{print \$1}'")
[ -n "$ADDR_B" ] || die "B needs a reachable address: at least one side must be dialable"

# ── keys ────────────────────────────────────────────────────────────────────
say "Generating identities"
for h in "$HOST_A" "$HOST_B"; do
    ssh -n -o BatchMode=yes "$h" "mkdir -p $RUN && chmod 700 $RUN &&
        $BIN/karstd genkey > $RUN/node.key 2>/dev/null && chmod 600 $RUN/node.key &&
        printf '[node]\nlisten = \"0.0.0.0:$PORT\"\naddresses = [\"$SUBNET.1/24\"]\nprivate_key_file = \"node.key\"\n' > $RUN/stub.toml &&
        chmod 600 $RUN/stub.toml"
done
pub() { ssh -n -o BatchMode=yes "$1" "$BIN/karstd pubkey --config $RUN/stub.toml"; }
A_PUB=$(pub "$HOST_A"); B_PUB=$(pub "$HOST_B")
field() { printf '%s\n' "$2" | sed -n "s/$1 = \"\(.*\)\"/\1/p"; }
A_KEM=$(field kem_public_key "$A_PUB"); A_DH=$(field dh_public_key "$A_PUB")
B_KEM=$(field kem_public_key "$B_PUB"); B_DH=$(field dh_public_key "$B_PUB")

# A per-pair PSK (spec §2.6). Phase 3's control plane distributes these; here it
# is shared out of band, which is exactly the Phase 2 arrangement. Without one
# the handshake still has both key families but loses the pre-shared secret that
# would survive a break of both, and karstd says so at startup (§7.3).
PSK=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')

# ── configuration ───────────────────────────────────────────────────────────
say "Writing rosters"
write_config() {
    local host=$1 me=$2 peer_name=$3 peer_kem=$4 peer_dh=$5 peer_addr=$6 peer_ip=$7
    local endpoint=""
    # An empty peer address means that peer is behind NAT: leave the endpoint
    # out and it is learned from the handshake.
    [ -n "$peer_addr" ] && endpoint="endpoint = \"$peer_addr:$PORT\""
    ssh -n -o BatchMode=yes "$host" "cat > $RUN/karstd.toml <<'CFG'
[node]
listen = \"0.0.0.0:$PORT\"
interface = \"$IFACE\"
addresses = [\"$SUBNET.$me/24\"]
private_key_file = \"node.key\"
psk_epoch = 1

[[peer]]
name = \"$peer_name\"
kem_public_key = \"$peer_kem\"
dh_public_key = \"$peer_dh\"
psk = \"$PSK\"
$endpoint
allowed_ips = [\"$SUBNET.$peer_ip/32\"]
CFG
chmod 600 $RUN/karstd.toml && $BIN/karstd check --config $RUN/karstd.toml"
}
write_config "$HOST_A" 1 "$HOST_B" "$B_KEM" "$B_DH" "$ADDR_B" 2
write_config "$HOST_B" 2 "$HOST_A" "$A_KEM" "$A_DH" "$ADDR_A" 1

# ── start ───────────────────────────────────────────────────────────────────
say "Starting daemons"
cleanup_quiet() { ssh -n -o BatchMode=yes "$1" "sudo -n pkill -x karstd 2>/dev/null; true"; }
cleanup_quiet "$HOST_A"; cleanup_quiet "$HOST_B"
for h in "$HOST_B" "$HOST_A"; do
    # `setsid` and a redirected stdin, or the ssh channel stays open holding the
    # daemon's stdio and this script blocks forever.
    # `setsid --fork`, not `setsid ... &` — with `&` the ssh session never
    # closes and this loop hangs forever. See scripts/soak.sh for the detail.
    ssh -n -o BatchMode=yes "$h" "cd $RUN && sudo -n setsid --fork $BIN/karstd \
        --config $RUN/karstd.toml --socket $RUN/karstd.sock \
        < /dev/null > $RUN/karstd.log 2>&1"
    sleep 2
    ssh -n -o BatchMode=yes "$h" "head -2 $RUN/karstd.log 2>/dev/null || true"
done

# ── verify ──────────────────────────────────────────────────────────────────
say "Connectivity"
sh_a "ping -c4 -W2 $SUBNET.2" | tail -2
say "Reverse direction"
sh_b "ping -c4 -W2 $SUBNET.1" | tail -2

# 1280 bytes of IP packet with DF set. This is the case spec §13.6 exists for:
# it must cross without IP fragmentation anywhere on the path.
say "Full-MTU, DF set (spec §13.6)"
sh_a "ping -c3 -W2 -s 1252 -M do $SUBNET.2" | tail -2

say "Status"
sh_a "sudo -n $BIN/karst status --socket $RUN/karstd.sock"

[ "$BENCH" -eq 1 ] || exit 0

# ── measure ─────────────────────────────────────────────────────────────────
command -v iperf3 >/dev/null 2>&1 || sh_a "command -v iperf3" >/dev/null 2>&1 || {
    say "iperf3 is not installed on $HOST_A; skipping the benchmark"
    exit 0
}

say "Baseline: underlay, no tunnel"
sh_b "setsid iperf3 -s -B $ADDR_B -p 5202 -D >/dev/null 2>&1; sleep 1"
sh_a "iperf3 -c $ADDR_B -p 5202 -t $DURATION -f m" | grep -E 'sender|receiver' || true

say "Through the Karst tunnel"
sh_b "setsid --fork iperf3 -s -B $SUBNET.2 -D >/dev/null 2>&1 || true; sleep 1"
sh_a "iperf3 -c $SUBNET.2 -t $DURATION -f m" | grep -E 'sender|receiver' || true

# Parallel streams separate two very different explanations for a low number.
# If throughput does not rise with more flows, the bottleneck is serialisation
# inside the daemon rather than per-packet cost.
say "Through the tunnel, 4 parallel streams"
sh_a "iperf3 -c $SUBNET.2 -t $DURATION -P 4 -f m" | grep -E 'SUM.*(sender|receiver)' || true

say "Daemon CPU during transfer"
sh_a "iperf3 -c $SUBNET.2 -t 8 -f m >/dev/null 2>&1 &
      sleep 3; top -b -n1 -H -p \$(pgrep -x karstd) 2>/dev/null | tail -5; wait" || true
