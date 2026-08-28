#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright the Karst contributors.
#
# ADR-0012 gate 1: what userspace mode costs against the privileged baseline.
#
# The ADR requires "release-binary size delta, peak/resident memory, and TCP
# throughput/latency for the same Karst topology and payload as the privileged
# baseline, including the exact commands and host details" before the proposal
# is accepted as implemented. The size delta was measured on 2026-08-20; this
# script is the rest.
#
# Three scenarios over one topology, so the numbers are comparable:
#
#     underlay   two namespaces, no Karst          — bounds the instrument
#     tun        both daemons on TUN devices       — the privileged baseline
#     userspace  the subject on smoltcp + SOCKS5   — what the gate is about
#
# The subject and the peer are in **separate network namespaces**, and that is
# not incidental. Both overlay addresses are local addresses on one host, so a
# TUN baseline in a single namespace would be short-circuited by the kernel and
# would measure loopback rather than Karst.
#
# One instrument for all three (bins/karstd/examples/tcpload.rs): iperf3 cannot
# speak SOCKS5, and measuring the two modes with two tools would put the
# instrument inside the difference.
#
# Usage:
#     sudo scripts/userspace-cost.sh [--seconds N] [--rtt-count N] [--keep]
#
# Needs root (namespaces and TUN devices), and a release build. Everything runs
# on this host; nothing is dialled.

set -euo pipefail

SECONDS_PER_RUN=10
RTT_COUNT=200
KEEP=0

NS_S=karst-uc-s          # the subject: TUN in one scenario, userspace in the other
NS_P=karst-uc-p          # the peer: an ordinary privileged node throughout
UNDERLAY_S=10.99.7.1
UNDERLAY_P=10.99.7.2
OVERLAY_S=10.88.7.1
OVERLAY_P=10.88.7.2
IFACE=karst-uc0
PORT_S=51861
PORT_P=51862
SOCKS_PORT=11081
SERVICE_PORT=19001
RUN=/tmp/karst-userspace-cost

die() { echo "userspace-cost: $*" >&2; exit 1; }
say() { printf '\n\033[1m%s\033[0m\n' "$*"; }

while [ $# -gt 0 ]; do
    case $1 in
        --seconds)   SECONDS_PER_RUN=$2; shift 2 ;;
        --rtt-count) RTT_COUNT=$2;       shift 2 ;;
        --keep)      KEEP=1;             shift ;;
        *) die "unknown option $1" ;;
    esac
done

[ "$(id -u)" -eq 0 ] || die "needs root: namespaces and TUN devices"
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN="$ROOT/target/release"

cleanup() {
    pkill -f "$BIN/karstd --config $RUN" 2>/dev/null || true
    pkill -f "$BIN/examples/tcpload serve" 2>/dev/null || true
    for ns in $NS_S $NS_P; do ip netns del $ns 2>/dev/null || true; done
    [ "$KEEP" -eq 1 ] || rm -rf "$RUN"
}
trap cleanup EXIT

# ── build ───────────────────────────────────────────────────────────────────
# Release, and stated as such: PLAN.md §3.4 records a 7x difference between a
# debug and a release datapath, which is enough to invert any conclusion here.
say "Building (release)"
cargo build --release --manifest-path "$ROOT/Cargo.toml" -p karstd 2>&1 | tail -1
cargo build --release --manifest-path "$ROOT/Cargo.toml" -p karstd --example tcpload 2>&1 | tail -1
TCPLOAD="$BIN/examples/tcpload"
[ -x "$TCPLOAD" ] || die "tcpload did not build"

# ── topology ────────────────────────────────────────────────────────────────
rm -rf "$RUN"; mkdir -p "$RUN"; chmod 700 "$RUN"

# ── host details, because the gate asks for them ────────────────────────────
say "Host"
{
    printf 'kernel\t%s\n' "$(uname -sr)"
    # `model name` is x86's field and is absent on aarch64, where an empty line
    # would look like a harness that failed rather than a CPU that does not
    # advertise one. `lscpu` answers on both, and the architecture is printed
    # beside it because it is the part that matters when comparing runs.
    printf 'cpu\t%s\n' "$(lscpu 2>/dev/null | sed -n 's/^Model name: *//p' | head -1)"
    printf 'arch\t%s\n' "$(uname -m)"
    printf 'cores\t%s\n' "$(nproc)"
    printf 'memory_kb\t%s\n' "$(awk '/MemTotal/ {print $2}' /proc/meminfo)"
    printf 'rustc\t%s\n' "$(rustc --version)"
    printf 'karstd_bytes\t%s\n' "$(stat -c %s "$BIN/karstd")"
} | tee "$RUN/host.tsv"

topology() {
    for ns in $NS_S $NS_P; do ip netns del $ns 2>/dev/null || true; done
    for ns in $NS_S $NS_P; do
        ip netns add $ns
        ip netns exec $ns ip link set lo up
    done
    ip link add uc-s netns $NS_S type veth peer name uc-p netns $NS_P
    ip netns exec $NS_S ip addr add $UNDERLAY_S/24 dev uc-s
    ip netns exec $NS_P ip addr add $UNDERLAY_P/24 dev uc-p
    ip netns exec $NS_S ip link set uc-s up
    ip netns exec $NS_P ip link set uc-p up
}

# ── keys ────────────────────────────────────────────────────────────────────
keys() {
    for tag in s p; do
        mkdir -p "$RUN/$tag"
        "$BIN/karstd" genkey > "$RUN/$tag/node.key" 2>/dev/null
        chmod 600 "$RUN/$tag/node.key"
        printf '[node]\nlisten = "0.0.0.0:%s"\naddresses = ["%s/24"]\nprivate_key_file = "node.key"\n' \
            "$PORT_S" "$OVERLAY_S" > "$RUN/$tag/stub.toml"
    done
    field() { sed -n "s/$1 = \"\(.*\)\"/\1/p" "$2"; }
    ( cd "$RUN/s" && "$BIN/karstd" pubkey --config stub.toml > pub.txt )
    ( cd "$RUN/p" && "$BIN/karstd" pubkey --config stub.toml > pub.txt )
    S_KEM=$(field kem_public_key "$RUN/s/pub.txt"); S_DH=$(field dh_public_key "$RUN/s/pub.txt")
    P_KEM=$(field kem_public_key "$RUN/p/pub.txt"); P_DH=$(field dh_public_key "$RUN/p/pub.txt")
    # A per-pair PSK, as §2.6 requires of a real deployment. Identical in both
    # scenarios, so it is in neither difference — but a run without one takes a
    # different branch of the key schedule and logs a warning, and a benchmark
    # should not be measuring the unusual path.
    PSK=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
}

# $1 = tag, $2 = own overlay, $3 = own port, $4 = peer kem, $5 = peer dh,
# $6 = peer underlay, $7 = peer port, $8 = peer overlay, $9 = "userspace"|"tun"
write_config() {
    local attachment=""
    [ "$9" = userspace ] && attachment=$(printf 'network_mode = "userspace"\nuserspace_socks5_listen = "127.0.0.1:%s"\n' "$SOCKS_PORT")
    cat > "$RUN/$1/karstd.toml" <<CFG
[node]
listen = "0.0.0.0:$3"
interface = "$IFACE"
addresses = ["$2/24"]
private_key_file = "node.key"
psk_epoch = 1
$attachment
[[peer]]
name = "other"
kem_public_key = "$4"
dh_public_key = "$5"
psk = "$PSK"
endpoint = "$6:$7"
allowed_ips = ["$8/32"]
CFG
    chmod 600 "$RUN/$1/karstd.toml"
}

start_node() {   # $1 = tag, $2 = namespace
    ip netns exec "$2" env -C "$RUN/$1" "$BIN/karstd" \
        --config "$RUN/$1/karstd.toml" --socket "$RUN/$1/karstd.sock" \
        > "$RUN/$1/karstd.log" 2>&1 &
}

established() {  # $1 = tag
    "$BIN/karst" status --socket "$RUN/$1/karstd.sock" 2>/dev/null \
        | grep -q 'state = "established"'
}

wait_established() {
    local deadline=$((SECONDS + 40))
    while [ $SECONDS -lt $deadline ]; do
        if established s && established p; then return 0; fi
        sleep 0.5
    done
    echo "--- subject log ---"; cat "$RUN/s/karstd.log" || true
    echo "--- peer log ---";    cat "$RUN/p/karstd.log" || true
    die "the pair never established"
}

# Peak and current resident set, from the kernel rather than from `ps`, which
# rounds. VmHWM is the high-water mark: it survives the transfer ending, which
# a sample of VmRSS taken afterwards does not.
memory() {       # $1 = pid
    awk '/VmHWM|VmRSS/ {printf "%s\t%s\n", tolower(substr($1,1,length($1)-1)), $2}' \
        "/proc/$1/status" 2>/dev/null || true
}

record() {       # $1 = scenario, then key/value lines on stdin
    sed "s/^/$1\t/" >> "$RUN/results.tsv"
}

# ── scenario 1: the underlay, with no Karst in it ───────────────────────────
say "Scenario: underlay (no Karst)"
topology
ip netns exec $NS_P "$TCPLOAD" serve "$UNDERLAY_P:$SERVICE_PORT" > "$RUN/serve.log" 2>&1 &
sleep 0.5
ip netns exec $NS_S "$TCPLOAD" sink "$UNDERLAY_P:$SERVICE_PORT" --seconds "$SECONDS_PER_RUN" | record underlay
ip netns exec $NS_S "$TCPLOAD" rtt  "$UNDERLAY_P:$SERVICE_PORT" --count "$RTT_COUNT" | record underlay
pkill -f "$TCPLOAD serve" || true

# ── scenarios 2 and 3: through Karst ────────────────────────────────────────
run_karst() {    # $1 = tun|userspace
    local mode=$1
    say "Scenario: $mode"
    topology
    keys
    write_config s "$OVERLAY_S" "$PORT_S" "$P_KEM" "$P_DH" "$UNDERLAY_P" "$PORT_P" "$OVERLAY_P" "$mode"
    write_config p "$OVERLAY_P" "$PORT_P" "$S_KEM" "$S_DH" "$UNDERLAY_S" "$PORT_S" "$OVERLAY_S" tun
    start_node s $NS_S
    start_node p $NS_P
    wait_established

    # `ip netns exec` may fork before exec, so the daemon's pid is looked up
    # rather than assumed to be the one the shell was handed.
    local subject peer
    subject=$(pgrep -f "karstd --config $RUN/s/karstd.toml" | head -1)
    peer=$(pgrep -f "karstd --config $RUN/p/karstd.toml" | head -1)
    [ -n "$subject" ] && [ -n "$peer" ] || die "lost track of a daemon"

    # The service always lives on the peer's overlay address, on the privileged
    # path. Only how the client reaches it changes.
    ip netns exec $NS_P "$TCPLOAD" serve "$OVERLAY_P:$SERVICE_PORT" > "$RUN/serve.log" 2>&1 &
    sleep 0.5

    local via=()
    [ "$mode" = userspace ] && via=(--socks5 "127.0.0.1:$SOCKS_PORT")
    ip netns exec $NS_S "$TCPLOAD" sink "$OVERLAY_P:$SERVICE_PORT" "${via[@]}" \
        --seconds "$SECONDS_PER_RUN" | record "$mode"
    ip netns exec $NS_S "$TCPLOAD" rtt "$OVERLAY_P:$SERVICE_PORT" "${via[@]}" \
        --count "$RTT_COUNT" | record "$mode"

    # Sampled while the daemons are still up: VmHWM is gone with the process.
    memory "$subject" | sed 's/^/subject_/' | record "$mode"
    memory "$peer"    | sed 's/^/peer_/'    | record "$mode"

    pkill -f "$TCPLOAD serve" || true
    kill "$subject" "$peer" 2>/dev/null || true
    sleep 1
}

run_karst tun
run_karst userspace

# ── report ──────────────────────────────────────────────────────────────────
say "Results"
column -t -s "$(printf '\t')" "$RUN/results.tsv"

say "Summary"
value() { awk -F'\t' -v s="$1" -v k="$2" '$1==s && $2==k {print $3}' "$RUN/results.tsv"; }
printf 'metric\tunderlay\ttun\tuserspace\n'
for k in mbps rtt_p50_ms rtt_p90_ms subject_vmhwm subject_vmrss; do
    printf '%s\t%s\t%s\t%s\n' "$k" "$(value underlay "$k")" "$(value tun "$k")" "$(value userspace "$k")"
done | column -t -s "$(printf '\t')"

[ "$KEEP" -eq 1 ] && say "kept: $RUN"
exit 0
