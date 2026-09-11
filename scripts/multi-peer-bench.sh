#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright the Karst contributors.
#
# Measure the thing karst-net/karst#118's sharded datapath is actually for.
#
# scripts/two-host-test.sh's --workers flag proves sharding does not regress
# a single peer's single flow — it cannot prove more than that, because
# sharding by peer/socket-hash does not parallelize one flow to one peer
# across cores (see karst-tun's `Tun::open_queue` doc comment): a single
# PHREATIC session serializes on that peer's own session lock no matter how
# many TUN queues or reuseport sockets exist. What multiple workers can
# parallelize is *more than one peer's* traffic, since each peer's packets
# land on whichever queue/socket the kernel's flow hash picks for its own
# address — and that is what this script drives: one "hub" node with
# node.datapath_workers = N, talking to N independent "leaf" peers on the
# other host, so the hub's aggregate throughput is a real test of whether N
# workers use more than one core where one worker could not.
#
# The leaves are ordinary karstd processes, not a simulation of one: each is
# its own process, its own TUN device, its own identity, listening on its own
# port on the leaf host. What makes them distinguishable to the hub's
# SO_REUSEPORT sockets is exactly what makes real peers distinguishable —
# each arrives from a different UDP source (same host, different port) — so
# this is the same kernel mechanism a real multi-peer deployment gets, run at
# a scale two machines can produce on demand.
#
# Usage:
#     scripts/multi-peer-bench.sh HUB_HOST LEAF_HOST [OPTIONS]
#
#     HUB_HOST     ssh destination for the node under test — the one whose
#                  node.datapath_workers this script varies.
#     LEAF_HOST    ssh destination that runs PEERS independent karstd
#                  processes, one per simulated peer.
#
# Options:
#     --peers N        how many independent leaf peers      (default: 4)
#     --workers N      HUB_HOST's node.datapath_workers      (default: PEERS)
#     --hub-addr IP    HUB_HOST's underlay address, as the leaves should
#                       dial it                              (default: resolved)
#     --leaf-addr IP   LEAF_HOST's underlay address, as the hub should
#                       dial it                               (default: resolved)
#     --base-port P    first leaf UDP port; leaf i uses P+i-1 (default: 51820)
#     --duration SECS  iperf3 run length per flow             (default: 10)
#     --keep           leave the daemons running on exit
#
# Both hosts need passwordless sudo, a Rust toolchain, and a checkout at
# ~/karst — the same prerequisites scripts/two-host-test.sh has, and for the
# same reasons (see that script's own header).

set -euo pipefail

PEERS=4
WORKERS=""
HUB_ADDR=""
LEAF_ADDR=""
BASE_PORT=51820
DURATION=10
KEEP=0

die() { echo "multi-peer-bench: $*" >&2; exit 1; }
say() { printf '\n\033[1m%s\033[0m\n' "$*"; }

[ $# -ge 2 ] || die "need two hosts; see the comment at the top of this file"
HUB_HOST=$1; LEAF_HOST=$2; shift 2

while [ $# -gt 0 ]; do
    case $1 in
        --peers)     PEERS=$2;     shift 2 ;;
        --workers)   WORKERS=$2;   shift 2 ;;
        --hub-addr)  HUB_ADDR=$2;  shift 2 ;;
        --leaf-addr) LEAF_ADDR=$2; shift 2 ;;
        --base-port) BASE_PORT=$2; shift 2 ;;
        --duration)  DURATION=$2;  shift 2 ;;
        --keep)      KEEP=1;       shift ;;
        *) die "unknown option $1" ;;
    esac
done
[ -n "$WORKERS" ] || WORKERS=$PEERS

RUN='~/karst-mp-run'
BIN='~/karst/target/release'

sh_hub()  { ssh -n -o BatchMode=yes "$HUB_HOST" "$@"; }
sh_leaf() { ssh -n -o BatchMode=yes "$LEAF_HOST" "$@"; }

cleanup() {
    [ "$KEEP" -eq 1 ] && { say "left running (--keep); stop with: pkill -x karstd; pkill -x iperf3"; return; }
    sh_hub  "sudo -n pkill -x karstd 2>/dev/null; pkill -x iperf3 2>/dev/null; true" || true
    sh_leaf "sudo -n pkill -x karstd 2>/dev/null; pkill -x iperf3 2>/dev/null; true" || true
    # The per-leaf policy rules below outlive the interfaces they route to —
    # `ip rule` is not torn down with a TUN device the way a route through it
    # is — so a rerun with a different --peers count would otherwise leave a
    # stale rule pointing nowhere.
    for i in $(seq 1 "$PEERS"); do
        sh_leaf "sudo -n ip rule del from 10.90.$i.11 lookup $((100 + i)) 2>/dev/null; true" || true
    done
}
trap cleanup EXIT

say "Hub: $HUB_HOST ($WORKERS datapath workers), $PEERS leaf peer(s) on $LEAF_HOST"

# ── addresses ────────────────────────────────────────────────────────────────
[ -n "$HUB_ADDR" ]  || HUB_ADDR=$(sh_hub  "hostname -I" | cut -d' ' -f1)
[ -n "$LEAF_ADDR" ] || LEAF_ADDR=$(sh_leaf "hostname -I" | cut -d' ' -f1)
[ -n "$HUB_ADDR" ] && [ -n "$LEAF_ADDR" ] || die "could not resolve an address; pass --hub-addr/--leaf-addr"

# ── build ────────────────────────────────────────────────────────────────────
say "Building on both hosts"
for h in "$HUB_HOST" "$LEAF_HOST"; do
    ssh -n -o BatchMode=yes "$h" \
        'cd ~/karst && PATH=$HOME/.cargo/bin:$PATH cargo build --release --workspace 2>&1 | tail -1'
done

say "Stopping anything already running from a previous pass"
sh_hub  "sudo -n pkill -x karstd 2>/dev/null; pkill -x iperf3 2>/dev/null; true" || true
sh_leaf "sudo -n pkill -x karstd 2>/dev/null; pkill -x iperf3 2>/dev/null; true" || true

sh_hub  "rm -rf $RUN && mkdir -p $RUN && chmod 700 $RUN"
sh_leaf "rm -rf $RUN && mkdir -p $RUN && chmod 700 $RUN"

# ── keys ─────────────────────────────────────────────────────────────────────
say "Generating identities (1 hub + $PEERS leaves)"
sh_hub "$BIN/karstd genkey > $RUN/node.key && chmod 600 $RUN/node.key"
# `private_key_file = "node.key"`, bare — resolved relative to the config
# file's own directory (`Config::from_file`'s `resolve`), not to the shell's
# CWD. A path with `$RUN`'s literal `~` embedded in the TOML value itself
# would not expand: the shell only expands a tilde it sees unquoted, and by
# the time this string is inside the file it is just text to the parser.
HUB_PUB=$(sh_hub "printf '[node]\nlisten = \"0.0.0.0:$BASE_PORT\"\naddresses = [\"10.90.0.1/24\"]\nprivate_key_file = \"node.key\"\n' > $RUN/stub.toml && $BIN/karstd pubkey --config $RUN/stub.toml")
field() { printf '%s\n' "$2" | sed -n "s/$1 = \"\(.*\)\"/\1/p"; }
HUB_KEM=$(field kem_public_key "$HUB_PUB")

LEAF_KEM=()
for i in $(seq 1 "$PEERS"); do
    sh_leaf "mkdir -p $RUN/leaf-$i && $BIN/karstd genkey > $RUN/leaf-$i/node.key && chmod 600 $RUN/leaf-$i/node.key"
    pub=$(sh_leaf "printf '[node]\nlisten = \"0.0.0.0:$BASE_PORT\"\naddresses = [\"10.90.$i.11/24\"]\nprivate_key_file = \"node.key\"\n' > $RUN/leaf-$i/stub.toml && $BIN/karstd pubkey --config $RUN/leaf-$i/stub.toml")
    LEAF_KEM+=("$(field kem_public_key "$pub")")
done

# ── rosters ──────────────────────────────────────────────────────────────────
say "Writing rosters"
{
    printf '[node]\nlisten = "0.0.0.0:%s"\ninterface = "karst-hub"\naddresses = ["10.90.0.1/24"]\nprivate_key_file = "node.key"\ndatapath_workers = %s\n' \
        "$BASE_PORT" "$WORKERS"
    for i in $(seq 1 "$PEERS"); do
        port=$((BASE_PORT + i - 1))
        printf '\n[[peer]]\nname = "leaf%s"\nkem_public_key = "%s"\nendpoint = "%s:%s"\nallowed_ips = ["10.90.%s.11/32"]\n' \
            "$i" "${LEAF_KEM[$((i - 1))]}" "$LEAF_ADDR" "$port" "$i"
    done
} | ssh -o BatchMode=yes "$HUB_HOST" "cat > $RUN/karstd.toml"
sh_hub "chmod 600 $RUN/karstd.toml && $BIN/karstd check --config $RUN/karstd.toml"

for i in $(seq 1 "$PEERS"); do
    port=$((BASE_PORT + i - 1))
    {
        printf '[node]\nlisten = "0.0.0.0:%s"\ninterface = "karst-p%s"\naddresses = ["10.90.%s.11/24"]\nprivate_key_file = "node.key"\n' \
            "$port" "$i" "$i"
        printf '\n[[peer]]\nname = "hub"\nkem_public_key = "%s"\nendpoint = "%s:%s"\nallowed_ips = ["10.90.0.1/32"]\n' \
            "$HUB_KEM" "$HUB_ADDR" "$BASE_PORT"
    } | ssh -o BatchMode=yes "$LEAF_HOST" "cat > $RUN/leaf-$i/karstd.toml"
    sh_leaf "chmod 600 $RUN/leaf-$i/karstd.toml && $BIN/karstd check --config $RUN/leaf-$i/karstd.toml"
done

# ── start ────────────────────────────────────────────────────────────────────
say "Starting daemons"
sh_hub "cd $RUN && sudo -n setsid --fork $BIN/karstd \
    --config $RUN/karstd.toml --socket $RUN/karstd.sock \
    < /dev/null > $RUN/karstd.log 2>&1"
for i in $(seq 1 "$PEERS"); do
    sh_leaf "cd $RUN/leaf-$i && sudo -n setsid --fork $BIN/karstd \
        --config $RUN/leaf-$i/karstd.toml --socket $RUN/leaf-$i/karstd.sock \
        < /dev/null > $RUN/leaf-$i/karstd.log 2>&1"
done
sleep 2
sh_hub "head -3 $RUN/karstd.log 2>/dev/null || true"

# **All $PEERS leaves share one network namespace on $LEAF_HOST**, unlike a
# real deployment's separate hosts — and every one of them installs its own
# cryptokey route to the same single hub address, `10.90.0.1/32`. The kernel's
# ordinary routing table can hold only one such route at a time, so whichever
# leaf's karstd added it last silently wins it away from every other leaf: a
# reply from leaf i can then leave through leaf j's TUN device instead of its
# own, arrive at the hub encrypted under peer j's session, and decrypt to an
# inner source address (leaf i's) that peer j is not entitled to claim — which
# is exactly `source_violations` firing, correctly, on a genuine cryptokey
# routing violation this script's own topology caused. A source-keyed policy
# route per leaf fixes the cause instead of the symptom: traffic actually
# originating from 10.90.$i.11 is pinned to karst-p$i regardless of what the
# main table says, the same way two real hosts never have this ambiguity
# because they never share a routing table at all.
say "Pinning each leaf's reply traffic to its own interface"
for i in $(seq 1 "$PEERS"); do
    table=$((100 + i))
    sh_leaf "sudo -n ip rule add from 10.90.$i.11 lookup $table 2>/dev/null; \
              sudo -n ip route replace 10.90.0.1/32 dev karst-p$i table $table"
done

say "Waiting for every tunnel to come up"
for i in $(seq 1 "$PEERS"); do
    for _ in $(seq 1 30); do
        sh_hub "ping -c1 -W1 10.90.$i.11 >/dev/null 2>&1" && break
        sleep 1
    done
    sh_hub "ping -c1 -W1 10.90.$i.11 >/dev/null 2>&1" || die "hub cannot reach leaf $i"
done
say "All $PEERS tunnels are up"

for h in "$HUB_HOST" "$LEAF_HOST"; do
    ssh -n -o BatchMode=yes "$h" "command -v iperf3" >/dev/null 2>&1 || {
        say "iperf3 is not installed on $h; skipping the measurement"
        exit 0
    }
done

# ── measure ──────────────────────────────────────────────────────────────────
# One iperf3 server per leaf, all on the hub's one tunnel address but distinct
# ports — the hub side of $PEERS simultaneous flows, one per peer.
say "Starting $PEERS iperf3 servers on the hub"
for i in $(seq 1 "$PEERS"); do
    sport=$((5300 + i))
    sh_hub "iperf3 -s -B 10.90.0.1 -p $sport -D >/dev/null 2>&1"
done
sleep 1

say "Running $PEERS simultaneous flows, one per leaf, ${DURATION}s each"
for i in $(seq 1 "$PEERS"); do
    sport=$((5300 + i))
    sh_leaf "iperf3 -c 10.90.0.1 -p $sport -B 10.90.$i.11 -t $DURATION -f m \
        > $RUN/leaf-$i/iperf.out 2>&1" &
done
wait

TOTAL=0
for i in $(seq 1 "$PEERS"); do
    line=$(sh_leaf "grep receiver $RUN/leaf-$i/iperf.out | tail -1" || true)
    echo "  leaf $i: ${line:-<no result>}"
    mbps=$(printf '%s\n' "$line" | grep -oE '[0-9.]+ Mbits/sec' | head -1 | cut -d' ' -f1)
    [ -n "${mbps:-}" ] && TOTAL=$(awk -v a="$TOTAL" -v b="$mbps" 'BEGIN{printf "%.1f", a+b}')
done
say "Aggregate across $PEERS peers, $WORKERS hub worker(s): ${TOTAL} Mbits/sec"

say "Hub CPU during the last flow's tail"
sh_hub "top -b -n1 -H -p \$(pgrep -x karstd) 2>/dev/null | tail -8" || true
