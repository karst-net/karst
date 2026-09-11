#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright the Karst contributors.
#
# Measure one karstd's steady-state CPU and memory with a large idle roster —
# karst-net/karst#119's "200-peer idle CPU <1%/RSS <60 MB" criterion.
#
# All PEERS peer entries are fake identities with no endpoint and nothing on
# the other end to dial in: `Engine::connect_all`/`poll` still walk the whole
# roster every tick (see `bins/karstd/src/engine.rs::poll`'s per-peer timer
# sweep), so this measures the thing the criterion actually asks about — the
# steady-state cost of *carrying* 200 configured peers, not of any traffic —
# on a single real host. No second host is needed: idle peers never send
# anything for a two-host test to differ on.
#
# Usage:
#     scripts/idle-peers-bench.sh HOST [OPTIONS]
#
#     HOST    ssh destination. Needs passwordless sudo, a Rust toolchain, and
#             a checkout at ~/karst.
#
# Options:
#     --peers N        idle peer entries          (default: 200)
#     --duration SECS  sampling window, after a 5s warmup (default: 120)
#     --interval SECS  seconds between samples     (default: 5)
#     --keep           leave the daemon running on exit

set -euo pipefail

PEERS=200
DURATION=120
INTERVAL=5
KEEP=0

die() { echo "idle-peers-bench: $*" >&2; exit 1; }
say() { printf '\n\033[1m%s\033[0m\n' "$*"; }

[ $# -ge 1 ] || die "usage: idle-peers-bench.sh HOST [OPTIONS]"
HOST=$1; shift

while [ $# -gt 0 ]; do
    case $1 in
        --peers)    PEERS=$2;    shift 2 ;;
        --duration) DURATION=$2; shift 2 ;;
        --interval) INTERVAL=$2; shift 2 ;;
        --keep)     KEEP=1;      shift ;;
        *) die "unknown option $1" ;;
    esac
done

RUN='~/karst-idle-run'
BIN='~/karst/target/release'
sh_h() { ssh -n -o BatchMode=yes "$HOST" "$@"; }

cleanup() {
    [ "$KEEP" -eq 1 ] && { say "left running (--keep); stop with: pkill -x karstd"; return; }
    sh_h "sudo -n pkill -x karstd 2>/dev/null; true" || true
}
trap cleanup EXIT

say "Building on $HOST"
sh_h 'cd ~/karst && PATH=$HOME/.cargo/bin:$PATH cargo build --release --workspace 2>&1 | tail -1'

sh_h "sudo -n pkill -x karstd 2>/dev/null; true"
sh_h "rm -rf $RUN && mkdir -p $RUN && chmod 700 $RUN"

say "Generating identity and a $PEERS-peer idle roster"
sh_h "$BIN/karstd genkey > $RUN/node.key && chmod 600 $RUN/node.key"

# Each fake peer needs its own valid ML-KEM-1024 public key — `karstd genkey`
# plus `pubkey` gives a real one cheaply, once, reused for every entry. It is
# the same fake identity `PEERS` times over, which is fine: nothing here ever
# authenticates as one of them, so their key material only has to be
# well-formed, not distinct.
sh_h "$BIN/karstd genkey > $RUN/fake.key && chmod 600 $RUN/fake.key &&
    printf '[node]\nlisten = \"0.0.0.0:0\"\naddresses = [\"10.250.0.1/32\"]\nprivate_key_file = \"fake.key\"\n' > $RUN/fake-stub.toml"
FAKE_PUB=$(sh_h "$BIN/karstd pubkey --config $RUN/fake-stub.toml")
FAKE_KEM=$(printf '%s\n' "$FAKE_PUB" | sed -n 's/kem_public_key = "\(.*\)"/\1/p')
[ -n "$FAKE_KEM" ] || die "could not derive a fake peer public key"

{
    printf '[node]\nlisten = "0.0.0.0:51820"\ninterface = "karst0"\naddresses = ["10.249.0.1/24"]\nprivate_key_file = "node.key"\n'
    for i in $(seq 1 "$PEERS"); do
        a=$(( i / 256 )); b=$(( i % 256 ))
        printf '\n[[peer]]\nname = "idle%s"\nkem_public_key = "%s"\nallowed_ips = ["10.248.%s.%s/32"]\n' "$i" "$FAKE_KEM" "$a" "$b"
    done
} | ssh -o BatchMode=yes "$HOST" "cat > $RUN/karstd.toml"
sh_h "chmod 600 $RUN/karstd.toml && $BIN/karstd check --config $RUN/karstd.toml"

say "Starting karstd with $PEERS idle peers"
sh_h "cd $RUN && sudo -n setsid --fork $BIN/karstd \
    --config $RUN/karstd.toml --socket $RUN/karstd.sock \
    < /dev/null > $RUN/karstd.log 2>&1"
sleep 5
PID=$(sh_h "pgrep -x karstd | head -1")
[ -n "$PID" ] || die "karstd did not start; see $RUN/karstd.log on $HOST"

say "Sampling for ${DURATION}s (${INTERVAL}s interval, PID $PID)"
: > /tmp/idle-samples.$$
n=0
while [ "$n" -lt $((DURATION / INTERVAL)) ]; do
    sample=$(sh_h "ps -o %cpu=,rss= -p $PID 2>/dev/null" || true)
    [ -n "$sample" ] && printf '%s\n' "$sample" >> /tmp/idle-samples.$$
    sleep "$INTERVAL"
    n=$((n + 1))
done

say "Result"
if [ -s /tmp/idle-samples.$$ ]; then
    awk '
        {cpu[NR]=$1; rss[NR]=$2; cpu_sum+=$1; if($1>cpu_max)cpu_max=$1; if(rss_max=="" || $2>rss_max)rss_max=$2}
        END {
            printf "n=%d samples\n", NR
            printf "CPU: mean=%.2f%% max=%.2f%% (target: <1%%)\n", cpu_sum/NR, cpu_max
            printf "RSS: max=%.1fMB (target: <60MB)\n", rss_max/1024
        }
    ' /tmp/idle-samples.$$
else
    echo "no samples collected"
fi
rm -f /tmp/idle-samples.$$
sh_h "tail -3 $RUN/karstd.log"
