#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright the Karst contributors.
#
# Long-duration soak between two hosts — PLAN.md's Phase 2 exit criterion.
#
# The criterion asks the tunnel to "survive a 12-hour soak with rekeying". At
# REKEY_AFTER_TIME = 120 s that is ~360 rekeys per peer, so what is really being
# tested is whether anything *accumulates*: a leak, a counter that drifts, a
# session that fails to come back, a reassembly slot never released.
#
# Usage:
#     scripts/soak.sh HOST_A HOST_B [--hours N] [--addr-a IP] [--addr-b IP]
#
# Samples every minute and writes a TSV log plus a verdict. Safe to leave
# running: it tears the daemons down on exit, including on interrupt.
#
# A short run first is strongly advised — `--hours 0.25` exercises every code
# path here in fifteen minutes, and finding a harness bug twelve hours in is an
# expensive way to learn about it.

set -euo pipefail

HOURS=12
PORT=51820
SUBNET=10.99.0
ADDR_A=""
ADDR_B=""
INTERVAL=60

die() { echo "soak: $*" >&2; exit 1; }
say() { printf '\n\033[1m%s\033[0m\n' "$*"; }

[ $# -ge 2 ] || die "usage: soak.sh HOST_A HOST_B [--hours N]"
HOST_A=$1; HOST_B=$2; shift 2
while [ $# -gt 0 ]; do
    case $1 in
        --hours)   HOURS=$2;    shift 2 ;;
        --addr-a)  ADDR_A=$2;   shift 2 ;;
        --addr-b)  ADDR_B=$2;   shift 2 ;;
        --port)    PORT=$2;     shift 2 ;;
        --interval) INTERVAL=$2; shift 2 ;;
        *) die "unknown option $1" ;;
    esac
done

RUN='~/karst-soak'
BIN='~/karst/target/release'
LOG="soak-$(date +%Y%m%d-%H%M%S).tsv"

# Both sides go over ssh, including a host driving itself. A local `bash -c`
# path was tried and dropped: it is a *third* level of quoting for the same
# command strings, and it failed in a way that looked like the daemon refusing
# to start. One code path that works beats two that nearly do.
#
# A long soak should still be *launched* from one of the machines under test —
# `ssh HOST ./soak.sh HOST OTHER` — so the run outlives the session that started
# it, rather than from a workstation that may disconnect hours in.
sh_a() { ssh -n -o BatchMode=yes "$HOST_A" "$@"; }
sh_b() { ssh -n -o BatchMode=yes "$HOST_B" "$@"; }

cleanup() {
    say "Tearing down"
    sh_a "sudo -n pkill -x karstd 2>/dev/null; pkill -x iperf3 2>/dev/null; rm -rf $RUN; true" || true
    sh_b "sudo -n pkill -x karstd 2>/dev/null; pkill -x iperf3 2>/dev/null; rm -rf $RUN; true" || true
}
trap cleanup EXIT INT TERM

[ -n "$ADDR_A" ] || ADDR_A=$(sh_a "hostname -I | awk '{print \$1}'")
[ -n "$ADDR_B" ] || ADDR_B=$(sh_b "hostname -I | awk '{print \$1}'")

say "Building"
sh_a 'cd ~/karst && PATH=$HOME/.cargo/bin:$PATH cargo build --release --workspace 2>&1 | tail -1'
sh_b 'cd ~/karst && PATH=$HOME/.cargo/bin:$PATH cargo build --release --workspace 2>&1 | tail -1' 

say "Generating identities"
identity() {
    "$1" "mkdir -p $RUN && chmod 700 $RUN &&
        $BIN/karstd genkey > $RUN/node.key 2>/dev/null && chmod 600 $RUN/node.key &&
        printf '[node]\nlisten = \"0.0.0.0:$PORT\"\naddresses = [\"$SUBNET.1/24\"]\nprivate_key_file = \"node.key\"\n' > $RUN/stub.toml &&
        chmod 600 $RUN/stub.toml"
}
identity sh_a
identity sh_b
field() { printf '%s\n' "$2" | sed -n "s/$1 = \"\(.*\)\"/\1/p"; }
A_PUB=$(sh_a "$BIN/karstd pubkey --config $RUN/stub.toml")
B_PUB=$(sh_b "$BIN/karstd pubkey --config $RUN/stub.toml")
PSK=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')

write_config() {
    local runner=$1 me=$2 peer=$3 kem=$4 addr=$5 peer_ip=$6
    "$runner" "cat > $RUN/karstd.toml <<'CFG'
[node]
listen = \"0.0.0.0:$PORT\"
interface = \"karst0\"
addresses = [\"$SUBNET.$me/24\"]
private_key_file = \"node.key\"
psk_epoch = 1

[[peer]]
name = \"$peer\"
kem_public_key = \"$kem\"
psk = \"$PSK\"
endpoint = \"$addr:$PORT\"
allowed_ips = [\"$SUBNET.$peer_ip/32\"]
CFG
chmod 600 $RUN/karstd.toml"
}
write_config sh_a 1 "$HOST_B" "$(field kem_public_key "$B_PUB")" "$ADDR_B" 2
write_config sh_b 2 "$HOST_A" "$(field kem_public_key "$A_PUB")" "$ADDR_A" 1

say "Starting daemons"
# **`setsid --fork`, not `setsid ... &`.** The difference is the whole reason
# this harness did not work: with `&`, the ssh session never closes even though
# the daemon's own descriptors are all redirected to a file, so the script hangs
# forever on the first daemon it starts. `setsid --fork` returns as soon as the
# parent has forked, which closes the channel cleanly. Measured: 20 s timeout
# versus 1 s.
#
# The log is then read by a *separate* invocation. `|| true` on it is
# load-bearing under `set -e`: `head` exits non-zero on a file the daemon has
# not flushed yet, and liveness is established by the ping below rather than by
# whether a banner arrived in time.
start_daemon() {
    "$1" "cd $RUN && sudo -n setsid --fork $BIN/karstd \
        --config $RUN/karstd.toml --socket $RUN/karstd.sock \
        < /dev/null > $RUN/karstd.log 2>&1"
    sleep 2
    "$1" "head -1 $RUN/karstd.log 2>/dev/null || true"
}
start_daemon sh_b
start_daemon sh_a
sleep 2
sh_a "ping -c5 -W2 $SUBNET.2" | tail -2 || {
    say "The tunnel did not come up. Daemon logs:"
    sh_a "tail -5 $RUN/karstd.log" || true
    sh_b "tail -5 $RUN/karstd.log" || true
    die "aborting before a long run on a tunnel that is already down"
}

# Continuous load. `-t 0` runs until killed, so the tunnel is never idle and
# every rekey happens under traffic rather than in a quiet moment — which is the
# case that matters and the one a ping-only soak would miss.
say "Starting continuous load"
sh_b "setsid --fork iperf3 -s -B $SUBNET.2 -D >/dev/null 2>&1 || true; sleep 1"
sh_a "cd $RUN && setsid --fork iperf3 -c $SUBNET.2 -t 0 -i 0 --logfile $RUN/iperf.log < /dev/null > /dev/null 2>&1"
sleep 2
say "Load started"

END=$(( $(date +%s) + $(awk "BEGIN{printf \"%d\", $HOURS*3600}") ))
printf 'elapsed_s\tstate\ttx\trx\tmalformed\tdecrypt_fail\tmac_fail\tsrc_viol\tunroutable\trss_kb\tping_ms\n' > "$LOG"
say "Soaking for $HOURS h — logging to $LOG"

START=$(date +%s)
fails=0
while [ "$(date +%s)" -lt "$END" ]; do
    status=$(sh_a "sudo -n $BIN/karst status --socket $RUN/karstd.sock" 2>/dev/null || echo "")
    get() { printf '%s\n' "$status" | sed -n "s/^$1 = //p" | tr -d '"' | head -1; }
    state=$(printf '%s\n' "$status" | sed -n 's/^state = "\(.*\)"/\1/p' | head -1)
    rss=$(sh_a "ps -o rss= -C karstd 2>/dev/null | head -1 | tr -d ' '" || echo 0)
    rtt=$(sh_a "ping -c1 -W2 $SUBNET.2 2>/dev/null | sed -n 's/.*time=\([0-9.]*\).*/\1/p'" || echo "")

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$(( $(date +%s) - START ))" "${state:-DOWN}" "$(get tx_packets)" "$(get rx_packets)" \
        "$(get malformed)" "$(get decrypt_failures)" "$(get mac_failures)" \
        "$(get source_violations)" "$(get unroutable)" "${rss:-0}" "${rtt:-LOSS}" >> "$LOG"

    # Two things end a soak early, because continuing tells you nothing more.
    if [ "${state:-DOWN}" = "DOWN" ]; then
        fails=$((fails+1))
        echo "soak: status unavailable ($fails)" >&2
        [ "$fails" -ge 3 ] && die "the daemon stopped answering — see $RUN/karstd.log"
    elif [ -z "$rtt" ]; then
        echo "soak: ping lost at $(( $(date +%s) - START ))s" >&2
    else
        fails=0
    fi
    sleep "$INTERVAL"
done

say "Verdict"
awk -F'\t' 'NR>1 {
    n++
    if ($2 !~ /established/) down++
    if ($11 == "LOSS") loss++
    if (NR==2) { rss0=$10; tx0=$3 }
    rssN=$10; txN=$3
    if ($5+0 > 0) malformed=$5
    if ($6+0 > 0) decfail=$6
    if ($7+0 > 0) macfail=$7
    if ($8+0 > 0) srcviol=$8
}
END {
    printf "samples          %d\n", n
    printf "not established  %d\n", down+0
    printf "ping lost        %d\n", loss+0
    printf "packets sent     %d\n", txN-tx0
    printf "RSS first/last   %d / %d kB  (%+d)\n", rss0, rssN, rssN-rss0
    printf "malformed        %d\n", malformed+0
    printf "decrypt failures %d\n", decfail+0
    printf "mac failures     %d\n", macfail+0
    printf "source violations %d\n", srcviol+0
    verdict = (down+0 == 0 && loss+0 == 0 && srcviol+0 == 0) ? "PASS" : "FAIL"
    printf "\n%s\n", verdict
}' "$LOG"

say "Full log: $LOG"
