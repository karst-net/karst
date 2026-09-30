#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright the Karst contributors.
#
# Bring karst up between two hosts, measure it, tear it down — the "karst"
# row of scripts/vpn-compare/run-all.sh (issue #201).
#
# Modeled directly on scripts/two-host-test.sh (genkey/config/start
# sequence), with two differences forced by these particular lab hosts:
# turing/lovelace already run a *production* karstd+karst-relay on
# 0.0.0.0:51820/karst0 (see lib.sh's header), so this script uses a
# disjoint port/interface/subnet ($VC_PORT_BASE, vc-karst0, 10.201.0.0/24)
# and tears down by matching its own config path with `pkill -f`, never
# `pkill -x karstd` — that would kill the production daemon too.
#
# Usage:
#     scripts/vpn-compare/setup-karst.sh HOST_A HOST_B [--keep]

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./lib.sh

[ $# -ge 2 ] || die "usage: setup-karst.sh HOST_A HOST_B [--keep]"
HOST_A=$1; HOST_B=$2; shift 2
KEEP=0
[ "${1:-}" = --keep ] && KEEP=1

PORT=$((VC_PORT_BASE + 20))
SUBNET=10.201.0
IFACE=vc-karst0
RUN="$RUN_DIR/karst"
BIN=$KARST_BIN
# pkill -f anchor for cleanup. Deliberately *without* the leading `~/`: `~`
# is only expanded by the remote shell in the unquoted command that starts
# karstd (so its real /proc cmdline holds the expanded absolute path), but
# pkill_safe embeds this pattern inside single quotes, which suppresses
# tilde expansion — matching on the literal "~/..." would silently never
# match the running process's actual (expanded) argv.
CFG_MATCH="vpn-compare-run/karst/karstd.toml"

cleanup() {
    [ "$KEEP" -eq 1 ] && { say "karst: left running (--keep)"; return; }
    pkill_safe "$HOST_A" "$CFG_MATCH" sudo
    pkill_safe "$HOST_B" "$CFG_MATCH" sudo
}
trap cleanup EXIT

say "karst: addresses"
ADDR_A=$(sh_a "hostname -I" | cut -d' ' -f1)
ADDR_B=$(sh_b "hostname -I" | cut -d' ' -f1)

say "karst: keys + config"
for h in "$HOST_A" "$HOST_B"; do
    ssh -n -o BatchMode=yes "$h" "mkdir -p $RUN && chmod 700 $RUN && \
        $BIN/karstd genkey > $RUN/node.key 2>/dev/null && chmod 600 $RUN/node.key && \
        printf '[node]\nlisten = \"0.0.0.0:$PORT\"\naddresses = [\"$SUBNET.1/24\"]\nprivate_key_file = \"node.key\"\n' \
            > $RUN/stub.toml && chmod 600 $RUN/stub.toml"
done
pub() { ssh -n -o BatchMode=yes "$1" "$BIN/karstd pubkey --config $RUN/stub.toml"; }
A_PUB=$(pub "$HOST_A"); B_PUB=$(pub "$HOST_B")
field() { printf '%s\n' "$2" | sed -n "s/$1 = \"\(.*\)\"/\1/p"; }
A_KEM=$(field kem_public_key "$A_PUB")
B_KEM=$(field kem_public_key "$B_PUB")
PSK=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')

write_config() {
    local host=$1 me=$2 peer_name=$3 peer_kem=$4 peer_addr=$5 peer_ip=$6
    ssh -n -o BatchMode=yes "$host" "cat > $RUN/karstd.toml <<CFG
[node]
listen = \"0.0.0.0:$PORT\"
interface = \"$IFACE\"
addresses = [\"$SUBNET.$me/24\"]
private_key_file = \"node.key\"
psk_epoch = 1

[[peer]]
name = \"$peer_name\"
kem_public_key = \"$peer_kem\"
psk = \"$PSK\"
endpoint = \"$peer_addr:$PORT\"
allowed_ips = [\"$SUBNET.$peer_ip/32\"]
CFG
chmod 600 $RUN/karstd.toml && $BIN/karstd check --config $RUN/karstd.toml"
}
write_config "$HOST_A" 1 "$HOST_B" "$B_KEM" "$ADDR_B" 2
write_config "$HOST_B" 2 "$HOST_A" "$A_KEM" "$ADDR_A" 1

say "karst: starting daemons"
START=$(date +%s.%N)
sh_b "cd $RUN && sudo -n setsid --fork $BIN/karstd --config $RUN/karstd.toml \
    --socket $RUN/karstd.sock < /dev/null > $RUN/karstd.log 2>&1"
sh_a "cd $RUN && sudo -n setsid --fork $BIN/karstd --config $RUN/karstd.toml \
    --socket $RUN/karstd.sock < /dev/null > $RUN/karstd.log 2>&1"

say "karst: waiting for direct path"
for _ in $(seq 1 30); do
    sh_a "ping -c1 -W1 $SUBNET.2 >/dev/null 2>&1" && break
    sleep 1
done
END=$(date +%s.%N)
SETUP_S=$(python3 -c "print(round($END-$START,2))")
sh_a "ping -c1 -W1 $SUBNET.2 >/dev/null 2>&1" || die "karst tunnel never came up — see $RUN/karstd.log on both hosts"

read -r IDLE_CPU IDLE_RSS <<< "$(idle_sample "$HOST_A" "$CFG_MATCH")"
collect_metrics karst lan-direct "$SUBNET.1" "$SUBNET.2" "$SETUP_S" "$IDLE_CPU" "$IDLE_RSS"
