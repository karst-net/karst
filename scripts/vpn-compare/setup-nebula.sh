#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright the Karst contributors.
#
# Bring Nebula up between two hosts (turing as lighthouse), measure it,
# tear it down — the "nebula" row of scripts/vpn-compare/run-all.sh
# (issue #201). Self-hosted, no account: a local CA signs both hosts' certs
# out of band, the same way scripts/two-host-test.sh shares karst's PSK out
# of band for a two-node test.
#
# Nebula binary: v1.11.2 (github.com/slackhq/nebula), fetched to
# ~/vpn-compare-run/nebula-bin/nebula on both hosts ahead of this script —
# see docs/measurements/vpn-comparison-2026-09-30.md for the exact install
# command.
#
# Usage:
#     scripts/vpn-compare/setup-nebula.sh HOST_A HOST_B [--keep]
#
# HOST_B acts as the lighthouse (must be reachable inbound on $PORT/udp from
# HOST_A — true for turing/lovelace on the lab LAN).

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./lib.sh

[ $# -ge 2 ] || die "usage: setup-nebula.sh HOST_A HOST_B [--keep]"
HOST_A=$1; HOST_B=$2; shift 2
KEEP=0
[ "${1:-}" = --keep ] && KEEP=1

PORT=$((VC_PORT_BASE + 30))
SUBNET=10.203.0
IFACE=vc-neb0
RUN="$RUN_DIR/nebula"
NEB='~/vpn-compare-run/nebula-bin/nebula'
NEBCERT='~/vpn-compare-run/nebula-bin/nebula-cert'
# See setup-karst.sh's CFG_MATCH comment: no leading `~/`, pkill_safe quotes
# suppress tilde expansion so the literal tilde form never matches the
# running process's expanded /proc cmdline.
CFG_MATCH="vpn-compare-run/nebula/config.yml"

cleanup() {
    [ "$KEEP" -eq 1 ] && { say "nebula: left running (--keep)"; return; }
    pkill_safe "$HOST_A" "$CFG_MATCH" sudo
    pkill_safe "$HOST_B" "$CFG_MATCH" sudo
    sh_a "sudo -n ip link del $IFACE 2>/dev/null; true" || true
    sh_b "sudo -n ip link del $IFACE 2>/dev/null; true" || true
}
trap cleanup EXIT

say "nebula: addresses"
ADDR_A=$(sh_a "hostname -I" | cut -d' ' -f1)
ADDR_B=$(sh_b "hostname -I" | cut -d' ' -f1)

# Nebula reads pki.{ca,cert,key} itself (it's not a shell — no tilde
# expansion), so config.yml needs real absolute paths, not the literal
# "~/..." text $RUN_DIR carries for ssh command strings. Resolve each
# host's actual $HOME and use that instead, just for this script.
HOME_A=$(sh_a 'echo $HOME'); HOME_B=$(sh_b 'echo $HOME')
RUN_A="$HOME_A/vpn-compare-run/nebula"
RUN_B="$HOME_B/vpn-compare-run/nebula"

say "nebula: CA + certs (signed locally on HOST_B, copied to HOST_A)"
sh_b "mkdir -p $RUN && chmod 700 $RUN && cd $RUN && \
    $NEBCERT ca -name vpncompare-ca -out-crt ca.crt -out-key ca.key && \
    $NEBCERT sign -name hostb -ip $SUBNET.2/24 -ca-crt ca.crt -ca-key ca.key \
        -out-crt hostb.crt -out-key hostb.key && \
    $NEBCERT sign -name hosta -ip $SUBNET.1/24 -ca-crt ca.crt -ca-key ca.key \
        -out-crt hosta.crt -out-key hosta.key"

# Ship HOST_A's cert/key and the shared CA cert over via this machine — no
# direct scp between the two lab hosts is assumed to be set up.
TMP=$(mktemp -d)
sh_b "cat $RUN/ca.crt"        > "$TMP/ca.crt"
sh_b "cat $RUN/hosta.crt"     > "$TMP/hosta.crt"
sh_b "cat $RUN/hosta.key"     > "$TMP/hosta.key"
ssh -n -o BatchMode=yes "$HOST_A" "mkdir -p $RUN && chmod 700 $RUN"
ssh -o BatchMode=yes "$HOST_A" "cat > $RUN/ca.crt"    < "$TMP/ca.crt"
ssh -o BatchMode=yes "$HOST_A" "cat > $RUN/hosta.crt" < "$TMP/hosta.crt"
ssh -o BatchMode=yes "$HOST_A" "cat > $RUN/hosta.key" < "$TMP/hosta.key"
ssh -n -o BatchMode=yes "$HOST_A" "chmod 600 $RUN/hosta.key"
rm -rf "$TMP"

write_config() {
    local host=$1 run_abs=$2 cert=$3 key=$4 am_lighthouse=$5 lighthouse_block=$6
    ssh -n -o BatchMode=yes "$host" "cat > $RUN/config.yml <<CFG
pki:
  ca: $run_abs/ca.crt
  cert: $run_abs/$cert
  key: $run_abs/$key
static_host_map:
  \"$SUBNET.2\": [\"$ADDR_B:$PORT\"]
lighthouse:
  am_lighthouse: $am_lighthouse
$lighthouse_block
listen:
  host: 0.0.0.0
  port: $PORT
tun:
  dev: $IFACE
firewall:
  outbound:
    - port: any
      proto: any
      host: any
  inbound:
    - port: any
      proto: any
      host: any
CFG"
}
write_config "$HOST_B" "$RUN_B" hostb.crt hostb.key true "  hosts: []"
write_config "$HOST_A" "$RUN_A" hosta.crt hosta.key false "  hosts: [\"$SUBNET.2\"]"

say "nebula: starting (lighthouse first)"
START=$(date +%s.%N)
sh_b "cd $RUN && sudo -n setsid --fork $NEB -config $RUN/config.yml \
    < /dev/null > $RUN/nebula.log 2>&1"
sleep 1
sh_a "cd $RUN && sudo -n setsid --fork $NEB -config $RUN/config.yml \
    < /dev/null > $RUN/nebula.log 2>&1"

say "nebula: waiting for tunnel"
for _ in $(seq 1 20); do
    sh_a "ping -c1 -W1 $SUBNET.2 >/dev/null 2>&1" && break
    sleep 1
done
END=$(date +%s.%N)
SETUP_S=$(python3 -c "print(round($END-$START,2))")
sh_a "ping -c1 -W1 $SUBNET.2 >/dev/null 2>&1" || die "nebula tunnel never came up — see $RUN/nebula.log on both hosts"

read -r IDLE_CPU IDLE_RSS <<< "$(idle_sample "$HOST_A" "$CFG_MATCH")"
collect_metrics nebula lan-direct "$SUBNET.1" "$SUBNET.2" "$SETUP_S" "$IDLE_CPU" "$IDLE_RSS"
