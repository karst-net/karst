#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright the Karst contributors.
#
# Bring up a self-hosted Headscale control plane (HOST_B) plus two
# isolated `tailscale`/`tailscaled` client instances pointed at it,
# measure the resulting tunnel, tear it down — the "headscale" row of
# scripts/vpn-compare/run-all.sh (issue #201).
#
# "Isolated" matters: both hosts already run a *production* tailscaled,
# logged into the user's real personal tailnet (default
# --state/--socket/--port, see lib.sh's header). This script never touches
# that instance — it starts a second tailscaled per host with its own
# --state/--socket/--port/--tun, driven entirely through
# `tailscale --socket=<harness socket> ...` so the production login is
# never at risk of being reconfigured or logged out.
#
# Headscale binary: v0.29.4 (github.com/juanfont/headscale), fetched to
# ~/vpn-compare-run/headscale-bin/headscale on HOST_B ahead of this
# script. tailscale/tailscaled are the distro-installed production
# binaries — only invoked against harness-owned --socket/--state, never
# against the default ones.
#
# Usage:
#     scripts/vpn-compare/setup-headscale.sh HOST_A HOST_B [--keep]
#
# HOST_B runs the headscale server; HOST_A and HOST_B both run an isolated
# tailscale client against it.

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./lib.sh

[ $# -ge 2 ] || die "usage: setup-headscale.sh HOST_A HOST_B [--keep]"
HOST_A=$1; HOST_B=$2; shift 2
KEEP=0
[ "${1:-}" = --keep ] && KEEP=1

HS_PORT=$((VC_PORT_BASE + 40))
HS_METRICS_PORT=$((VC_PORT_BASE + 41))
HS_GRPC_PORT=$((VC_PORT_BASE + 42))
TS_PORT=$((VC_PORT_BASE + 43))
HS_STUN_PORT=$((VC_PORT_BASE + 44))
IFACE=vc-ts0
RUN="$RUN_DIR/headscale"
HS='~/vpn-compare-run/headscale-bin/headscale'
# See setup-karst.sh's CFG_MATCH comment for why these omit the leading `~/`.
HS_CFG_MATCH="vpn-compare-run/headscale/config.yaml"
TS_STATE_MATCH="vpn-compare-run/headscale/tailscaled.state"

ts() { # ts HOST ARGS... — drive the isolated client, never the default socket
    local host=$1; shift
    local h; [ "$host" = "$HOST_A" ] && h=sh_a || h=sh_b
    $h "sudo -n tailscale --socket=$RUN/tailscaled.sock $*"
}

cleanup() {
    [ "$KEEP" -eq 1 ] && { say "headscale: left running (--keep)"; return; }
    ts "$HOST_A" "down" >/dev/null 2>&1 || true
    ts "$HOST_B" "down" >/dev/null 2>&1 || true
    pkill_safe "$HOST_A" "$TS_STATE_MATCH" sudo
    pkill_safe "$HOST_B" "$TS_STATE_MATCH" sudo
    pkill_safe "$HOST_B" "$HS_CFG_MATCH" sudo
    sh_a "sudo -n ip link del $IFACE 2>/dev/null; true" || true
    sh_b "sudo -n ip link del $IFACE 2>/dev/null; true" || true
}
trap cleanup EXIT

say "headscale: addresses"
ADDR_A=$(sh_a "hostname -I" | cut -d' ' -f1)
ADDR_B=$(sh_b "hostname -I" | cut -d' ' -f1)
HOME_B=$(sh_b 'echo $HOME')
RUN_B_ABS="$HOME_B/vpn-compare-run/headscale"

say "headscale: server config on $HOST_B"
sh_b "mkdir -p $RUN && chmod 700 $RUN && cat > $RUN/config.yaml <<CFG
server_url: http://$ADDR_B:$HS_PORT
listen_addr: 0.0.0.0:$HS_PORT
metrics_listen_addr: 127.0.0.1:$HS_METRICS_PORT
grpc_listen_addr: 127.0.0.1:$HS_GRPC_PORT
grpc_allow_insecure: true
unix_socket: $RUN_B_ABS/headscale.sock
unix_socket_permission: "0770"
dns:
  override_local_dns: false
  magic_dns: false
  base_domain: vpncompare.internal
  nameservers:
    global: []
noise:
  private_key_path: $RUN_B_ABS/noise_private.key
prefixes:
  v4: 100.90.90.0/24
  v6: fd7a:115c:a1e0:90::/64
  allocation: sequential
derp:
  server:
    enabled: true
    region_id: 999
    region_code: "vpncompare"
    region_name: "vpncompare embedded DERP"
    stun_listen_addr: "0.0.0.0:$HS_STUN_PORT"
    private_key_path: $RUN_B_ABS/derp_server_private.key
    automatically_add_embedded_derp_region: true
  urls: []
  paths: []
  auto_update_enabled: false
disable_check_updates: true
database:
  type: sqlite
  sqlite:
    path: $RUN_B_ABS/db.sqlite
log:
  level: info
CFG"

say "headscale: starting server"
sh_b "cd $RUN && sudo -n setsid --fork $HS serve --config $RUN/config.yaml \
    < /dev/null > $RUN/headscale.log 2>&1"
sleep 2
sh_b "tail -5 $RUN/headscale.log" || true

say "headscale: creating user + preauth key"
sh_b "sudo -n $HS --config $RUN/config.yaml users create vpncompare 2>&1" || true
# 0.29's --user flag takes a numeric user ID, not a name — look it up.
USER_ID=$(sh_b "sudo -n $HS --config $RUN/config.yaml users list --output json 2>/dev/null" \
    | python3 -c "import json,sys; print(json.load(sys.stdin)[0]['id'])")
[ -n "$USER_ID" ] || die "headscale: could not resolve vpncompare user id — see $RUN/headscale.log on $HOST_B"
PREAUTH=$(sh_b "sudo -n $HS --config $RUN/config.yaml preauthkeys create --user $USER_ID --reusable --expiration 1h 2>&1" | tail -1)
[ -n "$PREAUTH" ] || die "headscale: could not create preauth key — see $RUN/headscale.log on $HOST_B"

say "headscale: isolated tailscaled + client on both hosts"
START=$(date +%s.%N)
bring_up_client() {
    local host=$1 hostname=$2 h
    [ "$host" = "$HOST_A" ] && h=sh_a || h=sh_b
    $h "mkdir -p $RUN && chmod 700 $RUN"
    $h "sudo -n setsid --fork tailscaled --state=$RUN/tailscaled.state \
        --socket=$RUN/tailscaled.sock --port=$TS_PORT --tun=$IFACE \
        < /dev/null > $RUN/tailscaled.log 2>&1"
    sleep 2
    ts "$host" "up --login-server=http://$ADDR_B:$HS_PORT --authkey=$PREAUTH \
        --hostname=$hostname --accept-routes=false --timeout=30s"
}
bring_up_client "$HOST_B" vc-hostb
bring_up_client "$HOST_A" vc-hosta

say "headscale: resolving overlay addresses"
TS_IP_A=$(ts "$HOST_A" "ip -4" | head -1)
TS_IP_B=$(ts "$HOST_B" "ip -4" | head -1)
[ -n "$TS_IP_A" ] && [ -n "$TS_IP_B" ] || \
    die "headscale: client(s) never got an address — see $RUN/tailscaled.log on both hosts"

say "headscale: waiting for direct path"
for _ in $(seq 1 20); do
    sh_a "ping -c1 -W1 $TS_IP_B >/dev/null 2>&1" && break
    sleep 1
done
END=$(date +%s.%N)
SETUP_S=$(python3 -c "print(round($END-$START,2))")
sh_a "ping -c1 -W1 $TS_IP_B >/dev/null 2>&1" || \
    die "headscale: tunnel never came up between $TS_IP_A and $TS_IP_B"

read -r IDLE_CPU IDLE_RSS <<< "$(idle_sample "$HOST_A" "$TS_STATE_MATCH")"
collect_metrics headscale lan-direct "$TS_IP_A" "$TS_IP_B" "$SETUP_S" "$IDLE_CPU" "$IDLE_RSS"
