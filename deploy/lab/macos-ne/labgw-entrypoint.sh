#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright the Karst contributors.
#
# labgw: the lab Mac's default gateway. Forwards the Mac's traffic to the
# core network (control, relay) and to the LAN's own router, masquerading on
# the way out of each so replies come back through here.
set -eu
lan_if=$(ip -o -4 addr show | awk -v a="$KARST_LAB_GW_LAN_IP" 'index($4, a"/") == 1 { print $2; exit }')
core_if=$(ip -o -4 addr show | awk -v a="$KARST_LAB_GW_LAN_IP" '$2 != "lo" && index($4, a"/") != 1 { print $2; exit }')
if [ -z "$lan_if" ] || [ -z "$core_if" ]; then
    echo "labgw: cannot find LAN/core interfaces" >&2
    exit 1
fi
for out in "$lan_if" "$core_if"; do
    iptables -t nat -C POSTROUTING -o "$out" -j MASQUERADE 2>/dev/null \
        || iptables -t nat -A POSTROUTING -o "$out" -j MASQUERADE
done
echo "labgw: routing via $lan_if (LAN) and $core_if (core)"
exec sleep infinity
