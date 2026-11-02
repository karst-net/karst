#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright the Karst contributors.
#
# Lab peer startup: routes, fixture addresses, firewall, fixtures, karstd.
set -eu

lan_if=$(ip -o -4 addr show | awk -v a="$KARST_LAB_LAN_IF_ADDR" 'index($4, a"/") == 1 { print $2; exit }')
lab_if=$(ip -o -4 addr show | awk -v a="$KARST_LAB_LAN_IF_ADDR" '$2 != "lo" && index($4, a"/") != 1 { print $2; exit }')
if [ -z "$lan_if" ] || [ -z "$lab_if" ]; then
    echo "peer: cannot find LAN/lab interfaces" >&2
    exit 1
fi
# Docker gives every bridge network's gateway the network's .1 address.
lab_gw=$(ip -o -4 addr show dev "$lab_if" | awk '{ split($4, n, "/"); split(n[1], o, "."); print o[1]"."o[2]"."o[3]".1"; exit }')

# Control and relay are published on the host's LAN address, which a macvlan
# child cannot reach; send just that address over the bridge. The default
# route (compose's gw_priority) already goes out the LAN, towards the Mac.
ip route replace "$KARST_LAB_HOST_IP/32" via "$lab_gw" dev "$lab_if"

# The subnet-route and exit-route fixtures are local addresses on this peer,
# reachable from the Mac only when the corresponding route is active.
ip link add lab-fixtures type dummy 2>/dev/null || true
ip link set lab-fixtures up
ip addr replace "$KARST_LAB_SUBNET_ADDR/32" dev lab-fixtures
ip addr replace "$KARST_LAB_EXIT_ADDR/32" dev lab-fixtures

# sshd: a ping/ssh-reachable fixture, gated the same way as the HTTP/UDP
# ones below — only reachable through the overlay, never the LAN. The
# authorized key is `bootstrap.sh`'s lab-only keypair, mounted read-only at
# /etc/karst/ssh_authorized_keys; sshd's own StrictModes rejects an
# AuthorizedKeysFile it does not own, and the bind mount keeps the host's
# ownership (not root's), so this copies it into root's own .ssh instead of
# pointing AuthorizedKeysFile at the mount directly. Host keys are
# regenerated on every start, which is fine for a disposable lab (nothing
# here is meant to survive a container recreation, same as the rest of
# this file).
mkdir -p /run/sshd /root/.ssh
chmod 700 /root/.ssh
cp /etc/karst/ssh_authorized_keys /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
ssh-keygen -A >/dev/null 2>&1
cat > /etc/ssh/sshd_config.d/lab.conf <<'EOF'
PermitRootLogin prohibit-password
PasswordAuthentication no
EOF
/usr/sbin/sshd

# Fixtures answer only traffic that arrived through the overlay.
iptables -N LAB-FIXTURES 2>/dev/null || iptables -F LAB-FIXTURES
iptables -A LAB-FIXTURES -i karst0 -j ACCEPT
iptables -A LAB-FIXTURES -i lo -j ACCEPT
iptables -A LAB-FIXTURES -j DROP
for rule in "-p tcp --dport 8080" "-p udp --dport 7777" "-p tcp --dport 22"; do
    # shellcheck disable=SC2086
    iptables -C INPUT $rule -j LAB-FIXTURES 2>/dev/null || iptables -A INPUT $rule -j LAB-FIXTURES
done

# The relay scenario's switch (labctl.py toggles it): drop all UDP on the LAN
# attachment so no direct candidate works, while the relay stays reachable
# over the bridge.
iptables -N LAB-DIRECT 2>/dev/null || true
iptables -C INPUT -i "$lan_if" -p udp -j LAB-DIRECT 2>/dev/null || iptables -A INPUT -i "$lan_if" -p udp -j LAB-DIRECT
iptables -C OUTPUT -o "$lan_if" -p udp -j LAB-DIRECT 2>/dev/null || iptables -A OUTPUT -o "$lan_if" -p udp -j LAB-DIRECT

python3 /usr/local/libexec/peer-fixtures.py &

exec /usr/local/bin/karstd --config /etc/karst/karstd.toml
