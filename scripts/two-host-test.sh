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
# Either host may be a Mac. That is the point of the branching below, and it is
# plans/phase-5/06-macos-client.md §8's "cross-platform" row: a Mac and a Linux
# host, a real NIC, a real NAT, and the exit criterion's "reaches a peer
# directly across a NAT" measured rather than asserted. Nothing else in the tree
# puts a macOS node on a real network — the `macos_pair` suite is two daemons on
# one machine over loopback, by construction.
#
# Usage:
#     scripts/two-host-test.sh HOST_A HOST_B [OPTIONS]
#
#     HOST_A, HOST_B    ssh destinations, Linux or macOS. Both need passwordless
#                       sudo, a Rust toolchain, and a checkout at ~/karst.
#
# Options:
#     --addr-a IP       underlay address of A, as B should dial it
#     --addr-b IP       underlay address of B, as A should dial it
#                       (default: resolved from each host's hostname)
#     --port PORT       UDP port                       (default: 51820)
#     --subnet PREFIX   tunnel /24, first three octets (default: 10.88.0)
#     --iface NAME      interface name                 (default: karst0)
#                       A preference, not a promise: macOS names utun devices
#                       itself and karstd reports the name it actually got.
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

# ── what each host is ───────────────────────────────────────────────────────
#
# Asked once, because every difference below is a command that exists on both
# systems and means something different there. Those are worse than a command
# that is simply missing: `ping -W 2` waits two seconds on Linux and two
# *milliseconds* on macOS, so a harness that does not branch here does not fail
# with "unknown option" — it reports every packet lost and sends somebody
# looking for a datapath bug that is not there.
OS_A=$(sh_a 'uname -s')
OS_B=$(sh_b 'uname -s')
say "Hosts: $HOST_A is $OS_A, $HOST_B is $OS_B"

# ping's reply timeout: seconds on Linux, milliseconds on macOS.
ping_wait() { case $1 in Darwin) echo "-W 2000" ;; *) echo "-W 2" ;; esac; }
# ping's "set DF and do not fragment": `-M do` on Linux, `-D` on macOS.
ping_df()   { case $1 in Darwin) echo "-D" ;; *) echo "-M do" ;; esac; }
PING_A=$(ping_wait "$OS_A"); PING_B=$(ping_wait "$OS_B")

# The host's own underlay address, when no `--addr-*` was given. `hostname -I`
# is glibc's and macOS has no counterpart, so there the default route names the
# interface and `ipconfig` reads the address off it. Both parsed here rather
# than in the remote shell, which keeps the quoting legible.
host_address() {
    local host=$1 os=$2 iface
    if [ "$os" = Darwin ]; then
        iface=$(ssh -n -o BatchMode=yes "$host" "route -n get default 2>/dev/null" \
                | sed -n 's/.*interface: *//p' | head -1)
        [ -n "$iface" ] || die "$host has no default route; pass its address with --addr-*"
        ssh -n -o BatchMode=yes "$host" "ipconfig getifaddr $iface"
    else
        ssh -n -o BatchMode=yes "$host" "hostname -I" | cut -d' ' -f1
    fi
}

# ── build ───────────────────────────────────────────────────────────────────
say "Building on both hosts"
for h in "$HOST_A" "$HOST_B"; do
    ssh -n -o BatchMode=yes "$h" \
        'cd ~/karst && PATH=$HOME/.cargo/bin:$PATH cargo build --release --workspace 2>&1 | tail -1'
done

# ── addresses ───────────────────────────────────────────────────────────────
# Default to each host's own idea of its primary address — see `host_address`.
# Override for a dedicated link: a bonded or 10G interface is usually neither
# what DNS returns nor where the default route points.
[ "$ADDR_A_SET" -eq 1 ] || ADDR_A=$(host_address "$HOST_A" "$OS_A")
[ "$ADDR_B_SET" -eq 1 ] || ADDR_B=$(host_address "$HOST_B" "$OS_B")
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

# The daemon has to be detached before ssh will hang up, and the two systems
# spell that differently.
#
# Linux: `setsid --fork`, not `setsid ... &` — with `&` the ssh session never
# closes and this loop hangs forever. See scripts/soak.sh for the measurement.
#
# macOS: there is no setsid(1) at all. `sudo -b` is the equivalent that matters
# here — sudo forks and the parent returns without waiting — and the inner
# `sh -c` does the redirection, which `sudo -b` does not do for you.
#
# **Paths are relative in the macOS branch, deliberately.** `$RUN` and `$BIN`
# both start with `~`, and a tilde does not expand inside the quotes that
# `sh -c` needs; it would travel to root's shell as a literal. `cd $RUN`
# already ran in the outer, unquoted position, so the config and the socket are
# named relative to it, and the binary is reached through `$HOME` expanded by
# the *user's* shell before sudo — root's `$HOME` is /var/root and would not
# find the checkout.
start_daemon() {
    local host=$1 os=$2
    if [ "$os" = Darwin ]; then
        ssh -n -o BatchMode=yes "$host" "cd $RUN && bin=\$HOME/karst/target/release && \
            sudo -n -b /bin/sh -c \"exec \$bin/karstd \
                --config karstd.toml --socket karstd.sock \
                < /dev/null > karstd.log 2>&1\""
    else
        ssh -n -o BatchMode=yes "$host" "cd $RUN && sudo -n setsid --fork $BIN/karstd \
            --config $RUN/karstd.toml --socket $RUN/karstd.sock \
            < /dev/null > $RUN/karstd.log 2>&1"
    fi
    sleep 2
    ssh -n -o BatchMode=yes "$host" "head -2 $RUN/karstd.log 2>/dev/null || true"
}
start_daemon "$HOST_B" "$OS_B"
start_daemon "$HOST_A" "$OS_A"

# ── verify ──────────────────────────────────────────────────────────────────
say "Connectivity"
sh_a "ping -c4 $PING_A $SUBNET.2" | tail -2
say "Reverse direction"
sh_b "ping -c4 $PING_B $SUBNET.1" | tail -2

# 1280 bytes of IP packet with DF set. This is the case spec §13.6 exists for:
# it must cross without IP fragmentation anywhere on the path.
say "Full-MTU, DF set (spec §13.6)"
sh_a "ping -c3 $PING_A -s 1252 $(ping_df "$OS_A") $SUBNET.2" | tail -2

# On macOS the interface name in the roster is a preference the kernel declines,
# so this is also where the name karstd actually got is read back rather than
# assumed. Nothing below depends on it; it is here for the operator.
say "Status"
sh_a "sudo -n $BIN/karst status --socket $RUN/karstd.sock"

[ "$BENCH" -eq 1 ] || exit 0

# ── measure ─────────────────────────────────────────────────────────────────
#
# Both hosts, not this one. The check used to consult the local machine first,
# which passed on any workstation with iperf3 installed and then failed inside
# the run — and neither remote host is necessarily this machine. macOS has no
# iperf3 in the base system, so a Mac is the host that usually lacks it.
for h in "$HOST_A" "$HOST_B"; do
    ssh -n -o BatchMode=yes "$h" "command -v iperf3" >/dev/null 2>&1 || {
        say "iperf3 is not installed on $h; skipping the benchmark"
        exit 0
    }
done

# No `setsid` on either line: `iperf3 -D` already forks and detaches itself,
# which is the whole reason the daemon above needs the treatment and this does
# not. It is also the only spelling that works on macOS.
say "Baseline: underlay, no tunnel"
sh_b "iperf3 -s -B $ADDR_B -p 5202 -D >/dev/null 2>&1; sleep 1"
sh_a "iperf3 -c $ADDR_B -p 5202 -t $DURATION -f m" | grep -E 'sender|receiver' || true

say "Through the Karst tunnel"
sh_b "iperf3 -s -B $SUBNET.2 -D >/dev/null 2>&1 || true; sleep 1"
sh_a "iperf3 -c $SUBNET.2 -t $DURATION -f m" | grep -E 'sender|receiver' || true

# Parallel streams separate two very different explanations for a low number.
# If throughput does not rise with more flows, the bottleneck is serialization
# inside the daemon rather than per-packet cost.
say "Through the tunnel, 4 parallel streams"
sh_a "iperf3 -c $SUBNET.2 -t $DURATION -P 4 -f m" | grep -E 'SUM.*(sender|receiver)' || true

# `top` agrees on neither the batch flag nor the per-PID flag: Linux wants
# `-b -n1 -H -p PID`, macOS wants `-l 1 -pid PID`, and macOS has no per-thread
# mode at all — so the Mac row is the process total where the Linux row breaks
# out threads. Worth having anyway: what this measures is whether the daemon is
# CPU-bound during the transfer, and that reads the same either way.
say "Daemon CPU during transfer"
case $OS_A in
    Darwin) cpu='top -l 1 -pid $(pgrep -x karstd) -stats pid,command,cpu 2>/dev/null | tail -3' ;;
    *)      cpu='top -b -n1 -H -p $(pgrep -x karstd) 2>/dev/null | tail -5' ;;
esac
sh_a "iperf3 -c $SUBNET.2 -t 8 -f m >/dev/null 2>&1 &
      sleep 3; $cpu; wait" || true
