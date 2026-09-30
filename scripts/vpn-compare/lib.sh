# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright the Karst contributors.
#
# Shared helpers for scripts/vpn-compare/*.sh — issue #201's mesh-VPN
# comparison harness. Sourced, not executed.
#
# Each setup-<tool>.sh in this directory is self-contained, the same way
# scripts/two-host-test.sh is: it brings its tool's tunnel up between
# HOST_A and HOST_B, runs the shared `collect_metrics` battery (defined
# below) against it, and tears down on exit via `trap cleanup EXIT` — no
# state is handed between separate script invocations over SSH.
#
# turing/lovelace already run a live karstd+karst-relay+karst-control
# deployment and an already-authenticated tailscaled on the default
# port/interface (karst0:51820, tailscale0:41641). Every tool this harness
# brings up uses a disjoint port range ($VC_PORT_BASE+) and disjoint
# interface names (vc-*), and teardown targets those specific
# interfaces/PIDs it created — never `pkill -x <binary>`, which would also
# kill the production daemon of the same name.
#
# collect_metrics writes one row per (tool, topology) to $RESULTS_TSV, a
# single TSV shared across all setup-*.sh runs in one run-all.sh invocation
# so every tool's numbers land in one comparable table.

die() { echo "vpn-compare: $*" >&2; exit 1; }
say() { printf '\n\033[1m%s\033[0m\n' "$*" >&2; }

# ssh -n throughout: without it a backgrounded remote command inherits the
# session's stdin and the connection never closes (same reason
# two-host-test.sh uses it).
sh_a() { ssh -n -o BatchMode=yes "$HOST_A" "$@"; }
sh_b() { ssh -n -o BatchMode=yes "$HOST_B" "$@"; }

# Single-quoted in callers so `~` expands on the remote side, not here.
RUN_DIR='~/vpn-compare-run'
KARST_BIN='~/karst-vpncompare/target/release'

VC_PORT_BASE=61800
IPERF_PORT=61900

RESULTS_TSV=${RESULTS_TSV:-/tmp/vpn-compare-results.tsv}

# bracket_pattern PATTERN — the classic `ps | grep '[f]oo'` trick, applied to
# `pkill -f`/`pgrep -f`. The remote command line ssh sends over is one string
# containing the pattern *and* the pkill/pgrep invocation itself, so an
# unbracketed `pkill -f "$pattern"` always finds itself (and the `bash -c`/
# `sudo` wrapper around it) in the process table and kills or lists its own
# ancestry — on a plain `pkill -f iperf3...` this silently killed the SSH
# session's own shell (exit-signal, not exit-status) and aborted the script
# with no useful message. Bracketing the pattern's first character makes it
# a one-character regex class in the search, which still matches the real
# target's cmdline, but no longer matches the *literal* bracketed text sitting
# in pkill's own argv.
bracket_pattern() { printf '[%s]%s' "${1:0:1}" "${1:1}"; }

# pkill_safe HOST PATTERN [sudo] — see bracket_pattern. Never raw `pkill -f`
# in this harness, and never `pkill -x <name>` — these hosts run production
# karstd/karst-relay/tailscaled under the same binary names.
pkill_safe() {
    local host=$1 pattern=$2 use_sudo=${3:-} h sudo_prefix=""
    [ "$host" = "$HOST_A" ] && h=sh_a || h=sh_b
    [ "$use_sudo" = sudo ] && sudo_prefix="sudo -n "
    $h "${sudo_prefix}pkill -f '$(bracket_pattern "$pattern")' 2>/dev/null; true" || true
}

results_header() {
    [ -s "$RESULTS_TSV" ] && return 0
    printf 'tool\ttopology\tsetup_s\ttcp_mbps\tudp_mbps\tudp_jitter_ms\tudp_loss_pct\tping_avg_ms\tping_p99_ms\tidle_cpu_pct\tidle_rss_kb\n' \
        > "$RESULTS_TSV"
}

# collect_metrics TOOL TOPOLOGY TUNNEL_IP_A TUNNEL_IP_B [SETUP_SECONDS]
#
# Runs on the *tunnel* addresses only — HOST_A dials HOST_B's tunnel IP over
# whichever interface the caller just brought up. iperf3 server on B,
# client on A; a single TCP and a single UDP (100M target) stream, then a
# ping RTT sample. Idle CPU/RSS is read by the caller before this (over a
# short settle window) and passed in as $6/$7, since "idle" means before
# any load, not after.
collect_metrics() {
    local tool=$1 topo=$2 ip_a=$3 ip_b=$4 setup_s=${5:-0} \
          idle_cpu=${6:-} idle_rss=${7:-}
    results_header
    say "Measuring: $tool / $topo ($ip_a -> $ip_b)"

    pkill_safe "$HOST_B" "iperf3 -s -p $IPERF_PORT"
    sh_b "nohup iperf3 -s -1 -p $IPERF_PORT >/tmp/vc-iperf-tcp.log 2>&1 &disown" || true
    sleep 1
    local tcp_json tcp_mbps
    tcp_json=$(sh_a "iperf3 -c $ip_b -p $IPERF_PORT -t 8 -J" 2>/dev/null) || true
    tcp_mbps=$(echo "$tcp_json" | python3 -c \
        "import json,sys
try: print(round(json.load(sys.stdin)['end']['sum_received']['bits_per_second']/1e6,1))
except Exception: print('NA')" 2>/dev/null || echo NA)

    sh_b "nohup iperf3 -s -1 -p $IPERF_PORT >/tmp/vc-iperf-udp.log 2>&1 &disown" || true
    sleep 1
    local udp_json udp_mbps udp_jitter udp_loss
    udp_json=$(sh_a "iperf3 -c $ip_b -p $IPERF_PORT -u -b 500M -t 8 -J" 2>/dev/null) || true
    read -r udp_mbps udp_jitter udp_loss <<< "$(echo "$udp_json" | python3 -c \
        "import json,sys
try:
    d=json.load(sys.stdin)['end']['sum']
    print(round(d['bits_per_second']/1e6,1), round(d['jitter_ms'],3), round(d['lost_percent'],2))
except Exception:
    print('NA NA NA')" 2>/dev/null || echo 'NA NA NA')"

    local ping_out ping_avg ping_p99
    ping_out=$(sh_a "ping -c 50 -i 0.05 $ip_b" 2>/dev/null) || true
    ping_avg=$(echo "$ping_out" | awk -F'/' '/rtt|round-trip/{print $5}')
    ping_p99=$(echo "$ping_out" | grep -oP '(?<=time=)[0-9.]+' | sort -n | \
        awk '{a[NR]=$1} END{if(NR>0) print a[int(NR*0.99)==0?1:int(NR*0.99)]; else print "NA"}')

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$tool" "$topo" "$setup_s" "${tcp_mbps:-NA}" "${udp_mbps:-NA}" \
        "${udp_jitter:-NA}" "${udp_loss:-NA}" "${ping_avg:-NA}" "${ping_p99:-NA}" \
        "${idle_cpu:-NA}" "${idle_rss:-NA}" \
        | tee -a "$RESULTS_TSV" >&2
}

# idle_sample HOST PID_CMD — sample %CPU and RSS(kB) of a process matched by
# `pgrep -f PID_CMD` on HOST, after a short settle window with no load. Uses
# the same bracket trick as pkill_safe: unbracketed, `pgrep -f` would put its
# own PID first in the match list (its own argv contains the pattern too),
# and `| head -1` would then sample pgrep's own already-exited PID instead of
# the real target.
idle_sample() {
    local host=$1 pat=$2 h bracketed
    [ "$host" = "$HOST_A" ] && h=sh_a || h=sh_b
    bracketed=$(bracket_pattern "$pat")
    sleep 5
    $h "ps -o %cpu=,rss= -p \$(pgrep -f '$bracketed' | head -1) 2>/dev/null" | \
        awk '{printf "%s %s", $1, $2}'
}
