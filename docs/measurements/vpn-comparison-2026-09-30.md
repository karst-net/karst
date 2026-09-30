<!--
SPDX-License-Identifier: CC-BY-4.0
Copyright the Karst contributors.
-->

# karst vs. self-hosted mesh VPN alternatives — issue #201

**2026-09-30.** Harness: [`../../scripts/vpn-compare/`](../../scripts/vpn-compare/)
(`run-all.sh`), run between `turing` and `lovelace`.

## The question

Issue #201 asks for reproducible performance data comparing karst against
alternative mesh/overlay VPNs, "to know where we stand and where to
prioritize optimization," and explicitly asks for the candidate list to be
narrowed to whatever is reachable in the time available.

Tailscale and ZeroTier's real products both require a live account on a
vendor cloud coordination service. Narrowing to what's reachable without
that dependency, this pass compares **karst** against three self-hosted
alternatives, all standable entirely on the lab LAN with no external
account and no internet egress:

- **WireGuard** — plain point-to-point, no control plane. The floor/
  reference the issue asks for.
- **Nebula** — self-hosted, certificate-based, lighthouse-coordinated
  overlay (Slack's mesh VPN).
- **Headscale** — a self-hosted, open-source reimplementation of
  Tailscale's control plane, driving the real `tailscale`/`tailscaled`
  client binaries against it instead of tailscale.com.

A fourth row, **real Tailscale**, is also included: `turing` already runs a
production `tailscaled` logged into the user's actual personal tailnet, and
`lovelace` completed its one-time interactive re-login after this pass's
first draft (`tailscale up` prints a login URL; OAuth has to be completed by
a human in a browser — that step was manual, not this harness's to do).
`scripts/vpn-compare/setup-tailscale.sh` confirmed both peers online with a
direct path (`tailscale ping` returned a LAN address, not a DERP relay)
before measuring.

## Method

Each tool gets its own `scripts/vpn-compare/setup-<tool>.sh`: bring a
tunnel up between the two hosts, run one shared instrument
(`collect_metrics` in [`lib.sh`](../../scripts/vpn-compare/lib.sh)) against
it, tear down. `run-all.sh` runs all of them in sequence into one TSV, so
every tool's numbers come from the same instrument on the same hardware in
the same sitting — the same principle
[`userspace-cost-2026-08-21.md`](userspace-cost-2026-08-21.md) uses for its
three scenarios.

**Instrument**, identical across every tool: `iperf3` single-stream TCP (8s)
and single-stream UDP at a 500 Mbps offered rate (8s), then 50 pings at
20 ms spacing for RTT mean/p99. Setup time is wall-clock from "start
bringing the tunnel up" to "first successful ping" — a cold-start number,
comparable to how
[`handshake-latency-bench.sh`](../../scripts/handshake-latency-bench.sh)
times karst's own handshake. Idle CPU/RSS is sampled once, 5 seconds after
setup completes and before any load — see each tool's row below for what
process that means for that tool.

```sh
scripts/vpn-compare/run-all.sh turing lovelace
```

**These are shared lab hosts running a live production karst deployment**
(`karstd`+`karst-relay`+`karst-control` under systemd, plus a
production `tailscaled` in the user's real tailnet) — not clean benchmark
boxes. Every tool this harness brings up uses a disjoint port range and
interface names from the production instances, and every teardown targets
its own PIDs/interfaces specifically — verified after every run in this
pass with `pgrep -af karstd`/`tailscaled` and `ip link show` on both hosts,
confirming the production processes and the default `karst0`/`tailscale0`
interfaces were undisturbed throughout. See `lib.sh`'s header for the two
real bugs (a `pkill -f` self-match that silently killed an SSH session, and
a tilde-expansion mismatch between an unquoted and a quoted remote command)
this constraint surfaced while the harness was being built.

### Host

| | |
|---|---|
| hosts | `turing`, `lovelace` — 48-core Xeon, Ubuntu 24.04.3 LTS |
| kernel | 6.8.0-142-generic (turing), 6.8.0-139-generic (lovelace) |
| link | `bond0`, 3×1G bonded, 10.10.10.1 ↔ 10.10.10.2 |
| karst | commit `a1504ff` (origin/main, includes #220) |
| WireGuard | `wireguard-tools` v1.0.20210914 (distro package) |
| Nebula | v1.11.2 |
| Headscale | v0.29.4, embedded DERP (LAN test — DERP never actually used) |
| tailscale/tailscaled | 1.102.4 (distro package; production instance for
  the Tailscale row, driven as an isolated second instance for the
  Headscale row) |

## Results

All rows: LAN-direct topology (real `turing` ↔ `lovelace` over `bond0`).
Raw data: [`vpn-comparison-2026-09-30.tsv`](vpn-comparison-2026-09-30.tsv).

| Tool | Setup (s) | TCP (Mbps) | UDP¹ (Mbps) | UDP jitter (ms) | UDP loss (%) | Ping avg/p99 (ms) | Idle CPU² / RSS² |
|---|---|---|---|---|---|---|---|
| WireGuard | 1.08 | 900.0 | 499.9 | 0.007 | 0.00 | 0.570 / 0.603 | N/A (kernel) |
| karst | 0.94 | 806.6 | 499.9 | 0.012 | 0.42 | 0.590 / 0.622 | 0.1% / 9.9 MB |
| Nebula | 1.96 | 817.2 | 499.9 | 0.010 | 0.01 | 0.651 / 0.730 | 0.4% / 24.9 MB |
| Headscale | 30.36 | 887.2 | 499.9 | 0.017 | 1.08 | 0.816 / 0.966 | 4.5% / 85.4 MB³ |
| Tailscale | N/A⁴ | 887.2 | 499.9 | 0.015 | 0.02 | 0.902 / 0.924 | 2.4% / 82.5 MB |

¹ Offered at 500 Mbps; every tool delivered essentially all of it (this is
not each tool's UDP ceiling — see below).
² Sampled once, 5s after setup, before any load — see the per-tool caveats
below for what's actually being measured.
³ Headscale's number is an isolated *second* `tailscaled` instance's idle
cost, not the control-plane server's own cost — see below.
⁴ Tailscale's is the user's real, already-established production tunnel —
there's no cold enroll here to time, and measuring "time to first ping"
against a link that's been up for days would understate every other tool's
setup number for the wrong reason (see the Setup time section).

**Read this as "all five land within a fairly narrow band on a quiet,
uncontended LAN," not as a ranking.** WireGuard is the floor and comes out
fastest and lightest, as expected for a kernel datapath with zero control
plane. karst and Nebula, both userspace daemons doing real cryptographic
work per packet, land close to each other. Headscale's and Tailscale's
TCP/ping numbers are both for the *tailscale client's* userspace
WireGuard-Go-style datapath — expected to be close to each other, and they
are (887.2 Mbps TCP for both). Neither Headscale's nor Tailscale's control
plane is in the data path once the tunnel is established, which is the
point of that architecture; this comparison says nothing about either
control plane's own cost.

### Setup time

Headscale's 30.36s is not comparable to the others' ~1-2s: it includes
standing up an entire second `tailscaled` instance from cold (its own
`--state`/`--socket`, then a fresh `tailscale up` against the harness's
Headscale server) on top of the actual handshake, where the other three
scripts are timing a warm daemon dialing a peer it already has
configuration for. A fairer number would time a `tailscaled` that was
already running and only had to re-associate — not measured here.

### Idle CPU/RSS caveats

- **WireGuard**: N/A by construction — it's an in-kernel interface, not a
  userspace daemon, and this harness has no comparable per-tool instrument
  for kernel datapath cost. Not zero; not measured.
- **karst**: `karstd` with exactly the one peer configured for this test —
  directly comparable to the `karst0` production baseline, and consistent
  with it (this run: 0.1% / 9.9 MB; see
  [`idle-peers-bench.sh`](../../scripts/idle-peers-bench.sh) for karst's own
  200-idle-peer number, which this pass deliberately did not try to
  reproduce for the other three tools — see Scope cuts).
- **Nebula**: same shape as karst — one process, one peer, directly
  comparable.
- **Headscale**: this is where the comparison gets least apples-to-apples.
  The sampled process is the *client-side* `tailscaled`, run twice
  (once per host) against a Headscale server that is a separate process
  entirely and isn't sampled at all. 4.5% CPU / 85 MB RSS for one peer is
  markedly higher than karst's or Nebula's one-peer numbers; some of that
  is tailscale's own client being a heavier process in general (it does
  much more than a minimal WireGuard peer — DERP client, MagicDNS
  scaffolding even when disabled, etc.), and some of it may be residual
  work from having just come up cold 5 seconds earlier. Read this number as
  "tailscale's client is heavier," not as "Headscale's control plane is
  heavier" — the latter isn't measured here at all.
- **Tailscale**: the production `tailscaled` process, sampled in its
  ordinary steady state (it had been running for days, not 5 seconds like
  every other row) — 2.4% / 82.5 MB, close to Headscale's isolated client
  instance (4.5% / 85.4 MB) despite being the same binary in both cases.
  The gap is plausibly the Headscale row's client having *just* come up
  cold, not a real difference between the two control planes — not
  isolated further here.

## Scope cuts, documented rather than silently dropped

Matching how [`quic-relay-2026-09-12.md`](quic-relay-2026-09-12.md)
documents what it didn't measure:

- **Multi-stream throughput scaling.** Every number above is one TCP/one
  UDP stream. How each tool scales across cores with concurrent streams
  isn't measured — karst's own answer to a related question is
  [`scripts/multi-peer-bench.sh`](../../scripts/multi-peer-bench.sh), which
  has no counterpart built for the other three tools here.
- **Reconvergence-after-change timing.** None of the five tools was
  measured for how fast it recovers after a peer or route changes.
- **NAT-simulated / relay-forced paths.** The plan for this pass called for
  a network-namespace-simulated NAT topology forcing each tool's indirect
  path (karst → its relay, Headscale → DERP, Nebula → its relay-peer
  feature). This was cut after finding that karst's relay *selection* is
  driven entirely by the control-plane netmap (`Config.relays`, populated
  from `karst-control`, not settable in a static node TOML — see
  `bins/karstd/src/config.rs`'s `relays` field doc comment). Exercising it
  honestly would mean standing up a second, separate `karst-control` +
  enrollment flow specifically for this test, which is disproportionate
  effort for this pass and not something to improvise against the
  already-running *production* `karst-control` on these same hosts. Left as
  a real follow-up, not attempted with a fake substitute.
- **True cross-internet NAT/relay paths.** `turing` and `lovelace` are on
  the same lab LAN; nothing here crosses a real NAT or the public internet.
- **Same-size idle-roster comparison across all five tools** (e.g. all five
  with 200 idle peers, matching karst's existing
  [`idle-peers-bench.sh`](../../scripts/idle-peers-bench.sh) criterion).
  This pass's idle numbers are all single-peer (Tailscale's production
  tunnel has exactly one active peer in this measurement — its many other
  tailnet devices are idle/offline and not part of this comparison).

## Reproducing

```sh
scripts/vpn-compare/run-all.sh turing lovelace
```

Runs all five comparators (~40s total, plus however long Tailscale's
already-established ping/iperf3 pass takes) into
`/tmp/vpn-compare-results.tsv`; pass `--out FILE` to redirect. Any one
tool's failure doesn't cancel the others (`run-all.sh` is not `set -e`
across its `run` calls). `setup-tailscale.sh` requires both hosts already
logged into a real tailnet (`sudo tailscale status` shows `Running`, not
`Logged out`) — that login is a one-time, interactive, human step outside
this harness's scope (`sudo tailscale up` prints a login URL to complete in
a browser), not something `run-all.sh` does for you.

Each `setup-<tool>.sh` also runs standalone with a `--keep` flag (all but
`setup-tailscale.sh`, which never brings anything up or tears anything
down — it only measures the existing production tunnel) for manual
inspection before trusting its numbers — `wg show`, `karst status`,
`sudo ~/vpn-compare-run/nebula-bin/nebula-cert print -path ...`, `sudo
~/vpn-compare-run/headscale-bin/headscale --config ... nodes list`.
