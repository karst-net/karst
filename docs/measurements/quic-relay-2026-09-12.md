<!--
SPDX-License-Identifier: MIT OR Apache-2.0
Copyright the Karst contributors.
-->

# QUIC vs TCP+TLS relay transport — 2026-09-12

ADR-0020 / issue #122's performance comparison. Produced by
`bins/karst-relay/examples/quic_vs_tcp_bench.rs`
(`cargo run --release --example quic_vs_tcp_bench -p karst-relay`).

## Scope

This is a **clean-loopback** measurement, one process, one host: it shows the
fixed cost of each transport's handshake and framing, not the loss-recovery
difference ADR-0020 is actually motivated by (TCP-in-TCP retransmission,
spec §13 #5). Measuring that needs induced loss — `tc qdisc add dev lo root
netem loss <pct>` or equivalent — which this harness deliberately does not
apply itself: doing so would affect every process using loopback on whatever
host runs it, not just this benchmark, and is a system-wide change nobody
asked this measurement to make. An operator who wants the loss-recovery
comparison should run the same binary once against a network namespace or
veth pair with such a qdisc applied and once without, and diff the throughput
numbers below — the harness itself does not need to change.

Host: 16-core x86_64, Ubuntu 24.04.3, kernel 6.8.0. Three runs, `--release`.

## Results

| Metric | TCP+TLS | QUIC |
|---|---|---|
| Handshake, median (n=200) | 1.80–1.94 ms | 2.70–2.81 ms |
| Handshake, p95 | 3.23–3.46 ms | 4.63–5.14 ms |
| Handshake, max | 31.3–33.6 ms | 5.2–6.4 ms |
| Forwarding, 2000 max-size (1336 B) frames | 117.5–118.9 ms | 105.3–113.0 ms |
| Forwarding throughput | 16,825–17,018 frames/s | 17,711–19,001 frames/s |

## Reading this

- **QUIC's handshake costs more on a clean path**, consistently across all
  three runs (~45% higher median). Expected: a fresh UDP socket and QUIC's
  own connection-establishment state machine against an OS TCP stack whose
  fast path is already heavily optimized. This is the cost ADR-0020 accepts
  in exchange for QUIC's independent per-connection loss recovery — nothing
  here contradicts that trade, since paying it once per connection is cheap
  next to what a lost segment costs mid-stream on a lossy path.
- **QUIC's handshake tail is shorter, not longer**: TCP+TLS's max was
  31–34 ms against QUIC's 5–6 ms in every run, i.e. TCP+TLS's *worst* observed
  handshake was over 5× its own median, while QUIC's worst was under 2.3× its
  median. Consistent with TCP's occasional retransmission-timer or
  connect-queue stalls even on loopback; QUIC's user-space stack has none of
  those. One host, three runs — reported as an observation, not a claim about
  tail behavior in general.
- **QUIC forwarded slightly faster** once established (roughly 5–13% more
  frames/s across the three runs) despite carrying the same frame bytes.
  Plausibly fewer syscalls per write on this build's `SendStream`/`RecvStream`
  path versus a TLS record layer over a raw socket; not investigated further,
  since the actual property this transport targets is loss recovery, not
  clean-path throughput.
- **Neither result changes the ADR-0020 decision.** The reason to add QUIC
  was never clean-path speed — it was that a lost packet on the relay hop no
  longer costs a TCP retransmission on top of QUIC's own, and that property
  is exactly what this harness does not measure. It is recorded as the
  reproducible starting point for whoever measures it next.
