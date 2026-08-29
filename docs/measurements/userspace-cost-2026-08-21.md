<!--
SPDX-License-Identifier: CC-BY-4.0
Copyright the Karst contributors.
-->

# What userspace mode costs — ADR-0012 gate 1

**2026-08-21.** Harness: [`../../scripts/userspace-cost.sh`](../../scripts/userspace-cost.sh),
run as root on one host.

## The question

ADR-0012 adopted smoltcp for userspace mode and attached three acceptance
gates to it. Gate 2 (a no-`CAP_NET_ADMIN` TCP conversation) was met on
2026-08-20. Gate 1 asks for

> release-binary size delta, peak/resident memory, and TCP throughput/latency
> for the same Karst topology and payload as the privileged baseline, including
> the exact commands and host details

and had been outstanding since the ADR was written, with only the size delta
recorded. The ADR is explicit that these are "gates, not estimates", and it
carries a *Reconsider if* clause naming "the measured performance or memory
cost materially changes the deployment recommendation".

This is that measurement.

## Method

Three scenarios over **one** topology, so the numbers are comparable:

| Scenario | What runs |
|---|---|
| `underlay` | two namespaces joined by a veth, no Karst — bounds the instrument |
| `tun` | both daemons on TUN devices — the privileged baseline |
| `userspace` | the subject on smoltcp, reached over its loopback SOCKS5 listener |

The subject and the peer are in **separate network namespaces**. That is not
incidental: both overlay addresses are local addresses on one host, so a TUN
baseline in a single namespace would be short-circuited by the kernel and would
measure loopback rather than Karst.

**One instrument for all three**
([`../../bins/karstd/examples/tcpload.rs`](../../bins/karstd/examples/tcpload.rs)).
`iperf3` cannot speak SOCKS5, and measuring the privileged path with `iperf3`
and userspace mode with anything else would put the instrument inside the
difference. The only thing that changes between the two Karst runs is
`--socks5`. Throughput is **counted by the receiver** and reported back to the
sender: a sender counts bytes handed to a socket buffer, which at the end of a
run is bytes that have not crossed anything.

```sh
sudo scripts/userspace-cost.sh --seconds 10 --rtt-count 300
```

### Host

| | |
|---|---|
| kernel | Linux 6.8.0-138-generic |
| arch | aarch64 (the CPU advertises no model name) |
| cores | 4 |
| memory | 14,278,216 kB |
| rustc | 1.88.0 (6b00bc388 2025-06-23) |
| `karstd` | release, 5,981,872 B |

A 4-core VM, not the 48-core hosts PLAN.md §3.4's figures come from. The
absolute numbers are therefore not comparable with that section; the **ratios
between the three rows** are what this measures, and all three rows are on the
same hardware in the same minutes.

## Result

| Metric | underlay | tun (privileged) | userspace |
|---|---|---|---|
| Throughput, one flow | 135–137 Gbps | **1368–1392 Mbps** | **514.8–518.5 Mbps** |
| RTT, p50 | 0.053–0.059 ms | **0.180–0.192 ms** | **0.544–0.549 ms** |
| RTT, p90 | 0.07 ms | 0.22 ms | 0.57 ms |
| Peak RSS (`VmHWM`), subject | — | **6,560–6,564 kB** | **6,700–6,784 kB** |
| Release binary | — | — | +85,808 B (1.47%), measured 2026-08-20 |

Three runs of each; ranges are across runs.

**Userspace mode carries 37% of the privileged path's throughput, at 3× its
round-trip time, for about 200 kB more resident memory.** That is a cost worth
naming and not a disqualification.

### How it got there, because the first numbers were much worse

The measurement is more useful as a sequence than as a row, because two of the
three steps were not what they looked like:

| | Throughput | RTT p50 |
|---|---|---|
| As first measured | 1.1 Mbps | 4.135 ms |
| 1. Poll only when a pass moved nothing (finding 40) | 5.6–7.3 Mbps | **0.547 ms** |
| 2. `recv_segments` returns a batch, not one packet | 7.3 Mbps — **no change** | — |
| 3. TCP socket buffers sized above one MTU (finding 41) | **514.8–518.5 Mbps** | 0.546 ms |

**Step 1 was a timer, not a cost.** The original 4.135 ms had a p50/p90/p99
spread of 4.135/4.156/4.211 — 80 µs across every percentile. A distribution
that flat is a poll interval, and it was: two unconditional 2 ms sleeps in the
SOCKS5 relay loop, one per direction of a round trip.

**Step 2 is the negative result, and it is worth as much as the positives.**
`Userspace::recv_segments` returned exactly one packet per call where the
privileged path returns ~52 through segmentation offload — an obvious-looking
throughput bug, named as such in the first version of this document. Fixing it
moved the number from 7.3 Mbps to 7.3 Mbps. The queue almost never held a
second packet to batch.

**Step 3 is where the throughput was.** Each TCP socket was constructed with
receive and transmit buffers of exactly one MTU:

```rust
tcp::Socket::new(
    tcp::SocketBuffer::new(vec![0; self.mtu]),   // 1280 bytes
    tcp::SocketBuffer::new(vec![0; self.mtu]),
)
```

A TCP receive buffer *is* the window the stack advertises. A 1280-byte window
permits exactly one segment in flight, so the sender waits for an
acknowledgment after every segment — stop-and-wait, whatever the path can
carry, and no amount of batching or polling below it can help. Sizing the
buffers at 64 KiB — an ordinary kernel starting window — moved the mode from
7.3 to 516 Mbps, a **71× change**, and cost the 128 kB per connection visible
in the memory row.

The order matters to how this reads: step 2 was tried before step 3 because it
was the visible thing, and it is exactly the mistake PLAN.md §3.4 records
making with the datapath — batching and micro-optimization attempted before the
serialization was found. Same lesson, a different layer, four months later.

## What this does not measure

- **One flow, one peer, one connection.** A sidecar with many concurrent
  connections would put many relay threads on the same stack lock, and this
  says nothing about that.
- **A veth underlay**, which carries 130+ Gbps. Neither Karst row is limited by
  the wire here, which is deliberate — the point was to compare the two modes,
  not to reproduce §3.4's link. On a real 1G NIC both rows would be nearer that
  link's ceiling than to each other, which is worth knowing before quoting the
  37% anywhere: it is a ratio measured where the wire is free.
- **Bulk transfer only.** The workloads userspace mode exists for in a sidecar
  are often request/response, where the latency row matters more than the
  throughput row.

## The gate's verdict

Gate 1 is **met**: the numbers exist, they were taken with one instrument on one
host in one sitting, and the commands are above.

They also pass, which the first draft of this document could not say. At 37% of
the privileged path's throughput, 3× its latency and ~200 kB more memory,
userspace mode is a mode with a stated cost rather than a mode to avoid.
ADR-0012's *Reconsider if* clause — "the measured performance or memory cost
materially changes the deployment recommendation" — is **not** tripped: the
recommendation is unchanged, with the cost now written down.

The privileged path remains the default and remains faster. What has gone is
the version of this conclusion that would have been recorded if the measurement
had stopped after step 1: *"use the privileged path for anything but control
traffic"*, which was true of the code as it stood and would have been wrong as
a statement about the design.

## Three defects found on the way

Running the measurement is what found all three; none was visible from the
gate-2 test, which does one request and one reply, never half-closes, and
passes at any speed.

- **Finding 39** — the SOCKS5 relay treated a client half-close as a full
  teardown, so "send the request, close the write half, read the reply" —
  `curl`, `nc -N`, and any protocol that delimits a message by closing — lost
  the reply. The harness could not complete a single run until this was fixed.
  `bins/karstd/tests/userspace.rs` now carries the row, and the original gate
  test still passes against the defect, which is what makes the new row worth
  having.
- **Finding 40** — the flat 2 ms poll above.
- **Finding 41** — the one-MTU socket buffers above, which is the whole of the
  71× and which nothing short of a throughput measurement would have found: the
  mode worked, its tests passed, and it was 70× slower than it needed to be.
