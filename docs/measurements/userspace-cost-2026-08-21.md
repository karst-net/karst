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

| Metric | underlay | tun (privileged) | userspace | userspace, as first measured |
|---|---|---|---|---|
| Throughput, one flow | 130–138 Gbps | **1340–1384 Mbps** | **5.6–7.3 Mbps** | 1.1 Mbps |
| RTT, p50 | 0.04–0.06 ms | **0.15–0.18 ms** | **0.547 ms** | 4.135 ms |
| RTT, p90 | 0.07 ms | 0.21–0.23 ms | 0.566 ms | 4.156 ms |
| Peak RSS (`VmHWM`), subject | — | **6,672–6,692 kB** | **6,648–6,672 kB** | 6,584 kB |
| Release binary | — | — | +85,808 B (1.47%) | measured 2026-08-20 |

Three runs of each after the fixes below; ranges are across runs.

**Memory is a non-answer, and that is the answer.** The subject's peak resident
set is the same in both modes to within a rounding error — around 6.6 MB — and
the peer, which is an ordinary privileged node in both scenarios, sits at 6.5 MB
throughout. smoltcp's buffers are a fixed allocation per socket and there is one
socket. Nothing in the memory column argues for or against the mode.

**Latency was a timer, not a cost** — see finding 40. The first measurement's
4.135 ms had a p50/p90/p99 spread of 4.135/4.156/4.211: a distribution that flat
is a poll interval, not work. It was two 2 ms sleeps in the SOCKS5 relay loop,
one per direction of a round trip. With that fixed the mode is **0.547 ms
against 0.178 ms privileged** — 3× the baseline and 0.37 ms of absolute
difference, which is a real cost and a defensible one.

**Throughput is not a timer, and it is the finding.** After the same fix,
userspace mode carries 5.6–7.3 Mbps where the privileged path carries
1340–1384 Mbps on the same hardware — **about 0.5%**. This is not smoltcp's
arithmetic; it is the shape of the path around it:

- `Userspace::recv_segments` returns **one packet per call**. The privileged
  path returns ~52 per `read` through `IFF_VNET_HDR` segmentation offload
  (PLAN.md §3.4, change 5), so userspace mode gives up the batching the whole
  datapath was rebuilt around.
- Every one of `tcp_can_recv`, `tcp_may_recv`, `tcp_can_send`, `tcp_recv`,
  `tcp_send` takes the lock on the **entire** smoltcp stack and calls `poll()`.
  One relay pass therefore polls the stack several times.
- Each byte is copied at the SOCKS5 hop in addition to every copy the
  privileged path makes.

None of these is a defect and none was measured before, which is why the mode
shipped with a number nobody had. Fixing them is a redesign of the attachment
loop rather than a tuning pass, and it is named as such in PLAN.md rather than
attempted here.

## What this does not measure

- **One flow, one peer, one connection.** A sidecar with many concurrent
  connections would put many relay threads on the same stack lock, and this
  says nothing about that.
- **A veth underlay**, which carries 130+ Gbps. Neither Karst row is limited by
  the wire here, which is deliberate — the point was to compare the two modes,
  not to reproduce §3.4's link. On a real 1G NIC the `tun` row would fall to
  that link's ceiling and the `userspace` row would almost certainly not move.
- **Bulk transfer only.** The workloads userspace mode exists for in a sidecar
  are often request/response, where the latency row matters more than the
  throughput row.

## The gate's verdict

Gate 1 is **met in the sense that matters**: the numbers exist, they were taken
with one instrument on one host in one sitting, and the commands are above.

Whether they *pass* is a separate question, and the honest answer is that they
change the deployment recommendation rather than overturn it. ADR-0012's
*Reconsider if* clause is engaged, not tripped:

- For the control-plane and request/response traffic a sidecar usually carries,
  0.55 ms and a few Mbps is adequate, and the alternative — `CAP_NET_ADMIN` and
  a TUN device in every container — is what the mode exists to avoid.
- For bulk data it is not adequate, and no wording should imply otherwise. A
  deployment moving real traffic should use the privileged path until the
  attachment loop is rebuilt.

## Two defects found on the way

Running the measurement is what found both; neither was visible from the gate-2
test, which does one request and one reply with no half-close.

- **Finding 39** — the SOCKS5 relay treated a client half-close as a full
  teardown, so "send the request, close the write half, read the reply" —
  `curl`, `nc -N`, and any protocol that delimits a message by closing — lost
  the reply. The harness could not complete a single run until this was fixed.
  `bins/karstd/tests/userspace.rs` now carries the row, and the original gate
  test still passes against the defect, which is what makes the new row worth
  having.
- **Finding 40** — the flat 2 ms poll above.
