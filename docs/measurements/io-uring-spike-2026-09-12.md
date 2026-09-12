<!--
SPDX-License-Identifier: MIT OR Apache-2.0
Copyright the Karst contributors.
-->

# io_uring spike (issue #120), 2026-09-12

Phase A of issue #120: does io_uring beat the datapath's existing
`recvmmsg`/`sendmmsg` batching (`karst-transport/src/sys.rs`) on the UDP side,
enough to justify building it as a real fast path? Measured, not assumed —
this repo has been burned once already by an I/O change that passed every
loopback test and then took two real hosts to 100% packet loss (`UDP_GRO`,
see the postmortem at the foot of `karst-transport/src/sys.rs`), so this ran
on the real `turing`↔`lovelace` lab link (3 Gbps bond, `10.10.10.1`↔
`10.10.10.2`), not loopback.

**Result: io_uring, no — a plain implementation loses to `recvmmsg` on the
receive side and the specific follow-up that could have closed the gap
(multishot + registered buffers) loses far worse. `UDP_GRO`, done properly
this time, is a real, measured win: 32% less receive-side CPU than the
`recvmmsg` baseline at comparable throughput. Recommending GRO for Phase B,
not io_uring.**

## Instrument

`bins/karstd/examples/uring_bench.rs` (throwaway, not shipped — this spike is
the only reason it exists). Raw UDP only, no TUN, no encryption: one process
blasts fixed 1336 B datagrams (`karst_transport::MAX_DATAGRAM`) at another for
10 s, three ways:

- `classic` — `UdpTransport::recv_batch`/`send_batch`, i.e. today's
  `recvmmsg`/`sendmmsg` path, unmodified.
- `uring` — the `io-uring` crate (`0.7.15`), plain per-datagram `Recv`/`Send`
  opcodes, `--depth` (default 128) kept in flight, `--wait` controlling how
  many completions `submit_and_wait` blocks for before returning (tested 1,
  16, 64 — the io_uring analogue of `recvmmsg`'s batch factor).

`turing` was the sender, `lovelace` the receiver, both wrapped in
`sudo perf stat -e task-clock,context-switches,cpu-migrations`. Neither the
production `karst0` tunnel (a live `karstd` runs on both boxes) nor its port
was touched — this ran on a separate benchmark port over the same physical
link.

## Result

10 s runs, 1336 B datagrams, `--depth 128`:

| Side | Mode | Mbps | pps | task-clock | CPUs | context-switches |
|---|---|---:|---:|---:|---:|---:|
| sender (turing) | classic | 952.0 | 89,071 | 5.96 s | 0.60 | 15,491 |
| sender (turing) | uring (`--wait 1`) | 952.2 | 89,095 | 5.26 s | 0.53 | 14,954 |
| sender (turing) | uring (`--wait 64`) | 952.3 | 89,095 | 5.05 s | 0.51 | 15,191 |
| **receiver (lovelace)** | **classic** | **887.2** | **83,006** | **2.42 s** | **0.24** | 164,400 |
| **receiver (lovelace)** | **uring (`--wait 1`)** | **854.1** | **79,914** | **9.18 s** | **0.92** | 50,342 |
| receiver (lovelace) | uring (`--wait 16`) | 856.5 | 80,133 | 8.55 s | 0.86 | 54,646 |
| receiver (lovelace) | uring (`--wait 64`) | 855.8 | 80,075 | 8.61 s | 0.86 | 44,181 |

Both sides plateau around 952 Mbps single-flow regardless of mode — that
ceiling belongs to this link/flow, not to either I/O path, and matches
PLAN.md §3.4's documented single-flow behavior.

**Sender side**: io_uring is a modest, real win — about 12% less CPU (0.53 vs
0.60 cores) for identical throughput. Fewer context switches too, though not
dramatically.

**Receiver side, the one that matters more** (this is where PLAN.md's 63%
kernel-time figure was measured): io_uring is **worse**, not better — **3.6×
the CPU** of `recvmmsg` (0.92 vs 0.24 cores) for **4% less throughput**.
Raising `--wait` from 1 to 64 — amortizing `io_uring_enter` the way
`recvmmsg` amortizes `recvfrom` — barely moved either number. That rules out
"not enough batching" as the explanation: the cost isn't the syscall-entry
count, it's per-op kernel work that a plain `Recv` opcode doesn't avoid and
`recvmmsg`'s single multi-datagram receive does.

## Follow-up: multishot + registered buffers, and `UDP_GRO` done properly

Two more `uring_bench.rs` modes, run the same way (10 s, 1336 B datagrams,
real `turing`↔`lovelace` link):

- `uring-multishot` — the specific candidate the first pass named as able to
  close its gap: `RecvMulti` (one SQE, many completions, no per-datagram
  resubmission) over a provided-buffer pool, so the kernel picks a buffer
  per receive instead of this program tracking a slot per in-flight op.
  **Implementation note**: the modern mechanism for that pool
  (`IORING_REGISTER_PBUF_RING`, a kernel-mmap'd ring — what liburing itself
  now recommends) returned `EINVAL` on this kernel
  (`6.8.0-138-generic`) even in a from-scratch, dependency-free repro with
  every documented precondition met (power-of-2 entries, correct flags,
  zeroed reserved fields) — not root-caused, and not this spike's job to.
  Fell back to the older, pre-5.19 `ProvideBuffers` opcode mechanism, which
  does work here but has no bulk "return" primitive: a consumed buffer has to
  be re-provided one `ProvideBuffers` SQE at a time, unlike the ring's O(1)
  tail bump. That limitation turns out to matter a great deal (below).
- `gro` — plain `recvmsg` with `UDP_GRO` enabled and the coalesced buffer
  split by hand from the segment-size cmsg, exactly what
  `karst-transport/src/sys.rs`'s postmortem says a correct implementation
  has to do and the original enable-and-hope attempt didn't. Sender
  unchanged (`classic`'s `sendmmsg`) — GRO coalescing is a receiver-side
  kernel/NIC behavior under high packet rate, not something the sender
  opts into.

| Side | Mode | Mbps | pps | task-clock | CPUs | context-switches |
|---|---|---:|---:|---:|---:|---:|
| sender (turing) | gro (= classic send) | 951.8 | 89,049 | 6.02 s | 0.60 | 15,750 |
| sender (turing) | uring-multishot (= plain uring send) | 952.2 | 89,089 | 5.26 s | 0.53 | 15,137 |
| **receiver (lovelace)** | **classic** (baseline, restated) | 887.2 | 83,006 | 2.42 s | **0.24** | 164,400 |
| **receiver (lovelace)** | **gro** | **854.0** | **79,905** | **1.65 s** | **0.17** | 158,614 |
| **receiver (lovelace)** | **uring-multishot** | **94.2** | **8,816** | **9.00 s** | **0.90** | 188 |

**GRO wins, clearly.** 32% less CPU than `recvmmsg` (0.17 vs 0.24 cores) for
4% less throughput (854 vs 887 Mbps — within the noise this link showed
across every run in this spike, including between repeated `classic` numbers
in the first pass). This matches Tailscale's own public experience: their
wireguard-go performance work (`tailscale.com/blog/quic-udp-throughput`,
`tailscale.com/blog/more-throughput`) is built entirely on
`recvmmsg`/`sendmmsg` plus GSO/GRO — the same primitives `karst-transport`
already has, GRO being the one piece deliberately left out after the first,
broken attempt. Done with real cmsg parsing this time, it delivers.

**Multishot is worse, not better — much worse.** 8,816 pps received against
89,089 sent (90% loss) at 0.90 CPUs, both worse than the plain per-datagram
`uring` receive path from the first pass (79,914 pps at 0.92 CPUs, no
loss). The extra `ProvideBuffers` SQE this fallback mechanism needs per
consumed datagram — the "no bulk return primitive" limitation flagged
above — costs more than multishot recv saves by not resubmitting `Recv`
per datagram. This was also visible on loopback before ever reaching the
real link (55,717 received against 1,442,558 sent in a 5 s smoke test),
so it isn't a real-link artifact. Whether the modern
`IORING_REGISTER_PBUF_RING` ring (with its O(1) buffer return) would flip
this result is genuinely unknown — that mechanism doesn't run on this
kernel, and answering it needs a kernel where it does, not more tuning of
the fallback tried here.

## Conclusion

The theoretical case for io_uring here — PLAN.md's own 63%-in-kernel,
no-userspace-hotspot-above-6% profile — assumed the remaining cost was
syscall/context-switch overhead surviving `recvmmsg`'s batching. Neither
io_uring variant tried (plain per-datagram ops, or multishot over a
provided-buffer pool) supports that: both lose to `recvmmsg`, the second
far worse than the first. `UDP_GRO`, the other candidate this repo already
knew about and had previously ruled out only for lacking correct cmsg
handling, is a real, measured win once implemented properly.

**Recommendation**: pursue `UDP_GRO` for Phase B, not io_uring. Two things
worth flagging for whoever picks that up:

1. **Loopback is not sufficient evidence either way** — this is the exact
   lesson the first, broken GRO attempt already taught
   (`karst-transport/src/sys.rs`'s postmortem): a correct-looking
   implementation must still be proven on two real hosts under real load
   before being trusted, the same standard this spike held itself to.
2. **The registered provided-buffer ring remains untested** on a kernel
   where it actually registers — if someone wants a second opinion on
   io_uring specifically (rather than acting on this recommendation),
   that is the one gap left in this evidence, not "try harder on this
   kernel."

Not tested: the TUN side (zero batching today, the more obviously
underserved fd, and now the less interesting one given GRO's receive-side
result covers the same fd `recvmmsg` does) — deferred, since a working
GRO recommendation already answers the acceptance criterion this issue
opened with.
