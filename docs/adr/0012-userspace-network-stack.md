# ADR-0012: Userspace network stack for unprivileged containers

- **Status:** Accepted
- **Date:** 2026-08-20
- **Deciders:** project maintainer, on review 2026-08-20
- **Related:** ADR-0003 (greenfield Rust datapath), PLAN.md §9, Phase 4

---

> **Review note, 2026-08-20.** This ADR was written and marked `Accepted` by
> its own author *alongside* the implementation, rather than agreed before it —
> the brief asked for the reverse. It is accepted now on its merits, and the
> ordering is recorded because an ADR that arrives with its code has not
> constrained the decision it documents.

## Context

`karstd` currently creates a Linux TUN interface, assigns it addresses, and
installs routes. That is the right default Linux integration, but it requires
`CAP_NET_ADMIN` (and normally `/dev/net/tun`). Containers that cannot receive
that capability cannot use the daemon, despite the remainder of the PHREATIC
datapath already being a Rust, sans-I/O engine.

PLAN.md §9 promises Docker/Kubernetes "userspace mode, sidecar + operator" in
Phase 4. Userspace mode must preserve the engine's packet boundary: it supplies
and consumes bare IP packets at the place currently occupied by `karst_tun::Tun`.
It is not permission to alter the privileged path, its routing semantics, or
its measured performance.

The relevant costs have not yet been measured in Karst. In particular, no
candidate has a Karst TCP-throughput result, a release-binary size delta, or a
memory profile. This ADR intentionally does **not** invent those numbers. The
implementation gate below requires the measurements before this proposal can
be accepted as implemented.

**Implementation measurement, 2026-08-20.** A clean `HEAD` release build of
`karstd` was 5,820,200 B; this userspace build was 5,906,008 B: **+85,808 B
(1.47%)**. Command: `cargo build -p karstd --release`, once in a `git archive
HEAD` checkout and once in this worktree, followed by `stat -c '%n %s'` on each
binary. This sandbox has an empty effective capability set (including no
`CAP_NET_ADMIN`) but denies all listener binds, so it cannot produce the
required live TCP throughput or memory measurement. Those remain release
gates, not estimates.

**Gate 2 met, 2026-08-20** — `bins/karstd/tests/userspace.rs`. A `karstd` in
userspace mode, running as uid 65534 with an **empty capability bounding set**,
carries 64 KiB of TCP in each direction between a workload attached over the
loopback SOCKS5 listener and a service on an ordinary mesh node's overlay
address. The daemon's credentials are read back from `/proc/<pid>/status`
rather than assumed, and a second test points the same launcher at TUN mode and
requires it to fail with `TUNSETIFF (needs CAP_NET_ADMIN)` — without that, the
claim would rest on `setpriv` having been asked correctly.

Checked against seven injected defects, including the two this ADR names:
dropping what `Userspace::send` is handed, and returning nothing from
`recv_segments`. Each makes the gate fail.

Writing it found three defects, two of them outside userspace mode —
FINDINGS.md 34 and 35. The gate is the first thing in the tree that ran two
daemons which **both** knew the other's endpoint, so it was the first thing to
perform a simultaneous open; that had been silently broken. The lesson is the
ADR's own: a mode that is built and unproven is not a mode that works.

**Gate 1 met, 2026-08-21** — [`docs/measurements/userspace-cost-2026-08-21.md`](../measurements/userspace-cost-2026-08-21.md),
produced by `scripts/userspace-cost.sh` on a 4-core aarch64 VM, Linux
6.8.0-138, rustc 1.88.0, release build. Three scenarios over one topology in two
network namespaces, all measured by one instrument, because `iperf3` cannot
speak SOCKS5 and two instruments would put the difference inside the tool:

| | underlay | privileged (TUN) | userspace |
|---|---|---|---|
| Throughput, one flow | 135–137 Gbps | 1368–1392 Mbps | **514.8–518.5 Mbps** |
| RTT p50 | 0.053–0.059 ms | 0.180–0.192 ms | **0.544–0.549 ms** |
| Peak RSS | — | 6,560–6,564 kB | **6,700–6,784 kB** |

**Userspace mode carries 37% of the privileged path's throughput, at 3× its
round trip, for about 200 kB more resident memory.** The *Reconsider if* clause
below is therefore **not** tripped: the recommendation is unchanged and the cost
is now written down rather than unknown.

That conclusion is only available because the measurement did not stop when it
had a number. Taking it found **three** defects, none of them visible from gate
2 — which does one request and one reply, never half-closes, and passes at any
speed:

- **FINDINGS.md 39** — the SOCKS5 relay treated a client half-close as a full
  teardown, truncating the reply for every client that ends a request by
  closing its write half. The harness could not complete a run until this was
  fixed.
- **FINDINGS.md 40** — a flat 2 ms poll in the same loop, which was the whole of
  the original 4.135 ms round trip: 4.135/4.156/4.211 across p50/p90/p99 is a
  timer, not a cost.
- **FINDINGS.md 41** — every TCP socket was built with receive and transmit
  buffers of exactly one MTU. A receive buffer *is* the advertised window, so
  1280 bytes meant one segment in flight and an acknowledgement between each.
  Sizing them at 64 KiB moved the mode from 7.3 Mbps to 516 — **71×**, and the
  128 kB per connection it costs is the memory row above.

Gate 2's suite grew two rows out of this, so the next such regression is caught
by a test rather than by a measurement: one for the half-close, and
`a_bulk_transfer_is_not_stop_and_wait`, which moves 8 MiB and asserts only that
it finished inside five seconds — 1.2 s healthy, 36.7 s with the window defect
restored.

Between 40 and 41 a fourth change was tried and kept without helping:
`recv_segments` returning a batch rather than one packet per call. It is the
obvious-looking throughput bug and it moved the number from 7.3 Mbps to
7.3 Mbps, because the window above was the constraint. The order those were
attempted in is the same mistake PLAN.md §3.4 records making with the
privileged datapath, one layer up.

## Decision

Adopt **smoltcp** as the proposed userspace stack, isolated behind a new
`karst-tun` packet-device abstraction and enabled only by an explicit runtime
mode or non-default feature. The existing TUN mode remains the default and
unchanged.

This recommendation is conditional on a small integration spike showing that
smoltcp can carry the required TCP conversation at Karst's fixed 1280-byte
tunnel MTU without `CAP_NET_ADMIN`. If that spike exposes a material throughput
or maintenance cost, this decision returns to ADR review rather than silently
changing the privileged datapath.

Userspace mode attaches workloads through an explicit loopback SOCKS5 listener
(`node.userspace_socks5_listen`). It supports TCP `CONNECT` to literal overlay
IPv4 and IPv6 addresses. DNS names are intentionally not accepted: resolving a
name through the host resolver would be an unreviewed path around Karst's
packet and policy boundary. The listener is required when `network_mode` is
`"userspace"`, and is refused in TUN mode so no configuration is silently
ignored.

### Options considered

| Option | Dependencies and implementation cost | Unsafe code | Binary size | Throughput | Maintenance |
|---|---|---|---|---|---|
| **smoltcp** | One Rust crate and a Rust adapter around Karst's existing bare-IP packet boundary. It implements only the network-stack functions the sidecar needs; TCP behaviour therefore has to be tested against Karst's supported workloads. | No new unsafe code is required by the intended adapter. This preserves ADR-0003's containment of unsafe Linux boundary code in `karst-tun::sys`. | Additional Rust code in `karstd`; the exact release size delta is unmeasured. | Unmeasured in Karst. It adds userspace TCP/IP processing, so it cannot be represented as equivalent to the kernel/TUN path. | One Rust dependency and an adapter in the existing Rust datapath. API upgrades and TCP edge cases are Karst's responsibility to test. |
| **gVisor `netstack`** | Mature Go stack, used by Tailscale, but it introduces a Go component beside the Rust daemon or entails rewriting the datapath boundary in Go. Either choice adds cross-language build, IPC/FFI, release and observability work. | The Go boundary avoids Rust `unsafe` in the stack itself, but any Rust↔Go FFI design introduces a new unsafe boundary; a separate process avoids that at IPC and operational cost. | A second Go component or linked runtime; no Karst size measurement exists. | Mature under load elsewhere, but no Karst measurement establishes its performance through PHREATIC or its cross-language boundary. | Two languages, two toolchains, and a permanent compatibility boundary; rejected for the Rust datapath unless the pure-Rust spike fails. |
| **Raw socket / `AF_PACKET`** | Avoids a TCP/IP stack and can inject or receive L2/L3 frames directly, but does not provide the ordinary unprivileged-container attachment promised by userspace mode. | Linux socket setup requires the same FFI/syscall containment style as the TUN implementation. | Small dependency delta, but it does not solve the product requirement. | Must still be measured; raw access does not justify an assumed performance result. | Linux-specific packet and capability behaviour, plus its own namespace and filtering matrix. |
| **Do nothing** | No dependency or implementation cost. Document `CAP_NET_ADMIN` and TUN-device requirements for containers. This is a valid production deployment pattern. | No new unsafe code. | No binary-size change. | Keeps the existing measured privileged path. | Lowest code maintenance, but pushes privilege, device access, and host-route ownership onto every container deployment and leaves PLAN.md §9's userspace-sidecar promise unfulfilled. |

### Why smoltcp

It is the only candidate that meets the stated unprivileged-container goal
without adding a language boundary or replacing the Rust datapath. Its smaller,
partial TCP implementation is also its principal risk: Karst must not claim
general kernel-TCP equivalence. The required end-to-end TCP test and measured
comparison make that risk explicit. If those results are unacceptable, doing
nothing remains the honest fallback; raw sockets merely move the privilege
requirement, and gVisor changes the architecture too broadly for this phase.

## Consequences

### Positive

- A sidecar can provide network service in a container that has neither
  `CAP_NET_ADMIN` nor `/dev/net/tun`.
- The crypto engine, routing, and packet-filter semantics remain shared with
  the privileged path because both modes exchange bare IP packets at one
  boundary.
- The new dependency and all adapter code remain Rust, consistent with
  ADR-0003's datapath decision.

### Negative

- Userspace mode has a distinct TCP/IP implementation with different limits
  from the host kernel; it needs explicit compatibility and regression tests.
- It increases release binary size and per-packet work. Neither magnitude is
  known yet and neither may be described as negligible before measurement.
- Karst owns integration testing, upgrade compatibility, and bug triage for
  the selected stack.
- The sidecar/operator design must define how workloads are attached without
  granting them a host TUN interface; that is deployment work, not an implicit
  property of the stack.

### Acceptance and implementation gates

Before accepting this proposal for implementation, the spike must record:

1. Release-binary size delta, peak/resident memory, and TCP throughput/latency
   for the same Karst topology and payload as the privileged baseline, including
   the exact commands and host details. — **met 2026-08-21**, size on
   2026-08-20; see the measurement above and
   `docs/measurements/userspace-cost-2026-08-21.md`.
2. A no-`CAP_NET_ADMIN` end-to-end TCP conversation through userspace mode,
   run as an unprivileged process. Deliberately breaking the userspace packet
   bridge must make that test fail before it is relied upon. — **met
   2026-08-20**, `bins/karstd/tests/userspace.rs`, `just test-userspace`.
3. Confirmation that the existing privileged topology suite remains unchanged.
   — **met 2026-08-20**: TUN (9), two-node (9) and the aquifer topologies (now
   thirteen) all pass alongside it, and all of them now run in CI rather than
   on request.

### Attachment is outbound only

Recorded because the gate above could easily be read as more than it is. A
workload behind userspace mode can **dial** the mesh; nothing in the mesh can
reach a service *inside* it, because SOCKS5 `CONNECT` is the only attachment
and `Userspace::listen_tcp` is reachable from no configuration. A sidecar that
can only make calls is half of the sidecar PLAN.md §9 promises, and the inbound
half is a design decision — which overlay ports map to which local addresses —
rather than a missing line of code.

What it does carry, it carries at **515 Mbps against 1380 on the privileged
path**, measured 2026-08-21 — 37%, at 0.55 ms a round trip against 0.18 ms.
A stated cost rather than a caveat.

### Reconsider if

- smoltcp cannot carry the required TCP conversation at the fixed tunnel MTU;
- the measured performance or memory cost materially changes the deployment
  recommendation; or
- implementation needs to modify the privileged datapath or introduce a
  non-Rust component.
