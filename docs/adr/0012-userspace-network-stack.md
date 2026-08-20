# ADR-0012: Userspace network stack for unprivileged containers

- **Status:** Accepted
- **Date:** 2026-08-20
- **Deciders:** TBD
- **Related:** ADR-0003 (greenfield Rust datapath), PLAN.md §9, Phase 4

---

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
   the exact commands and host details.
2. A no-`CAP_NET_ADMIN` end-to-end TCP conversation through userspace mode,
   run as an unprivileged process. Deliberately breaking the userspace packet
   bridge must make that test fail before it is relied upon.
3. Confirmation that the existing privileged topology suite remains unchanged.

### Reconsider if

- smoltcp cannot carry the required TCP conversation at the fixed tunnel MTU;
- the measured performance or memory cost materially changes the deployment
  recommendation; or
- implementation needs to modify the privileged datapath or introduce a
  non-Rust component.
