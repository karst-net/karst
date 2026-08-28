# ADR-0003: Greenfield Rust datapath

- **Status:** Accepted — scope narrowed to the datapath by ADR-0009
- **Date:** 2026-08-09
- **Deciders:** TBD
- **Related:** ADR-0004 (MTU strategy), ADR-0009 (control plane forks NetBird), PLAN.md §3, §9

---

## Context

Karst needs a WireGuard-equivalent datapath carrying a post-quantum handshake.
The options were:

1. Fork **wireguard-go** and/or **tailscale/tailscale** (Go, BSD-3/MIT).
2. Fork **boringtun** (Rust, BSD-3).
3. Write a greenfield Rust datapath.

**Scope note:** this ADR originally covered the whole system. ADR-0009 narrowed
it to the datapath after establishing that the reasoning below is specific to
packet handling and says nothing about the coordination server, which is now a
NetBird fork. Read the two together.

---

## Decision

**Greenfield Rust for the datapath, handshake, relay and NAT traversal.**

### Why not fork a WireGuard implementation

WireGuard's design is unusually tight, and that tightness is load-bearing. Its
handshake initiation is 148 bytes; ours is 2378 (ADR-0004). That single change
invalidates the properties the rest of the implementation is built on:

- Handshake messages are no longer single datagrams, so **fragmentation and
  reassembly** must be introduced on the pre-authentication path.
- The **stateless responder** guarantee is lost by default and has to be
  reconstructed with mandatory cookies and per-fragment MACs.
- The cookie/`mac1`/`mac2` mechanism moves from the message to the fragment.
- Fixed-size buffer assumptions throughout the packet path no longer hold.

Retrofitting that into wireguard-go means touching precisely the code that
makes WireGuard trustworthy, while inheriting a framing we would immediately
need to change — and doing so without the freedom to redesign it cleanly. The
work is comparable to writing a fresh datapath and the result is harder to
review. `boringtun` has the same framing constraints with a smaller maintainer
base.

There is also no interoperability to preserve: a PQ handshake cannot talk to a
WireGuard peer regardless. The usual strongest argument for forking is absent.

### Why Rust rather than Go

Go was a serious candidate — `crypto/mlkem` is in the standard library as of
1.24, and the control plane is Go. Three things decided it:

- **No GC pauses in the packet path.** Tail latency matters for a datapath, and
  a stop-the-world pause is a network hiccup.
- **Memory safety on a pre-authentication parser.** The fragment reassembler
  processes attacker-controlled bytes before any authentication. Rust's
  guarantees are worth most exactly there. `#![forbid(unsafe_code)]` everywhere
  except `karst-tun` and the GSO paths, with `// SAFETY:` justifications.
- **Mobile.** One Rust core exposed through UniFFI serves both iOS and Android
  (Phase 7). Go's mobile story is weaker.

The verified `libcrux-ml-kem` implementation (ADR-0001) is also Rust-first,
which fits a project gating release on formal verification.

### Sans-io discipline

`karst-noise` and `karst-proto` perform no I/O: bytes and time in, bytes and
timer requests out. This costs plumbing and is worth it — it is what makes the
protocol deterministically testable, fuzzable, and tractable to model.

---

## Consequences

### Positive

- Free design of the wire format around PQ sizes, rather than working against
  a format built for 32-byte keys.
- Memory safety where attacker-controlled parsing happens.
- One datapath core for every platform including mobile.
- Deterministic simulation testing becomes practical (PLAN.md §11).

### Negative

- **No WireGuard interoperability.** Accepted; there was never a path to it.
- **No upstream maintenance sharing.** Every fix is ours. This is the single
  largest ongoing cost of the decision.
- **The full client-platform surface is ours to build** (§9) — Linux, macOS,
  Windows, then iOS and Android. Mobile alone is a quarter per platform
  including store review and battery tuning.
- Loss of a decade of WireGuard's hardening in the field. Mitigated by fuzzing,
  formal models, and external review — but mitigation is not equivalence, and
  the plan should not pretend otherwise.

### Reconsider if

An in-kernel Rust datapath becomes viable and the licensing constraint bites —
which is why ADR-0007 chose `MIT OR Apache-2.0` for the crates, preserving
GPLv2 compatibility through the MIT arm.
