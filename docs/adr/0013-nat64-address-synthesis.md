# ADR-0013: NAT64 address synthesis at the socket boundary

- **Status:** Accepted
- **Date:** 2026-08-21
- **Deciders:** project maintainer, on review 2026-08-21
- **Related:** PLAN.md §6 (test matrix), FINDINGS.md 45, 46, 47, `aven-v1.md` §7.2

---

> **Review note, 2026-08-21.** As with ADR-0012, this ADR was written alongside
> its implementation rather than before it. It is accepted on its merits, and
> the ordering is recorded because an ADR that arrives with its code has not
> constrained the decision it documents. What it *did* constrain is real
> nonetheless: the whole-aquifer row was built and run to failure before any of
> the code below existed, so the problem statement is a measurement rather than
> an anticipation.

## Context

PLAN.md §6 names NAT64/DNS64 as one of the topologies the NAT matrix must
cover. The instrument row landed 2026-08-19 and established how such a path
treats a *datagram*. The whole-aquifer row — a real `karstd` on an IPv6-only
network behind a real translator — was built on 2026-08-21, and it failed in
thirty seconds, before the node had finished starting.

**Every address Karst hands a node is an IPv4 literal.** The control server
comes from the node's own configuration file, the relay from the netmap, the
peer from a call-me-maybe. A node on a NAT64-only network has no IPv4 address
and no IPv4 route, so none of the three is reachable, and no amount of local
configuration fixes two of them — they arrive from the wire.

The fixture was verified independently before any of this was attributed to
Karst: `ping6` and a TCP connection from the IPv6-only namespace both reached
`51.75.10.10` at `64:ff9b::334b:a0a`. The network worked. The daemon could not
name it.

A NAT64 network's answer is the **prefix**: `prefix::v4` is the IPv6 address the
translator converts back to `v4` on the way out, and converts *to* on the way
back. A node that knows the prefix reaches the whole IPv4 internet; one that
does not is confined to its own segment.

## Decision

### 1. Translate at the socket boundary, in both directions

The datapath socket synthesises `prefix::v4` on every send to an IPv4 address,
and extracts the IPv4 address back out of every source that arrives within the
prefix. Nothing above the socket is aware that either happened.

**Alternative rejected: translate where each address is used.** The engine,
AVEN's candidate list, the endpoint printed by `karst status`, and the
reassembler's source key would each have had to know about prefixes. That is
four places to keep consistent and four places for a synthesised address to
leak from.

The decisive argument is what a leak costs. `aven-v1.md` §7.2 has a node hand
back the source it saw as `Pong.observed`, and the peer publishes that as its
own reflexive candidate. A synthesised address escaping there means an IPv4 peer
advertising, to the entire mesh, an address that exists only inside one other
node's network. FINDINGS.md 45 is precisely this failure in its other spelling —
a v4-mapped address rather than a prefixed one — and the fix for it put
[`karst_transport::canonical`] at this same boundary for this same reason. A
NAT64 prefix is the same category of fact: a purely local spelling of an IPv4
address. `::ffff:a.b.c.d` is the kernel's, `prefix::a.b.c.d` is the network's,
and the daemon above is entitled to know neither.

### 2. Rewrite the relay address and the control URL, once, as text

These are TCP connections rather than datapath sends, and they are named by
strings. Both are rewritten at the point the configuration becomes real
(`control::load_config`), so every later consumer — the first Ponor connection,
§9.1's latency measurements, §9.2's moves — dials an address that works without
any of them knowing why.

**A hostname is left alone, in both.** DNS64 synthesises for names already; that
is what it is for. Only a literal arrives at a node unsynthesised, because
nothing looked it up.

### 3. Learn the prefix by RFC 7050, gated twice

`node.nat64` takes `"auto"` (the default), `"off"`, or a literal prefix.
`"auto"` resolves `ipv4only.arpa` for AAAA and takes the prefix out of the
synthesised answer — but only after two gates:

1. **The datapath socket must be IPv6.** `node.listen` decides the address
   family, because §4 gives the datapath one shared socket, and an `AF_INET`
   socket cannot send to an IPv6 address at all. A prefix on such a node would
   rewrite every *reachable* destination into an unreachable one.
2. **The host must hold no IPv4 address of its own.** This is not an
   optimisation. A host with working IPv4 and a NAT64 translator would, if it
   synthesised, route every IPv4 flow through the translator — and so learn a
   reflexive address belonging to the translator rather than to itself,
   advertise it, and be reached there by peers that could have reached it
   directly.

An explicit prefix skips the second gate and not the first: the first is a hard
incompatibility, the second is a judgement an operator may overrule.

**Alternative rejected: RFC 8781's PREF64 router-advertisement option.** It is
the better mechanism — no DNS, no DNS64 dependency, and the information comes
from the router that actually knows. It requires reading ICMPv6 router
advertisements, which requires a raw socket, which requires `CAP_NET_RAW` in a
daemon that otherwise wants only `CAP_NET_ADMIN`. That is a real widening of the
daemon's privilege for a mechanism the gated fallback already covers on every
network that runs DNS64. Declined, and revisitable if a deployment turns up
running NAT64 without it.

**Alternative rejected: configuration only.** It works and it is what the first
draft did, but it makes a node on a NAT64 network require an operator who knows
the prefix. On mobile and enterprise IPv6-only networks the prefix is
network-specific and the operator generally does not. A VPN that needs manual
prefix entry to work on the networks that most need it is not finished.

**What RFC 7050 costs, stated rather than glossed.** It is a heuristic and the
RFC says so (§3, §6): it needs a DNS64 resolver on the path, and it trusts an
unauthenticated answer. A resolver that lies can choose where this node sends.
That is bounded by what Karst already assumes — traffic is authenticated and
encrypted end to end, so a hostile prefix costs reachability and not
confidentiality — and it is why the mechanism is gated rather than eager.

### 4. Support every prefix length RFC 6052 defines, and refuse the rest

32, 40, 48, 56, 64 and 96. The embedding is **not** concatenation below /96:
bits 64–71 are reserved and must be zero, so an address straddling them is split
around the gap, and five of the six lengths do straddle.

Assuming /96 for a prefix that is not one does not fail — it synthesises a
well-formed address for the wrong host, and the only symptom is that nothing
answers. So a length the standard does not define is refused at configuration
time with the standard's own reason.

The implementation is checked against RFC 6052 §2.4's worked example **copied
verbatim from the standard**, rather than against expectations derived from the
same bit-shifting the implementation uses. An implementation that agrees with
itself proves nothing.

## Consequences

- A node on a NAT64-only network reaches the mesh, and goes direct. The
  whole-aquifer row (`an_ipv6_only_node_behind_nat64_reaches_an_ipv4_mesh`)
  converges to a direct path by `Shape::NatA`'s mechanism — the masquerade
  behind the translator is an ordinary port-restricted cone.
- The peer on the far side is told nothing and does nothing. It holds a plain
  IPv4 address for a node that has none, which is what makes the translation
  node-local rather than a protocol change.
- **The whole-aquifer row cannot verify the receive half.** With extraction
  deleted the row still passes: a synthesised address is one the NAT64 node
  really can reach, so its own paths keep working, and what breaks is only what
  it tells *other* nodes. Observing that needs a third node.
  `bins/karstd/tests/nat64.rs` observes it directly instead, with a real socket
  and a real `Disco`, and asserts on the `Pong` that comes out. Writing that
  test found FINDINGS.md 47.
- The prefix is fixed for the process's life. A host that moves between
  networks needs a restart, which is already true of `node.listen`.
- One thing remains unaddressed and is named rather than implied: an `AF_INET`
  node's sends to an IPv6 candidate fail silently. Correct for a node with no
  IPv6 connectivity, and unreadable to its operator.
