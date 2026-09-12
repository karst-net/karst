# ADR-0019: Path MTU discovery for the encrypted datapath

- **Status:** Accepted
- **Date:** 2026-09-11
- **Deciders:** TBD
- **Supersedes:** —
- **Related:** ADR-0004 (handshake MTU strategy, which deferred this), GitHub issue #121

---

## Context

`spec/phreatic-v1.md` §13.6 (ADR-0004) fixes `TUNNEL_MTU` at 1280 bytes — the
RFC 8200 §5 IPv6 minimum, and a floor Karst cannot go below because nodes are
assigned a ULA IPv6 address. A full-size tunnel packet therefore produces a
1336-byte UDP payload (1384 bytes on the wire), and §8 forbids transport
messages from ever fragmenting — the reassembler is a pre-authentication data
structure and keeping it off the data path is the whole point of the two-tier
budget. Both of those are load-bearing and this decision does not touch
either.

The consequence §13.6 accepted at the time: **a path whose true MTU is below
1384 bytes silently black-holes every full-size data packet**, while
handshakes — bounded to 1232 bytes — keep succeeding. Nothing fragments,
nothing is rejected, nothing arrives. The tunnel looks up and stalls only on
large transfers, which is close to the worst presentation a network fault
can have. `aven-v1.md` §12 item 5 and `PLAN.md` §3.3 both named this and
deferred it to Phase 6. This ADR is that follow-up.

**There is nothing smaller to send.** Real traffic already rides at the
tunnel-MTU floor; discovering a path's true MTU cannot produce a smaller
size for the data plane to fall back to without either violating RFC 8200 on
the TUN interface or reintroducing transport-message fragmentation, both
foreclosed above. So "discovery" cannot mean "shrink the packet" here — the
only thing left to act on is *which path carries the traffic*.

Two properties of the deployment model rule out the classical mechanism:

1. **ICMP "packet too big" is exactly the signal NATs are known to drop**,
   and Karst's whole reason for existing is nodes behind NATs. A mechanism
   that depends on it degrades in the deployment it is supposed to serve.
2. **Reading ICMP needs a raw socket a node does not reliably hold.**
   `karst-transport`'s only existing raw-ICMP consumer (`RouterSocket`, PREF64
   discovery, `crates/karst-transport/src/sys.rs`) is opportunistic precisely
   because `CAP_NET_RAW` is not guaranteed: userspace-mode `karstd` runs with
   an empty capability set. Correctness cannot rest on a privilege that is
   sometimes absent.

## Decision

Add **RFC 4821-style Packetization-Layer PMTU Discovery** to `karst-disco`
(AVEN), as a new authenticated message pair rather than a new protocol:

- `MtuProbe` (`0x06`) and `MtuProbeAck` (`0x07`), keyed by the existing §5.2
  per-pair disco key — the same key `Ping`/`Pong` use, not the §5.3 reflect
  key. `MtuProbe`'s zero-padded body is sized so the *total* datagram equals
  the candidate size under test; `MtuProbeAck` is a fixed 46 bytes. Full wire
  format: `spec/aven-v1.md` §7.9.1.
- A node bisects between `MTU_FLOOR` (1232 B, `HANDSHAKE_DATAGRAM_MAX` — what
  RFC 8200 already guarantees every path delivers) and `MTU_CEILING` (1336 B,
  `TRANSPORT_DATAGRAM_MAX` — what full-size traffic needs), probing the
  ceiling first (optimistic: the common case resolves in one round trip) and
  only narrowing on **3 consecutive timeouts** at one size, so ordinary packet
  loss is never mistaken for a black hole. Algorithm: §7.9.3.
- Confined to the peer's **currently chosen path, when it is direct** —
  probing every candidate's MTU would multiply probe traffic for paths that
  will never carry data. A resolved search reopens every 5 minutes, and
  `Engine::rediscover` resets it immediately, so both a black hole clearing
  and a route regressing are found without operator intervention. §7.9.4.
- `aven-v1.md` §8's path-selection rule 2 ("direct beats relay, always") gets
  one narrow, named exception (new §8.4): a direct path whose search has
  **converged** below `MTU_CEILING` ranks behind the relay for that peer,
  until re-probing says otherwise. An unresolved search is not evidence of
  anything and keeps ranking exactly as before — a fresh direct path still
  displaces the relay immediately, unchanged from today.
- Relay paths are never entered into this mechanism at all. `ponor-v1.md`'s
  relay leg is a length-framed TCP stream (`FRAME_PAYLOAD_MAX` = 8192 B), not
  a fixed-size UDP datagram, and cannot black-hole the same way — confirmed by
  inspection rather than built, since there is nothing to build.

### Alternatives rejected

- **Classical, ICMP-fed PMTUD.** Rejected for the two reasons in Context: the
  signal is unreliable in exactly Karst's deployment shape, and reading it
  needs a privilege the process does not reliably have. Kept as a
  documented non-option rather than an opportunistic accelerant layered on
  top — an accelerant is a second mechanism to test and reason about for a
  case (a NAT that *does* forward ICMP) the active probe already handles
  within one extra round trip. Revisit if measurement shows PLPMTUD's
  convergence time is a real operational problem, since the two are not
  mutually exclusive.
- **Shrinking `TUNNEL_MTU` per-peer.** Rejected outright: the TUN interface is
  shared across every peer, RFC 8200 already pins its floor at 1280, and
  §13.6 already spent that budget down to the byte. There is no lower value
  to assign even to one peer without breaking IPv6 on the interface.
- **A continuous, unbounded-precision MTU value from a single probe pair.**
  Considered and rejected in favor of genuine bisection: a single
  ceiling/floor probe answers the only question selection needs (does
  `MTU_CEILING` arrive, yes or no) but throws away the diagnostic value of
  knowing where between 1232 and 1336 a path actually caps out — useful for
  an operator reading `karst status` and cheap to keep, since the bisection
  reuses the same probe primitive.
- **Demoting on the first confirmed-lost probe.** Rejected: one dropped UDP
  datagram is indistinguishable from a black hole at the moment it is lost.
  The 3-consecutive-timeout threshold (RFC 4821's own guidance) is what
  turns "probably lost" into "confirmed", and demoting before convergence
  would flap a path on ordinary loss.
- **Probing every known candidate's MTU, not just the chosen path.** Would
  let a challenger be pre-validated before promotion, which is a real
  benefit, but multiplies probe traffic across up to `MAX_PATHS_PER_PEER`
  (64) addresses for a benefit only the eventually-chosen one needs. Left as
  a documented follow-up (`aven-v1.md` §7.9.3) rather than built now.

---

## Consequences

### Positive

- A path that cannot carry real traffic is discovered and routed around
  instead of silently eating every large packet forever.
- No new privilege requirement: the mechanism runs entirely over the socket
  `karstd` already holds for AVEN and PHREATIC, with no raw socket and no
  `CAP_NET_RAW`.
- No change to any handshake constant, the §9 reassembly-DoS budget, or the
  fixed tunnel MTU — `phreatic-v1.md` §13.6 is amended only to point at this
  ADR, not to change a number.
- The relay-exemption argument required no new code: TCP's own recovery
  already handles this class of failure on that leg.

### Negative

- **`MtuProbe`/`MtuProbeAck` are not in `spec/models/aven.pv`.** The risk is
  bounded — both ride the existing per-pair disco key rather than a new one,
  so there is no new secret or key-agreement claim to state — but a symbolic
  model does not prove an implementation actually produces a datagram of the
  claimed size, and this ADR does not close that gap. Recorded as
  `aven-v1.md` §12 item 11.
- `msg::peek`'s length ceiling rises from 339 bytes (the largest ordinary
  AVEN message) to `MTU_CEILING` (1336 B) to admit the probe, before the MAC
  is checked. This is a real, if bounded, increase in the CPU an unfiltered
  UDP port will spend verifying a MAC over an attacker-chosen garbage
  datagram — roughly 4× the hashing work per rejected datagram, still far
  below what a PHREATIC handshake fragment already costs on the same port.
- A direct path takes at least one extra round trip after being chosen
  before its MTU is confirmed, during which it optimistically carries
  full-size traffic that may still be a black hole. This is the accepted
  cost of "optimistic until disproven" (§8.4) rather than "unconfirmed until
  proven", which would delay every fresh connection by a search instead of
  by nothing.
- Pre-validating a challenger path before promotion is left undone (see
  Alternatives rejected); a path that looked good on RTT alone can still be
  promoted and then demoted a few seconds later once its search converges.
- ~~**§8.4's demotion is inert in the shipped daemon today.**~~ **Resolved.**
  `Engine::via` (`bins/karstd/src/engine.rs`) still decides direct-versus-relay
  the same way it always has — from whether a direct endpoint is installed,
  never by asking `PathSet` to rank one against a relay directly — so this is
  bridged rather than replaced: `Disco::set_relay_latency`/`clear_relay` feed
  every peer's `PathSet` a relay `Path` from this node's held-relay RTT
  (`home::Selector`, sampled once per tick from `run.rs`), and `path_changes`
  (`bins/karstd/src/disco.rs`) now checks `PathSet::chosen_kind()`: a
  direct-kind choice installs exactly as before, but a **relay-kind** choice —
  §8.4 having demoted a confirmed black hole — withdraws the direct install
  instead of installing the relay's bookkeeping address, and `via`'s existing,
  unmodified relay/TURN fallback takes it from there. `PathSet`'s own
  comparison is still not what `via` consults for the ordinary rule-2 case;
  only the black-hole exception is bridged.
- **Still not surfaced in `karst status`'s `PeerStatus`.** A confirmed black
  hole updates `Path::mtu` and now affects real routing, but nothing yet
  reads that state back out for diagnostics — an operator can infer it only
  indirectly (traffic moving over the relay despite a direct endpoint
  existing). Bridging `Disco` and `Engine` for status reporting remains
  future work; routing did not require it because `path_changes`'s existing
  `Install`/`Release` boundary was the narrower, sufficient integration point.
- The relay latency fed to every peer's `PathSet` is this node's own held
  relay only (`home::Selector::chosen_latency_ms`), applied uniformly. A
  peer's separately published home relay (`via_relay`'s `refused` fallback,
  reached only after this node's own relay has said it cannot reach that
  peer) is not modeled — §8.4's decision does not depend on the relay's
  latency value (`group()` alone decides it), only on a relay `Path` existing
  at all, so this is a real simplification but not presently an accuracy gap.

### Reconsider if

- Real-world convergence time (the 3-loss threshold × bisection depth) proves
  too slow against a fast-changing network, in which case an opportunistic
  ICMP accelerant becomes worth the second mechanism's cost.
- Multi-TURN-server or per-peer-relay deployments make pre-validating a
  challenger's MTU before promotion worth its probe-traffic cost.
- Someone bridges `Disco` and `Engine` for `karst status`, at which point
  §8.4's demotion becomes diagnosable as well as effective.
