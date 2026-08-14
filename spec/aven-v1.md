<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# AVEN v1 — Path Discovery Protocol

- **Status:** Draft 0.1 — Phase 4 deliverable, not yet modelled, not externally reviewed
- **Date:** 2026-08-14
- **Licence:** CC-BY-4.0 with an irrevocable, royalty-free grant to implement
  in software under any licence. Independent implementations are wanted.

> **Implementable.** §4–§8 are stable enough to build against and match
> `crates/karst-disco/`. §12 lists what remains open, and the list is long:
> this is the first draft of the hardest unglamorous part of a mesh VPN.
>
> All four ProVerif queries verify (§11), against an attacker that holds **a
> different peer's disco key** — because a tailnet is not a trust boundary
> (PLAN.md §1.1).
>
> §7.4 is what the model found, and draft 0.1 did not have it: a `Ping` is
> authenticated, so it cannot be forged — which is true, and is not the same as
> saying a genuine one cannot be *replayed*.

---

## 1. Introduction

AVEN finds and maintains a **direct path** between two Karst nodes that begin
by talking through a relay, and chooses which of several working paths to use.
It is the protocol behind `karst-disco` (PLAN.md §6).

An *aven* is a shaft connecting a cave system upward to the surface; cavers
look for them to find a way out. The naming follows ADR-0010's rule that
invented proper nouns get themed names and standard technical terms do not.

### 1.1 What AVEN does

| | |
|---|---|
| **Candidate gathering** | Local interface addresses, server-reflexive addresses learned from peers and relays, and addresses a peer reports observing |
| **Path probing** | Small authenticated `Ping`/`Pong` pairs to each candidate |
| **Reflexive discovery** | A `Pong` reports the source address the `Ping` appeared to come from — the STUN function, without a STUN server |
| **Candidate exchange** | `CallMeMaybe` over the relay, so both ends probe at once |
| **Path selection** | Continuous measurement with hysteresis, preferring direct over relay and IPv6 over IPv4 |

### 1.2 What AVEN does not do

- **It carries no user data.** Only probes and candidate lists. A working path
  is handed to PHREATIC; AVEN never sees a tunnelled packet.
- **It derives no keys.** Its authentication key comes from the netmap (§5).
- **It does not decide whether two nodes may talk.** That is the ACL's job,
  enforced by the packet filter at both ends (PLAN.md §4.3).
- **It is not confidential.** Probes are authenticated, not encrypted. §9
  states exactly what an observer learns, which is more than nothing.
- **It does not do port mapping.** UPnP-IGD, NAT-PMP and PCP are gateway
  protocols, not this one; they gather candidates that AVEN then probes.

---

## 2. Conventions

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted
as in RFC 2119. `‖` is concatenation. Integers are **big-endian**. Lengths are
in bytes.

---

## 3. Cryptographic suite

Suite `0x0001` (`KARST_1`), as `phreatic-v1.md` §3. AVEN uses only:

| Role | Algorithm | Size |
|---|---|---|
| Message authentication | HMAC-SHA-512, truncated to 16 bytes | key 32 B, tag 16 B |
| Key derivation | HKDF-SHA-512 | — |

Truncation to 16 bytes matches `phreatic-v1.md` §9.2's fragment MAC. No AEAD
and no signature: a probe is a few dozen bytes sent many times a minute, and
3309 bytes of ML-DSA per probe would make the discovery traffic larger than the
traffic it exists to find a path for.

---

## 4. Sharing a socket with PHREATIC

AVEN datagrams travel on **the same UDP socket** as PHREATIC, to and from the
same ports. This is not an optimisation and MUST NOT be changed to a separate
port: a path is only useful if it is the path PHREATIC will actually use, and a
NAT binding proven on one port says nothing about another.

That makes demultiplexing a real problem, and it has no free answer.

**A magic prefix is a hint, not a decision.** A datagram whose first four bytes
are `0x4B 0x41 0x56 0x4E` (`KAVN`) SHOULD be tried as AVEN first. But
`phreatic-v1.md` §5 begins every datagram with `reassembly_id`, which is drawn
from a CSPRNG, so roughly one PHREATIC datagram in 2³² begins with the magic by
chance. A receiver MUST therefore fall through to PHREATIC when AVEN parsing or
authentication fails, and MUST fall through to AVEN when PHREATIC's `frag_mac`
fails.

Reserved bits are not an alternative. `phreatic-v1.md` §2 makes reserved fields
**ignored on receipt rather than rejected**, deliberately, so that adding a
suite later is not a flag day — which means no reserved-bit pattern makes a
datagram invalid PHREATIC, and none can be borrowed as a discriminator.

**What actually separates the two protocols is that both are authenticated.** A
PHREATIC datagram offered to AVEN fails AVEN's MAC; an AVEN datagram offered to
PHREATIC fails `frag_mac`. Each is a 16-byte tag, so a cross-protocol
acceptance requires a forgery rather than a coincidence. The magic exists only
so that the common case costs one MAC rather than two.

Cost, stated plainly: an attacker sending junk can force **two** MAC
computations per datagram instead of one. That is a factor of two on work the
receiver was already doing, not a new amplification class.

---

## 5. Keys and identifiers

### 5.1 The per-pair disco key

```
disco_key(A, B, epoch) = HKDF-SHA-512(
        master, "karst-disco-v1" ‖ min(A,B) ‖ max(A,B), epoch, 32)
```

Derived by the coordination server and shipped in the netmap, exactly as the
per-pair PSK is (PLAN.md §2.6). `A` and `B` are node IDs (`ponor-v1.md` §5.1).

**It is a separate derivation from the PSK, not the PSK itself.** Both come
from the same master, so this is not assumption diversity — it is blast-radius
containment. A disco key is used on far more packets, by code that runs before
any session exists, and it must not be the value that also gates the data
plane's key schedule.

**An absent disco key means no discovery, ever.** A node holding no disco key
for a peer MUST NOT probe that peer and MUST NOT accept probes from it; the
pair stays on the relay. There is deliberately no unauthenticated mode and no
zero-key fallback, and this is the one place where §2.6's zero-PSK fallback is
**not** mirrored — connectivity survives without discovery, because the relay
carries it, so nothing is bought by relaxing here. Unauthenticated probing
would let an attacker tell a node where to send its traffic, which is the whole
of what this protocol decides.

The netmap therefore carries one more secret, reinforcing PLAN.md §2.6's
encryption-at-rest requirement.

### 5.2 The sender tag

A datagram names its sender by an 8-byte **tag**, never by a node ID:

```
peer_tag(sender, epoch) = HMAC-SHA-512(
        disco_key, "aven-tag-v1" ‖ epoch ‖ sender_id)[0..8]
```

A receiver precomputes the tag for each peer it holds a disco key for and looks
up by it: one map lookup, then one MAC verification. Without a tag the receiver
would have to try every peer's key against every unmatched datagram, which at
200 peers is a 200× amplifier any unauthenticated source could pull.

The tag is not a node ID and MUST NOT be treated as one, and it is 8 bytes
rather than 32 for a second reason: `phreatic-v1.md` §4 keeps identity off the
wire, and putting a node handle in cleartext on every probe would give back
what ADR-0005 spent a design decision buying. An observer without the disco key
sees an opaque value that changes every epoch. Within an epoch it is linkable —
that is the accepted cost, and it matches PHREATIC's stated posture of
degrading to pseudonymity rather than to identification.

`sender_id` is bound into the derivation so that the two directions of a pair
have different tags. Without it both ends would present the same value and
neither could tell its own probes from its peer's.

---

## 6. Datagram format

```
 0        4        5        6                14           18
 +--------+--------+--------+---------------+------------+
 | magic  |version |  type  |   peer_tag    |   epoch    |
 |  (4)   |  (1)   |  (1)   |     (8)       |    (4)     |
 +--------+--------+--------+---------------+------------+
 |  body (0..305)                                        |
 +-------------------------------------------------------+
 |  mac (16)                                             |
 +-------------------------------------------------------+
```

Header is 18 bytes. `mac` is HMAC-SHA-512 truncated to 16, keyed by the pair
disco key, over **everything preceding it** — magic, version, type, tag, epoch
and body. Verified in constant time.

A receiver MUST reject a datagram longer than **339** bytes — the largest
legal one, a sixteen-candidate `CallMeMaybe` — before doing anything else, and MUST reject one whose length does not match what its type
requires.

### 6.1 Message types

| Type | Name | Body | Total |
|---|---|---|---|
| `0x01` | `Ping` | `tx_id` (12) | 46 |
| `0x02` | `Pong` | `tx_id` (12) ‖ `observed` (19) | 65 |
| `0x03` | `CallMeMaybe` | `count` (1) ‖ `count` × `endpoint` (19) | 54..339 |

`tx_id` is 12 bytes and MUST be drawn from a CSPRNG.

`count` MUST be between 1 and **16**. A node with more than sixteen candidates
sends its best sixteen; a receiver MUST reject a larger count rather than
truncating, because a truncating receiver and a non-truncating sender disagree
about what was said.

### 6.2 Endpoint encoding

Nineteen bytes, fixed:

```
 +--------+-----------------------------------+--------+
 | family |            address (16)           |  port  |
 |  (1)   |                                   |  (2)   |
 +--------+-----------------------------------+--------+
```

`family` is `0x04` or `0x06`. An IPv4 address occupies the first four bytes and
the remaining twelve MUST be zero; a receiver MUST reject a non-zero tail
rather than ignoring it, so there is no covert channel in the padding and no
two encodings of one address.

Fixed width rather than variable costs twelve bytes per IPv4 candidate and buys
a parser with no length arithmetic in it. On a protocol whose datagrams are
parsed before authentication, that is the right side of the trade.

---

## 7. Probing

### 7.1 What a `Pong` proves

**A `Pong` confirms the endpoint its `Ping` was sent *to*, not the address the
`Pong` arrived *from*.**

This is the most important rule in the protocol and the easiest to get wrong.
A sender MUST record the endpoint each outstanding `tx_id` was sent to, and on
receiving a matching `Pong` MUST mark *that* endpoint reachable — regardless of
the datagram's source address. An implementation that instead trusts the source
address can be walked to any address an on-path attacker likes, by copying a
genuine `Pong` and re-sending it from somewhere else.

A `tx_id` MUST be accepted **once**. A second `Pong` bearing a spent `tx_id` is
discarded.

Outstanding `tx_id`s MUST expire — five seconds is RECOMMENDED — and the number
of them MUST be bounded per peer. They are state allocated in response to a
peer's behaviour, which makes them worth counting.

### 7.2 Reflexive addresses

`Pong.observed` is the source address the `Ping` appeared to arrive from. A
node collects these as candidates to advertise. This is the STUN function, and
it needs no STUN server: any peer already exchanging probes can answer, and so
can a relay.

A node MUST NOT treat a reported reflexive address as a path to itself and
MUST NOT use it for anything but advertisement. A peer that lies here causes
its counterpart to advertise a candidate that does not work, which wastes
probes and nothing else — but only because nothing is trusted to it beyond
advertisement.

### 7.3 Candidate exchange

`CallMeMaybe` is sent **over the relay**, which is what makes simultaneous open
possible: both ends learn each other's candidates at nearly the same moment and
begin probing together, so both NATs see an outbound packet before either sees
an inbound one.

It MAY also be sent on an established direct path when candidates change — a
node that acquires a new interface should not have to wait for a relay round
trip to say so.

### 7.4 Answering a probe at most once — the flaw modelling found

**A responder MUST answer each `tx_id` at most once**, within a bounded window
per peer. **A prober MUST use a fresh `tx_id` for every probe, including
retransmissions** — which it needs anyway, or a retransmitted probe's round-trip
measurement is meaningless.

Recorded because draft 0.1 had neither rule and the reasoning that omitted them
was plausible. A `Ping` is authenticated, so a forged one is impossible; that is
true, and it is not the same as saying a *genuine* one cannot be reused.

ProVerif's answer to `inj-event(BAnswered(tx)) ==> inj-event(APinged(tx))` was
`is false`, with the note that the **non-injective form is true**. In words: the
responder answered a `Ping` the prober really did send — more than once. An
attacker that captures one `Ping` can replay it indefinitely, from any address,
and the responder answers each copy to wherever the copy came from.

That is a **reflector**, and it needs no key: 46 bytes in, 65 bytes out. The
amplification factor of 1.4 is small enough that this is not a serious
bandwidth attack, and saying so is part of reporting it accurately. What makes
it worth fixing anyway is that it is free to fix, that it lets an unauthenticated
attacker spend a peer's probe budget under someone else's name, and that a
reflector in a protocol that runs on an open UDP port on every node in a network
is not a thing to ship knowingly.

The window is bounded, so the guarantee is **at most once within the window**
rather than at most once ever. An unbounded cache would be a memory-exhaustion
vector reachable by the same replay it exists to stop, which would be trading
one flaw for a worse one.

### 7.5 Rates

| | |
|---|---|
| Probe a new candidate | Immediately on learning it, then backing off: 100 ms, 300 ms, 900 ms, then give up |
| Keep a chosen path alive | Every **5 seconds** |
| Re-probe alternatives | Every **30 seconds** |
| `CallMeMaybe` | On change, and at most once every **5 seconds** per peer |

These are RECOMMENDED, not normative. What is normative: a node MUST rate-limit
probes per peer, and MUST NOT emit more probe traffic to a peer than that peer
has authenticated itself to it — an unauthenticated source must never be able to
make a node send more than it received.

---

## 8. Path selection

A node holds a set of known paths per peer and chooses one. Ordering,
strongest key first:

1. **Working beats not working.** A path with no `Pong` inside the last 15
   seconds is not eligible.
2. **Direct beats relay**, always, even when the relay is faster. A relay
   discloses the traffic graph to its operator (`ponor-v1.md` §9); latency is
   not the only axis and the operator's exposure does not appear in a
   round-trip time.
3. **IPv6 beats IPv4** when both are direct and their latencies are within the
   hysteresis margin. IPv6 paths are less likely to be behind a translating
   middlebox that will rewrite them later.
4. **Lower latency** otherwise.

### 8.1 Rule 3 is a credit, not a comparison

"IPv6 beats IPv4 when their latencies are within the hysteresis margin" is not
a transitive relation, and an implementation that writes it as a comparator
directly is wrong for three or more paths — it can rank A over B over C over A,
and a sort or a minimum over a non-transitive comparator returns whichever
element it happened to examine first.

An implementation SHOULD instead give an IPv6 path a **latency credit of one
margin** and order by the credited value. That gives the same answer for two
paths, is a total order for any number, and cannot depend on iteration order.
Recorded here because the phrasing above is the natural one to write and the
bug it produces is a path selection that varies between runs on identical
inputs.

### 8.2 Hysteresis

A node MUST NOT switch away from a working chosen path unless the alternative
is better by a margin. RECOMMENDED: **20 ms or 20%, whichever is larger**,
sustained across **three** consecutive measurements.

Switching costs more than the latency difference usually recovers: the datapath
keeps both paths warm and cuts over on receipt of the first packet on the new
one, but a node that oscillates does so for every peer at once and turns a
measurement artefact into a network-wide event. Rule 2 is exempt — a direct
path that starts working displaces a relay immediately, because that transition
is what the whole protocol exists to cause.

### 8.3 Relay fallback is not a failure state

A node MUST retain its relay path while a direct path is in use, and MUST fall
back without dropping traffic when the direct path stops answering. The relay
connection is not torn down on promotion (`ponor-v1.md` §9.1 keeps the home
relay connected regardless), so falling back costs no handshake.

---

## 9. What an observer learns

An on-path observer without the disco key sees:

- That two addresses are exchanging small UDP datagrams with the AVEN magic,
  and how often.
- An 8-byte tag per direction, constant within an epoch and unlinkable across
  epochs. **Not** a node ID, and not resolvable to one without the key.
- The **candidate addresses in a `CallMeMaybe`**, in cleartext. This is the
  real disclosure: a node's local interface addresses — which may include
  private RFC 1918 addresses that describe its LAN — travel unencrypted between
  peers, and over the relay where the relay operator can also read them.

That last point is a genuine weakness and is recorded as such in §12.3 rather
than defended. Encrypting the body under the disco key would close it and costs
one AEAD; it is not in v1 because the key schedule for it was not designed in
time, which is a reason and not a justification.

---

## 10. Error handling

Every failure is a **silent drop**. There are no error messages in AVEN:

- Unknown tag → drop. Emitting anything would make a node an oracle for which
  peers it holds keys for.
- MAC failure → drop, without distinguishing it from an unknown tag.
- Malformed, over-long, wrong length for its type → drop.
- Unknown type or version → drop. Unlike `ponor-v1.md` §6, this does not close
  anything, because there is nothing to close: AVEN is stateless UDP.

A node MUST NOT log a per-datagram message on any of these paths at default
verbosity. The protocol runs on an unfiltered UDP port; a log line per dropped
datagram is a disk-filling primitive available to anyone who can reach it.

---

## 11. Formal verification

`spec/models/aven.pv`, ProVerif 2.05, seconds:

| Query | Result |
|---|---|
| A confirms a path as B's only if B answered, **injectively** | ✅ |
| The same, non-injectively | ✅ |
| B answers only probes A sent — no forgery | ✅ |
| The disco key stays secret | ✅ |

The attacker holds **a different peer of A's disco key** throughout. A tailnet
is not a trust boundary — PLAN.md §1.1 lists a malicious peer inside one as in
scope — so this is the ordinary configuration rather than an exotic one.

Not modelled: §7.1's transaction-to-endpoint association, which lives in the
receiver's bookkeeping rather than on the wire and is enforced by the
implementation's types; path selection, which is availability rather than
security; and §7.4's replay window, for the reason below.

### 11.1 Why §7.4 is not in the model

Expressing "answer each `tx_id` once" needs a table and a lock, and adding them
makes ProVerif answer **cannot be proved** on both agreement queries — in the
base model *and* in the broken variant, where a demonstration that cannot fail
demonstrates nothing. That is an incompleteness of the analysis rather than a
counterexample; there is no trace either way.

So the model is kept at the forgery-and-impersonation level, which it proves,
and §7.4 is carried by the implementation and its tests instead. Claiming
otherwise would be claiming something no run of the model establishes.

### 11.2 The broken variant

`spec/models/aven-headeronly.pv` authenticates only the header, leaving `tx_id`
and `observed` outside the MAC. Both agreement queries become **false**, with a
trace: an attacker rewrites `tx_id` on a captured `Pong` and confirms a path the
peer never answered from.

This one is not hypothetical. `phreatic-v1.md` §13.8 made exactly that trade on
the data path — deliberately, after profiling showed the fragment MAC costing
five times the AEAD it gated — and the variant exists to record that the saving
must not be carried across to AVEN, where the MAC's job is different.

---

## 12. Open items — this draft is incomplete

1. **No external review.** A symbolic model says nothing about implementation
   behaviour.
2. **Epoch rotation is specified only in outline.** The disco key rotates with
   the PSK epoch, but nothing here says what a node does with in-flight probes
   across a rotation, or whether it accepts epoch *n−1* the way
   `phreatic-v1.md` §7.3 does for PSKs. It should, and the window is unwritten.
3. **`CallMeMaybe` bodies are not encrypted** (§9). Local interface addresses,
   including private ones, are visible to the relay operator and to anyone on
   the path. An AEAD under the disco key would close this.
4. **Symmetric-NAT port prediction is unspecified.** PLAN.md §6 calls for
   birthday-paradox port prediction; nothing here says how many ports to try,
   at what rate, or how that interacts with §7.5's rate limit — which it
   plainly does, since the technique is "send many probes at once".
5. **No path-MTU interaction.** A direct path may have a smaller MTU than the
   relay path, and AVEN reports nothing about it. PLAN.md schedules PMTU
   discovery for Phase 6; until then a path can be selected that black-holes
   full-size packets, which is a worse failure than not selecting it.
6. **Nothing bounds the candidate set.** §6.1 caps a single `CallMeMaybe` at
   sixteen, but a peer may send one every five seconds with sixteen different
   addresses each time. The per-peer candidate table needs a cap and an
   eviction rule.
7. **No IPv4/IPv6 dual-stack policy for probing order.** §8 ranks paths once
   they work; it does not say whether to probe both families at once, and
   probing both doubles the traffic a node emits on first contact.
