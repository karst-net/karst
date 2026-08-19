# ADR-0005: Node identity model and peer presentation in the handshake

- **Status:** Accepted
- **Date:** 2026-08-09
- **Deciders:** TBD
- **Related:** ADR-0004 (MTU strategy), PLAN.md §2.2, §4.2, §4.5, §13 Q3

---

## Context

A Karst node identity comprises **three** keypairs:

| Key | Algorithm | Purpose |
|---|---|---|
| Identity key | ML-DSA-65 | Signed by the Bedrock chain (§4.5); establishes that the node is authorized to exist |
| Static KEM key | ML-KEM-768 | Encapsulated to during the handshake; establishes that the peer *is* that node |
| Static DH key | X25519 (32 B) | Classical authentication in the handshake — **added 2026-08-09**, see below |

> **Amendment, 2026-08-09.** This ADR originally specified two keypairs.
> Drafting [`spec/phreatic-v1.md`](../../spec/phreatic-v1.md) §7 exposed the
> gap: with no *static* X25519 key, the classical hybrid could only be
> ephemeral–ephemeral, giving forward secrecy against a passive classical
> adversary but **no classical authentication**. Authentication would have
> rested entirely on ML-KEM — the single point of failure
> [ADR-0002](0002-hybrid-key-agreement.md) claims to eliminate. The handshake
> now performs three DH operations (`es`, `ee`, `se`) mirroring its three KEM
> encapsulations, so every security property survives a break of either family.
> **Cost is zero wire bytes** — static DH keys come from the netmap, message
> sizes are unchanged at 2378/2236, and the netmap grows 32 B per peer against
> ~3200 B already. See `spec/phreatic-v1.md` §13.1.

The open question this ADR resolves: **how does the initiator present its
identity in msg1?**

WireGuard's `IK` pattern sends the initiator's full static public key in msg1,
encrypted under a key derived from the initiator's ephemeral and the
responder's static key. The responder decrypts it and learns who is calling.

That is unaffordable here. An ML-KEM-768 public key is **1184 bytes**. Carrying
it would take msg1 from 2378 B to 3530 B — **three fragments instead of two**,
a 50% increase in handshake packets and materially worse loss behaviour,
breaking the budget established in ADR-0004.

The alternative is to send a short hint and have the responder recover the full
key from the netmap it already holds. PLAN.md §13 Q3 asked whether that costs
identity confidentiality. **It does not** — see below. The premise of the
original question was faulty, and the §2.2 note describing a fingerprinting
tradeoff was written on the mistaken assumption that the hint might travel in
cleartext.

---

## Decision

msg1 carries

```
peer_id_hint = H(protocol_label || static_kem_pk)      // 32 bytes
```

inside the AEAD-protected payload, alongside the timestamp. The hint is
**unsalted** and **session-independent**. There is no full-key fallback
variant.

The hint is a *lookup key into the netmap*, not a decryption selector: a node
has exactly one static key, so no hint is required to decapsulate `ct_static`.
Its sole function is to let the responder find the initiator's static KEM
public key so it can encapsulate to it in msg2, which is what authenticates the
initiator.

### Identity confidentiality is preserved, and in places improved

Because the hint sits inside the AEAD, it is no more visible than WireGuard's
encrypted static key:

| Adversary | WireGuard (full static pk) | Hint |
|---|---|---|
| Passive observer | Learns nothing | Learns nothing — equivalent |
| Active prober | Nothing about third parties | Equivalent |
| Holds responder static key, **has** roster | Full identity | Full identity — equivalent |
| Holds responder static key, **no** roster | **Full identity** (raw pk is a permanent global identifier) | **Pseudonym only** (hash is one-way) |
| Retroactive ML-KEM break on recorded traffic | Full identity | Pseudonym only |

The hint is never worse and is better in two cases: identity confidentiality
degrades to **pseudonymity** rather than to full identification.

### No salt

A rotating salt would buy unlinkability across epochs against an attacker
holding the responder's static private key but *not* its roster. That threat
class is close to empty: the static key and the netmap live on the same
machine, and the netmap **is** the roster. The salt would cost triple lookup
tables (accepting epochs *n−1*, *n*, *n+1* for clock skew) and introduce a
midnight-boundary failure mode, in exchange for defending nobody.

### The hint must stay session-independent

Binding the hint to the session — for example `MAC(ss1, static_pk)` — is a
tempting-looking change that must be rejected. It gains nothing, since anyone
who can decrypt the payload already holds `ss1`. And it is actively harmful:
the responder could no longer precompute a hint→key table and would have to
recompute a MAC over every roster entry on every handshake, converting an O(1)
lookup into **O(N) work per handshake after the cookie check** — a DoS
amplifier that scales with aquifer size.

`spec/phreatic-v1.md` carries this as an explicit "do not do this" note.

### No full-key fallback on hint miss

The obvious objection is that a hint miss kills the handshake, creating a
netmap dependency in tension with control-plane-down operation (ADR-0004). A
fallback msg1 variant carrying the full 1184-byte key would appear to fix it.

It buys nothing. Consider what a responder does with a full public key for a
peer absent from its netmap: it has no ACL entry, no expiry, and no
lock-chain validation for that key, so **it must reject it regardless**.
Accepting would let anyone with a self-generated keypair join the network.
A hint miss and an unauthorized peer are the same condition.

The netmap dependency is inherent to the authorization model, not created by
this design choice, and 1184 additional bytes do not relax it.

*Theoretical exception:* authorizing purely from the Bedrock signature
chain with no netmap entry. The initiator would have to carry ML-DSA
signatures of 3309 bytes each inline — far worse than the problem it solves.
If ever wanted, it belongs in a post-handshake exchange, not msg1.

### Hint misses are dropped silently

The responder does **not** reply with an "unknown peer" error. Doing so would
make every node a membership oracle for its own roster, answering "is key X in
your aquifer?" to any prober. Hint misses are logged locally and dropped,
matching WireGuard's treatment of unknown peers.

---

## Consequences

### Positive

- msg1 stays within the two-fragment budget with 142 bytes of margin.
- Identity confidentiality matches WireGuard and exceeds it under
  responder-key compromise or a retroactive lattice break.
- Responder lookup is O(1) against a precomputed table.
- No roster-membership oracle.

### Negative

- A responder cannot accept an inbound handshake from a peer missing from its
  netmap. This is inherent to authorization, but it does mean netmap freshness
  is on the connectivity path, and stale-netmap symptoms will present as
  silent handshake failures rather than explicit errors. `karst status` must
  surface netmap age prominently, and `karst doctor` must diagnose hint misses
  explicitly — this will otherwise be a recurring support burden.
- Rotating a node's static KEM key changes its hint, so peers cannot reach it
  until they receive the netmap update. Rotation must therefore be
  netmap-driven with an overlap window, not unilateral.

### Notes

- Hint collisions require a 256-bit hash collision and are disregarded.
  Duplicate hints detected at netmap ingest are logged as a control-plane bug.
- 32 bytes is retained rather than truncating to 16. The saving is marginal
  against the fragment margin and not worth reasoning about collision
  behaviour.
