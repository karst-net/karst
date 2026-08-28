# ADR-0004: Handshake MTU strategy and static-key KEM selection

- **Status:** Accepted
- **Date:** 2026-08-08
- **Deciders:** TBD
- **Supersedes:** —
- **Related:** ADR-0001 (algorithm selection), ADR-0002 (hybrid rationale), ADR-0006 (agility layer)

---

## Context

The PHREATIC handshake (§2 of `PLAN.md`) carries ML-KEM-768 public keys (1184 B)
and ciphertexts (1088 B). Its messages therefore land at roughly 2.4 KB, well
over the 1280-byte IPv6 minimum MTU that the datapath targets.

WireGuard's DoS posture depends on a property we would lose: the responder
holds **zero state** until it has received one complete, MAC-validated
datagram. Fragmentation breaks this directly — the responder must buffer
fragment 0 while awaiting fragment 1, keyed by an unauthenticated reassembly
ID, giving an attacker a memory-exhaustion primitive from spoofed sources.

Reliability is the more obvious cost but the smaller one. At two fragments per
message, per-message success drops from 99% to ~98% at 1% path loss, and from
95% to ~90% at 5%. Retransmission absorbs this at a latency cost. **The
governing problem is pre-authentication state, not packet loss.**

The alternative is to eliminate fragmentation by choosing a KEM whose public
key never appears on the wire. Classic McEliece is extreme in exactly this
direction: 524,160-byte public key, 156-byte ciphertext (`mceliece460896`).
Since the coordination server already distributes peer keys out of band, the
public key size is in principle absorbable and the handshake shrinks
dramatically. This is the design Rosenpass ships.

### The constraint that decides it

McEliece only applies to the **static** key. The **ephemeral** public key must
travel in msg1 to give forward secrecy, and a McEliece ephemeral is absurd.
With a 156-byte McEliece static ciphertext but an ML-KEM-768 ephemeral, msg1
is still ~1488 B — **over MTU anyway**.

Fitting a single datagram forces the ephemeral down to **ML-KEM-512**
(pk 800 B, ct 768 B), yielding ~1.1 KB messages. Rosenpass's parameter choice
(McEliece-460896 + Kyber-512) is not incidental; it is compelled by the MTU.

So the real choice is not "McEliece instead of fragmentation." It is:

- **A:** ML-KEM-768 throughout, two fragments per message, Category 3 ephemeral.
- **B:** McEliece static + **Category 1** ephemeral, single datagram.

Option B's strongest argument is unrelated to packet size: it provides
**PQ assumption diversity**. Option A stakes all post-quantum confidentiality
on lattices; option B survives a lattice break because the McEliece static
secret is mixed into the same key schedule. Classic McEliece has resisted
cryptanalysis since 1978.

Option B's costs are operational and they compound: 524 KB × N peers hits
netmap size, RSS, disk, mobile feasibility, key-rotation cost, and offline
resilience simultaneously. At 500 peers that is 262 MB of key material. Lazy
fetching relieves the memory pressure but breaks first contact with an
uncached peer whenever the control plane is unreachable — forfeiting a
property that makes self-hosting credible. Classic McEliece is also not
NIST-standardized; CNSA 2.0 names ML-KEM only.

The obvious code-based substitute does not help: NIST's backup KEM selection,
HQC, is ~2.2 KB pk / ~4.5 KB ct at Category 1 — worse for a packet budget than
either option.

---

## Decision

**Adopt option A — ML-KEM-768 throughout with a two-fragment handshake — with
three modifications.**

### 1. Fragmentation with a stateless-under-load responder

Restore WireGuard's state discipline rather than accept its loss:

- Fragment header: `reassembly_id (4) | frag_index:2 frag_count:2 (1) | reserved (3) | frag_mac (16)` = 24 B.
  Usable payload per datagram = 1280 − 40 (IPv6) − 8 (UDP) − 24 = **1208 B**.
- **Authentication moves from the message to the fragment.** Each fragment
  carries its own MAC, so an invalid fragment is dropped without ever entering
  a reassembly buffer. This replaces WireGuard's message-level `mac1`/`mac2`.
- **Under load, the responder buffers nothing.** On receiving any fragment
  from an address-unvalidated source while above a queue threshold, it
  discards the fragment and emits a ~64-byte cookie reply (stateless HMAC over
  source address + rotating secret). Amplification ratio 64/1208 ≈ 0.05. Only
  after the initiator echoes a valid cookie in every fragment MAC does the
  responder allocate reassembly state — reducing the attack surface to
  on-path or real-address adversaries, which is precisely WireGuard's posture.
- Below the threshold, buffer freely against a global cap with a 3-second
  reassembly timeout and a per-source budget.
- Hard cap of **4 fragments**; reject anything claiming more.
- Never act on a partial reassembly. Never emit more bytes than received from
  an unvalidated source. Both asserted in tests.

### 2. Message layout revised to guarantee two fragments

The arithmetic is tight enough that the original field layout would have spilled
to three fragments (2422 B against a 2416 B two-fragment budget). Two changes
fix it with margin:

- Move `mac1`/`mac2` to the fragment layer (above) — saves 32 B.
- Fold `peer_id_hint` and `timestamp` into a single AEAD blob with one tag
  instead of two — saves 16 B.

Resulting sizes:

| Message | Bytes | Fragments |
|---|---|---|
| msg1 | ~2378 | 2 |
| msg2 | ~2236 | 2 |
| cookie reply | ~64 | 1 |

msg1 > msg2 natively, so the anti-amplification invariant holds without
padding. Assert it anyway — the margin is 142 bytes and future field additions
will erode it.

### 3. Per-pair PSK mixing for assumption diversity

Recover option B's cryptographic hedge at **zero bytes on the wire**, since
symmetric secrets are post-quantum safe:

- The coordination server derives a per-pair PSK
  `psk(A,B,epoch) = KDF(master, min(A,B), max(A,B), epoch)` and ships it in the
  netmap. Derivation rather than storage keeps server-side state at O(1)
  instead of O(N²); per-node netmap cost is 32 B × peers (6.4 KB at 200 peers).
- The PSK is mixed **last** into the chaining key, after both KEM shared
  secrets and the X25519 output, so it gates the final session key.
- A 4-byte `psk_epoch` in msg1 selects the version; responders accept epoch
  *n* and *n−1* during rotation. Rotate every 24 hours and on any Karst
  Lock event.
- If a node holds no PSK for a peer (new peer, stale netmap), fall back to an
  all-zero PSK so connectivity is preserved. Such sessions are lattice-only and
  **must be logged and surfaced in the console's crypto posture view** (§8.1).

Resulting security claim, stated precisely:

- Against a **classical** attacker: secure if X25519 **or** ML-KEM holds.
- Against a **quantum** attacker: secure if ML-KEM holds, **or** the attacker
  does not hold the PSK.

The honest caveat: because the server derives the PSKs, *control-server
compromise combined with a total lattice break* is a full break. Server
compromise alone is not — the KEM secrets are still required. This is a weaker
hedge than McEliece's, whose security is independent of the server, and that
weakening is the price of the operational benefits.

### 4. Option B retained as an optional profile

The agility layer (ADR-0006) must express a KEM whose public key is
**distributed out of band and never appears on the wire**. Concretely, the
`Kem` trait carries a `KEY_DISTRIBUTION: InBand | OutOfBand` associated
constant, and the handshake codec branches on it. No McEliece implementation
ships in v1; this is a design constraint on Phase 1 so the option stays open
for high-assurance deployments — small, fixed, server-class aquifers where
50 peers × 524 KB = 26 MB is a non-issue and code-based security is worth it.

---

## Consequences

### Positive

- Ephemeral keys stay at Category 3 (ML-KEM-768) rather than dropping to
  Category 1 — the security level the product's positioning implies.
- Peer key material stays at 1184 B, preserving the 60 MB RSS target, mobile
  and OpenWrt viability, cheap key rotation, and full-netmap caching for
  offline operation.
- Clean FIPS 203 lineage and an unobstructed CNSA 2.0 path (ADR-0006).
- Assumption diversity recovered at no packet cost.
- Responder statelessness preserved in the case that matters (under attack).

### Negative

- Reassembly, retransmission, and cookie logic are new code on the
  pre-authentication path — the highest-risk code in the system. Mandatory
  `cargo-fuzz` coverage; `kani` proof obligations on the reassembler; explicit
  spoofed-source DoS tests in CI.
- One extra RTT on first contact while under load.
- Handshake success degrades ~2× faster with path loss than a single-datagram
  design. Mitigate with a 300 ms initial retransmit and jittered backoff.
- **The netmap now carries secrets.** It must be encrypted at rest on nodes,
  never logged, and the PSK master must live in an HSM/KMS where available.
  This raises the value of a control-server compromise and must be stated
  plainly in the security whitepaper.
- Maintaining the out-of-band-KEM branch in the codec costs test-matrix surface
  for a profile with no current customer.

### Follow-ups

- Fragmentation + cookie DoS design and its test suite replace the Phase 1
  McEliece spike.
- PSK key-schedule and rotation semantics enter `spec/phreatic-v1.md` and the
  Verifpal model; the PSK-absent fallback must be modelled explicitly, since a
  downgrade-to-zero-PSK attack is the obvious thing to look for.
- Crypto posture view gains a "lattice-only sessions" indicator.
- Revisit if a customer presents a code-based-crypto mandate, or if lattice
  cryptanalysis materially advances.
