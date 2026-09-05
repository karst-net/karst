<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-0015: CNSA 2.0 is a mandate

- **Status:** Accepted
- **Date:** 2026-08-25
- **Deciders:** TBD
- **Related:** Amends ADR-0001 (algorithm selection) and ADR-0006 (agility layer); bears on ADR-0002 (hybrid), ADR-0011 (control channel), ADR-0014 (Bedrock hierarchy); overturns PLAN.md §13 Q6

---

## Context

**PLAN.md §13 Q6 was resolved on 2026-08-09 as "no CNSA 2.0 mandate, no
compliance date". That is no longer true.** CNSA 2.0 is a requirement.

Nearly every cryptographic decision in this project was made downstream of that
answer. ADR-0001 chose Category 3 and ChaCha20-Poly1305 *because* the audience
was "hobbyists and security-minded commercial organizations" with no compliance
deadline. ADR-0006 built the agility layer and put the CNSA profile in it as
suite 3, explicitly "not urgent". PLAN.md §10 scheduled that suite for Phase 7.
All three follow from a premise that has changed.

> **Checked against NSA's CNSA 2.0 FAQ v2.1 (December 2024) on 2026-08-25.**
> The algorithm set below is confirmed. The transition dates have been revised
> more than once and are the part still worth verifying against the current
> publication before any compliance commitment.

### What CNSA 2.0 requires

| Function | CNSA 2.0 | Karst today |
|---|---|---|
| Symmetric | **AES-256** | ChaCha20-Poly1305 (**not approved**) |
| Key establishment | **ML-KEM-1024** (Category 5) | ML-KEM-768 (Category 3) |
| Signature, general | **ML-DSA-87** (Category 5) | ~~ML-DSA-65~~ → ML-DSA-87 ✓ |
| Hash | **SHA-384 or SHA-512** | SHA-512 — **already compliant** |
| Software/firmware signing | **LMS or XMSS** (SP 800-208) | SLH-DSA-SHA2-192s (**not in CNSA 2.0**) |

Two things are notable by their absence. **ChaCha20-Poly1305 is not a NIST
algorithm at all** — it is RFC 8439, an IETF specification, and not FIPS 140-3
approved. And **SLH-DSA is not in CNSA 2.0**: the suite's hash-based signatures
are the *stateful* LMS and XMSS, not FIPS 205's stateless scheme.

Karst is a VPN, which places it in CNSA 2.0's networking-equipment category —
the category with the *earliest* deadlines, not the latest. The exact dates must
be confirmed, but the direction is unambiguous: this is not a Phase 7 concern.

---

## Decision

**CNSA 2.0 becomes a supported profile that a deployment can be held to, and
the work moves out of Phase 7.** Specifically:

> **Read items 1–6 with item 7's renumbering in mind.** They were written
> against the three-suite registry and call the CNSA profile `KARST_3`; item 7
> later removed the ChaCha suite and renumbered, so that profile is now
> `KARST_2` and the surviving Category 3 suite is `KARST_1`. The items are left
> as written — they record what was decided when — and the mapping is in item 7
> and, normatively, in `spec/phreatic-v1.md` §3.1.

1. **`KARST_3` stops being a demonstration of the agility layer and becomes a
   deliverable.** ADR-0006 offered it as proof the layer works; it is now the
   configuration a mandated deployment runs.

   **Done, 2026-08-25.** Two `KARST_3` nodes complete a handshake and exchange
   authenticated data over real UDP sockets, under ML-KEM-1024, AES-256-GCM and
   SHA-384, across three fragments. Items 2 and 3 supplied the primitives; this
   is what made them reachable.

   Four things had to change, and one design question had to be settled first.

   **The question: how does a node hold two KEM parameter sets?** It does not.
   `peer_id_hint` is derived from the static encapsulation key (spec §4), so a
   node holding both a Category 3 and a Category 5 static key would have two
   identities — in the netmap, the roster, the responder's O(1) lookup table and
   the audit trail. That is an identity change, not an agility one. So **the
   parameter set is a deployment property**: one static key, chosen once, and
   the node refuses any suite that key cannot serve. `karst_crypto::Profile`
   pairs the key's parameter set with the suite floor so the two cannot be
   configured apart, and `karstd`'s `Engine` reads its policy off the key rather
   than off a second configuration line.

   The consequence is stated plainly rather than smoothed over: **a `KARST_3`
   node and a `KARST_1` node do not interoperate.** A mandate is not a
   preference; a deployment held to CNSA 2.0 may not fall back, and one that is
   not held to it has no ML-KEM-1024 key to answer with. Moving between them is
   a re-keying, planned as one.

   - **Runtime KEM dispatch.** `karst_crypto::kem` gained `KemKind`,
     `KemPublicKey` and `KemSecretKey` — an enum over the same two `Kem` impls,
     every variant delegating rather than reimplementing. The trait stays the
     definition. A handshake learns its suite from a header field, so the
     parameter set genuinely *is* a value at that point and no amount of
     generics moves the decision earlier. `KemKind::for_public_key_len` is where
     a netmap or roster entry's class is inferred, and ML-KEM encodings are
     distinguished by length alone, so that one function is the whole
     suite-confusion defense.
   - **SHA-384.** `karst_crypto::hash` holds both suite hashes and the HKDF over
     them. The transcript stops being a `[u8; 64]` and becomes a `Digest`
     carrying its own length — a 48-byte transcript zero-padded to 64 would
     hash the padding, both ends would agree on it, and nobody would notice for
     years. Two SHA-512 uses stay fixed because both are computed before a suite
     is known: `peer_id_hint`, and the fragment MAC key (spec §13.9, new).
   - **The no-X25519 variant.** Steps 6, 10 and 11 of §7.1 are absent under a
     suite with `dh: None`, and `e_dh_pk` is absent from both messages rather
     than zero-filled — a placeholder both ends agree on and neither derives
     reads as a contribution in the transcript and is worth nothing in the key.
     A test changes the static X25519 keys and asserts a `KARST_3` session is
     unaffected while a `KARST_1` session is not, so the claim is checked in
     both directions.
   - **The three-fragment budget.** ADR-0004 recorded it; it is now exercised.
     A 3 210-byte `HandshakeInit` splits into three MTU-legal datagrams,
     MAC-verified and reassembled, and a second test drops each fragment in turn
     to confirm two of three do not complete. Nothing else about §5 changes —
     same header, same 1 208-byte bound, same reassembler. Three fragments is a
     count, not a different fragmentation.

   Two smaller things this surfaced:

   - **`respond` parsed variable-length fields before checking the floor.** It
     now resolves and accepts the suite before reading a single field whose
     length that suite decides. A refused suite costs nothing and cannot steer
     how the rest of the datagram is interpreted.
   - **`Engine` initiated at a hardcoded `KARST_1`**, which a Category 5 node
     cannot serve at all. It now initiates at its policy's floor. The floor
     rather than its strongest suite, because nothing tells a node which suites
     a *peer* accepts — the netmap carries no suite advertisement and there is
     no downgrade retry by design. So `KARST_2` is still only ever reached by
     answering a peer that chose it, never by choosing it; closing that needs a
     per-peer supported-suite list in the netmap, which is control-plane work.

   What this does **not** finish: the control channel and the netmap cache are
   still ML-KEM-768 and ChaCha20-Poly1305 (items 4's v2 row, and FINDINGS 53's
   third layer), and the Verifpal and ProVerif models now have a second key
   schedule to cover — the no-DH variant, where a missing contribution would be
   hardest to notice by reading.
2. **AES-256-GCM must be implemented.** It was named in the suite registry and
   implemented nowhere (FINDINGS 53); `karst-noise` hardcoded
   ChaCha20-Poly1305 for every suite. This was the single largest gap and the
   one that made the registry a statement of intent.

   **Data plane done, 2026-08-25.** `karst-crypto::aead` holds both algorithms
   behind one `Cipher`, chosen by `Algorithm::for_suite`, and `karst-noise`
   carries that choice on the `SymmetricState` from the moment the suite is
   known. The two share a 32-byte key, a 12-byte nonce and a 16-byte tag, which
   is what let one type dispatch between them without any caller changing —
   a property of these two algorithms rather than a guarantee, so `TAG_LEN`
   is a named constant and a third AEAD with a different tag size would break
   at it loudly.

   Three details worth keeping:

   - **`respond` now returns the suite it agreed to.** It was the one place
     that resolved a `SuiteId` and then discarded it, which was harmless while
     the AEAD was a constant and became a silent misconfiguration the moment it
     was not. The responder's transport is built from the returned value, not
     from a default.
   - **`KARST_2` is now in `Engine::new`'s `supported` list.** FINDINGS 53
     warned that adding it before the AEAD existed would be a one-line change
     making every crypto-posture report lie. The line is now safe to have made.
   - **A test asserts each registry row selects the AEAD it advertises**, and
     another that the two do not interoperate — so a ciphertext sealed under
     one cannot open under the other, which is what makes the negotiated suite
     decide something rather than label something.

   The control channel and the netmap cache still hardcode ChaCha20-Poly1305;
   the channel's suite mechanism is item 4 and its second suite waits on
   item 3.
3. **ML-KEM-1024 and ML-DSA-87 must be implemented.** Both are parameter
   changes to libraries already in the tree, and both change message sizes —
   ADR-0004's fragment budget already records that `KARST_3` needs three
   fragments rather than two, which is a real change to its loss and DoS
   behavior. **Done, 2026-08-25** (ML-DSA-87 under item 5).

   `karst_crypto::kem::MlKem1024Backend` implements the existing `Kem` trait.
   Go needed nothing: `crypto/mlkem` has carried both parameter sets all along.

   **Unlike the AEAD, this does not hide behind one runtime type.** The two
   parameter sets have different key and ciphertext sizes, so they are two
   impls of one trait selected at compile time rather than an enum. That is
   also why finishing this item does not make `KARST_3` reachable: `karst-noise`
   names ML-KEM-768 through a type alias, so `StaticKeys` and `PeerPublic` are
   Category 3 by construction. Dispatching per session is item 1's work, along
   with SHA-384 and the no-X25519 variant.

   Two things guard against that gap being mistaken for completeness:

   - **A registry test asserts every suite's KEM sizes are backed by a real
     implementation** — the mirror of the AEAD's. It deliberately claims less
     than "every suite runs", and says so where it is written.
   - **The Go and Rust registries' KEM sizes are now checked against the
     standard's own constants** (`crypto/mlkem`'s `EncapsulationKeySize1024`
     and so on) rather than typed in. A transposed digit in a suite nothing
     speaks yet has nothing else to catch it.

   Both parameter sets also refuse each other's keys and ciphertexts, in both
   directions and in both languages. ML-KEM encodings are distinguished by
   length alone, so the length check is the entire defense against a suite
   confusion, and it is worth a test rather than an assumption.
4. **The control channel needs a suite mechanism, or a build-time choice.**
   **Mechanism done, 2026-08-25; the second suite's primitives are items 2
   and 3.**

   A registry keyed by protocol version, mirrored in Go and Rust, plus a
   node-side floor. No negotiation: the data plane negotiates because two nodes
   configured by different people must agree, and a control channel is one
   operator's node talking to their own server — so negotiation would buy a
   downgrade surface and nothing else. The floor gives the property that
   mattered, which is that a server cannot talk a node down.

   Version 2 is reserved and unimplemented, so a floor set to it refuses every
   server at startup rather than falling back. That is the correct direction
   and it is why the version is reserved rather than omitted: "not implemented
   by this build" is actionable where "unknown version" is not.

   Pin sizes now come from the suite rather than from constants, which also
   catches pins and a configured version that disagree — a key's length is its
   algorithm.

   ADR-0011's construction hardcoded ML-KEM-768 and ChaCha20-Poly1305 with no
   mechanism at all around them. Its signature half moved to ML-DSA-87 under
   item 5, and that being possible without anything objecting is what made the
   registry worth building. The netmap cache (`karst-control-client/src/cache.rs`) has the same
   problem. ADR-0006's agility layer was designed for the data plane and stops
   at its edge.
5. **The relay identity and node identity move to ML-DSA-87** — Ponor's pinned
   `identity_key` and `node.Identity` alike. **Done, 2026-08-25.**

   This was the largest blast radius in the transition and it was done early on
   purpose: a node handle is a hash of its identity key, so every handle in the
   project changed with it — and handles index peer records, ACL rules, PSK pair
   derivation and Bedrock coverage. There is no rotation path; a deployed
   network would have had to re-enroll every node and re-countersign every one of
   them through the offline ceremony. **That was affordable exactly once, before
   anything shipped.**

   Two costs came out of it that the table above does not show. Ponor's
   handshake grew 39%, from 6 762 to 9 398 bytes, and its frame cap doubled to
   8 192 B — which is the bound a relay allocates against *before* authenticating
   anyone, so Category 5 costs twice the pre-authentication memory per
   connection. And the relay's connection future turned out to be two kilobytes
   from overflowing a stack (FINDINGS 58); the mandate did not cause that, it
   revealed it.
6. **CNSA 2.0 does not require the classical hybrid**, and the CNSA suite
   correctly has no DH component. ADR-0002's hybrid stays the default for
   everyone else; this ADR does not overturn it, it confines it.

7. **ChaCha20-Poly1305 is removed from the data plane, and the suite registry is
   renumbered.** Added 2026-08-25, after items 1–6 landed.

   **Done, 2026-08-25.**

   ChaCha20-Poly1305 is RFC 8439, an IETF specification. It is not a NIST
   algorithm, it is not FIPS 140-3 approved, and CNSA 2.0 does not name it —
   FINDINGS 53 established all of this when the question was still "does
   compliance matter?". Once the answer was "it is a mandate", a suite that no
   mandated deployment could select stopped paying for itself: it was a second
   AEAD code path, a second set of test vectors, a second thing for a suite to
   claim and not run, and a second answer to "which algorithm is this session
   using?" — for an audience that no longer exists in the deployments this
   project is being held to.

   The registry is now:

   | Wire | Name | Category |
   |---|---|---|
   | `0x0001` | `KARST_1_X25519_MLKEM768_MLDSA87_AES256GCM_SHA512` | 3 |
   | `0x0002` | `KARST_2_MLKEM1024_MLDSA87_AES256GCM_SHA384` | 5 |

   **The identifiers were reassigned, which a shipped registry must never do.**
   `0x0001` used to mean the ChaCha suite and now means what `0x0002` meant;
   `0x0002` used to mean the AES Category 3 suite and now means what `0x0003`
   meant. That is safe exactly once — before there is a deployed base, a
   captured packet or a published test vector to be incompatible with — and it
   is being spent here rather than left as a permanent gap at `0x0001` in a
   two-entry allowlist. `0x0003` is left unallocated rather than recycled again.

   The hazard this creates is documentary, not operational: every ADR, finding
   and spec section written before today that says `KARST_2` or `KARST_3` now
   names something else. It is handled by leaving those documents as written —
   they record decisions at a time — and putting the old→new mapping where a
   reader will hit it: `spec/phreatic-v1.md` §3.1 normatively, ADR-0006's suite
   table (which is where the numbering was decided), and the `karst-crypto`
   crate docs.

   **What this costs.** ADR-0001 chose ChaCha20-Poly1305 as the default because
   it is constant-time by construction and fast without AES-NI, which is what
   the hobbyist half of the audience runs. That reasoning was correct and it
   loses to a term ADR-0001 did not have to weigh. A node without AES-NI or
   ARMv8 crypto extensions now pays for AES-256-GCM in software. The cost is
   accepted knowingly; the alternative was carrying a suite unusable under the
   mandate.

   **What it does not touch.** The control channel and the netmap cache still
   run ChaCha20-Poly1305 — they have their own registry and reach the algorithm
   directly, not through `karst_crypto::aead`, which now has no ChaCha at all.
   That makes the control channel **the only place in the tree a mandated
   deployment is non-conformant**, and sharpens item 4's version 2 from a good
   idea into the last one. `spec/karst-control-v1.md` §3 now says so plainly
   rather than claiming to match PHREATIC's registry, which it no longer does.

   Two consequences worth stating because they read as regressions and are not:

   - **`aead::Algorithm` is a one-variant enum.** It stays an enum because
     `Algorithm::for_suite` is the mechanism that keeps a registry row from
     naming an AEAD nothing runs — the FINDINGS 53 defect — and that mechanism
     has to survive having one answer. Adding the next AEAD is a variant and a
     match arm.
   - **Two tests lost their subject.** "The two AEADs do not interoperate" and
     "a transport built for one suite cannot open the other's" both rested on
     there being two ciphers. The first is gone; the second was rewritten to
     rest on the *keys* instead, which is stronger — the two suites hash
     differently, so identical handshake inputs still derive different transport
     keys. `TransportSession` also lost its `new`/`with_aead` pair in favor of
     a single `for_suite`, removing the last constructor that could pick an
     AEAD independently of the suite the transcript bound.

**Karst does not become CNSA-only.** The mandate applies to deployments under
it, and `KARST_1` remains a Category 3 hybrid suite for everyone else — ADR-0002's
assumption-diversity hedge is intact. What item 7 removes is not the
non-mandated profile but the *choice of AEAD within it*. What changes overall is
that the compliant profile must actually exist, must be reachable by
configuration, and must be tested — not described.

### Alternatives rejected

> **Amendment, 2026-09-05.** [ADR-0018](0018-cnsa-2-0-as-the-sole-suite.md)
> reverses the alternative below: CNSA 2.0 is now the only deployment target,
> and the other PHREATIC suite and profile-selection mechanism are removed.
> The original rationale is retained to explain the decision at that time.

**Make CNSA 2.0 the only profile.** Simplest to reason about and wrong for the
audience ADR-0001 identified: it costs the non-AES-NI hardware a large constant
factor, and it discards the hybrid that ADR-0002 argued for on
assumption-diversity grounds for deployments under no mandate.

**Keep CNSA 2.0 in Phase 7 and treat the mandate as a later problem.** The
networking-equipment deadline is the earliest in the suite, and every item in
§Decision is a change to a wire format or a key size. Deferring means doing
them all at once, late, against a date.

**Declare compliance on the strength of the suite registry.** The registry
names two AES suites that do not exist. Nothing currently misreports only
because `Engine::new` offers `KARST_1` alone; adding `KARST_2` to that list
without implementing the AEAD would produce sessions claiming AES while running
ChaCha, which is worse than being visibly non-compliant.

---

## Bedrock's offline root — **decided: Option A, ML-DSA-87**

**Decision, 2026-08-25.** The root is ML-DSA-87. Assumption diversity is given
up rather than take on stateful keys held `k`-of-`n` on offline media, where SP
800-208's constraint against restoring a backup collides directly with §7's
recovery posture. The cost is real and is recorded in ADR-0014's supersession
notice and in `spec/bedrock-v1.md` §2: **a lattice break now takes the whole
hierarchy, recovery path included.**

Implemented the same day: both tiers are ML-DSA-87, `slh-dsa` and
`cloudflare/circl` are out of the tree, and the vectors are regenerated. Node,
server and relay identities followed in the same pass — see item 5.

The reasoning follows.

**SLH-DSA is not merely absent from CNSA 2.0. It is explicitly excluded.**

The FAQ carries a direct question — "Can I use SLH-DSA (aka SPHINCS+) to sign
software?" — and answers that although SLH-DSA is hash-based, **it is not part
of CNSA and is not approved for any use in NSS**. NSA further states it does not
plan to add future NIST post-quantum standards to CNSA, so waiting for FIPS 205
to be admitted is not a strategy.

ADR-0001 chose SLH-DSA-SHA2-192s for the root specifically *because it is not
lattice-based*: if lattice cryptography falls, the root of trust and the ability
to re-key the network survive. ADR-0014 built the two-tier hierarchy on that —
the rotatable ML-DSA authority tier is safe precisely because the roots above it
rest on different mathematics.

**The root must therefore change, and there is no reading in which it does
not.** Even the friendliest outcome would not preserve today's key: CNSA 2.0 is
Category 5 throughout and SLH-DSA-SHA2-192s is Category 3. The question is what
it becomes.

### Both candidates are compliant. The trade is diversity against statefulness.

| | Root becomes | Diversity | Cost |
|---|---|---|---|
| **A** | ML-DSA-87 | **Lost** — roots and authorities both lattice | None operationally; stateless, smaller signatures than today |
| **B** | LMS (SHA-256/192) | **Preserved** — hash-based | Stateful keys, and SP 800-208's constraints on backup |

This is a sharper choice than "no clean answer". LMS *is* approved and *is*
hash-based, so option B satisfies the mandate **and** keeps ADR-0001's property.

**What makes B harder than it looks, and less hard than it first appears.**
LMS is stateful: each one-time key index must be used exactly once, and reuse
is catastrophic. That collides directly with §7's "at least one printed as a
paper backup" — a paper backup of a stateful key is a snapshot of its state,
and restoring it after further signing reuses indices. NSA also prohibits the
multi-tree variants HSS and XMSS^MT, so a single tree's capacity is a hard cap.

Against that: Bedrock roots sign a *handful* of times in a deployment's life,
so capacity is a non-issue at any sane tree size. And `k`-of-`n` here means `n`
**independent keys**, not one key shared among `n` holders — so the state
coordination problem NSA warns about for "distributed signing environments"
does not arise. What remains is genuinely just the backup posture: with
`n >= 3` and `k = 2`, "never back a root up, and accept that a lost root is
lost" is a coherent and arguably better answer than a root key sitting in a
drawer.

**Option C, requiring both an ML-DSA-87 and an SLH-DSA signature on root
operations, is probably not available.** It would preserve diversity while
resting authorization on the approved algorithm, and it has some precedent in
NSA's tolerance of hybrid key exchange. But "not approved for **any** use in
NSS" reads as a prohibition on use rather than on reliance, and reading it
otherwise is not a call to make without the accreditor.

### Two things worth knowing before deciding

**NSA's own guidance points at A for this shape of deployment.** The FAQ says
ML-DSA-87 may be reasonable for software and firmware signing "when a signing
strategy requires more signatures than a single LMS or XMSS key can reasonably
support, or in distributed signing environments". Bedrock's roots are the
latter, if `k`-of-`n` is read as distributed signing.

**The exclusion appears to be policy, not cryptanalysis.** Discussion on the
NIST PQC forum reads the SLH-DSA entry as an interoperability and
transition-complexity decision rather than a security judgment — NSA's stated
reasoning elsewhere in the same FAQ is that more algorithms make interoperability
harder. Germany's BSI takes the opposite position and recommends SLH-DSA
explicitly as a hedge against lattice weaknesses, which is the argument
ADR-0001 made. **Karst's original design agrees with BSI and conflicts with
NSA.** A deployment answering to both has a real conflict, and it is not a
technical one.

**Still a decision for whoever owns the accreditation**, on two points this ADR
cannot settle: whether the root is in scope at all, and whether B's stateful
key handling is acceptable to them. The engineering trade above is the input to
that, not a substitute for it.

---

## Consequences

### Positive

- The compliant profile becomes real rather than described, and the agility
  layer gets the exercise ADR-0006 said it needed.
- SHA-512 already satisfies the hash requirement, so the KDF and the transcript
  need no change.
- `KARST_3` already exists in the registry with the right parameters, and the
  negotiation, downgrade protection and transcript binding are all built and
  tested. Only the primitives are missing.

### Negative

- **This is a large amount of unscheduled work**, and every item is a wire
  format or a key size: the netmap grows, the handshake grows past two
  fragments, the relay registry grows, the Bedrock log grows.
- **The control channel and the cache have no agility mechanism at all**, so
  each needs one designed rather than extended. This is the half nobody has
  looked at.
- **Bedrock's root question above is unresolved and blocks nothing today, which
  is exactly how it gets discovered late.**
- ADR-0001's Category 3 default, ADR-0002's hybrid, and ADR-0006's "none is
  urgent" all now carry a caveat they did not have.
- **Item 7 spends the one free renumbering this project will ever have.** The
  registry can be reshaped without cost only while nothing speaks it. After the
  first release, a suite can be deprecated but its identifier can never be
  reused, and a mistake in the two rows above becomes permanent. Anyone adding
  a third row should assume that constraint is already in force.
- **A node without AES-NI now pays for AES-256-GCM in software**, which is the
  cost ADR-0001 chose ChaCha20-Poly1305 to avoid. The hobbyist audience is not
  gone, only no longer given a separate cipher.
- **The control channel is now the only non-conformant component**, which is
  clarifying but also means the last of this work has no other item to hide
  behind.

### Reconsider if

- The mandate is scoped to a subset of deployments rather than all of them, in
  which case the profile matters but the defaults do not move.
- NSA adds SLH-DSA to CNSA 2.0, which would resolve §"What is unresolved"
  entirely and in the direction the existing design already took.
