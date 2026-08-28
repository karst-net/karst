<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-0014: Bedrock trust hierarchy

> **Superseded in part, 2026-08-25, by [ADR-0015](0015-cnsa-2-0-as-a-mandate.md).**
> CNSA 2.0 became a mandate and excludes SLH-DSA — "not approved for any use in
> NSS". **The root tier is now ML-DSA-87, not SLH-DSA-SHA2-192s**, and the
> authority tier moves from ML-DSA-65 to ML-DSA-87 with it.
>
> Everything below about *why* the tiers are split, why signatures are
> domain-separated per tier, why signing is deterministic, and why signer
> indices beat repeating public keys still holds. What no longer holds is this
> ADR's central claim: **the hash-based root is gone, so a lattice break now
> takes the entire hierarchy including the recovery path.** The cost analysis
> that argued the authority tier could safely be lattice-based *because the
> roots were not* has lost its premise.
>
> The one paragraph worth re-reading in that light is the domain-separation
> rule — "even though the algorithms differ today … they will not always
> differ". They no longer differ, and those context strings are now the only
> thing keeping a root signature from being an authority signature.

- **Status:** Accepted, superseded in part by ADR-0015
- **Date:** 2026-08-25
- **Deciders:** TBD
- **Related:** ADR-0001 (algorithm selection), ADR-0006 (agility layer), ADR-0011 (control-channel authentication), `spec/bedrock-v1.md`, PLAN.md §4.5

---

## Context

ADR-0001 specifies **SLH-DSA-SHA2-192s** for "the offline root (Bedrock)" and
says nothing about the tier beneath it. Bedrock needs two signing tiers, not
one: offline roots that authorise *who may countersign*, and online-ish
authorities that actually countersign each node as it enrols.

Leaving the second tier unstated is not a neutral omission. The next reader
assumes the omission means SLH-DSA throughout, and the sizes make that a
material decision rather than a detail.

**The numbers that decide it.** An authority signature is produced every time a
node enrols and travels in the replicated log to every node in the network.

| | SLH-DSA-SHA2-192s | ML-DSA-65 |
|---|---|---|
| Public key | 48 B | 1 952 B |
| Signature | **16 224 B** | **3 309 B** |
| Per node-sign at `q = 3` | 48 KB | 10 KB |
| 1 000-node network's log | **48 MB** | **10 MB** |

Every node replicates and verifies that log in full. 48 MB of signatures on a
mechanism whose entire purpose is to be verified by resource-constrained nodes
is a cost with nothing bought by it.

The opposing force is assumption diversity, and it is why ADR-0001 chose a
hash-based root in the first place: if lattice cryptography falls, it takes
ML-KEM and ML-DSA together, and the ability to re-key the network must survive
that.

---

## Decision

**Three tiers, two algorithms.**

| Tier | Algorithm | Where the key lives | Signs |
|---|---|---|---|
| Root | SLH-DSA-SHA2-192s | Offline media or hardware token, `k`-of-`n` | The authority list, and nothing else |
| Authority | ML-DSA-65 | Admin devices; a subset offline | Node countersignatures, revocations, quorum changes, anchors |
| Node | ML-DSA-65 | The node's keystore | Nothing in Bedrock — it is the subject, not a signer |

**The authority tier is lattice-based, and that is safe because it is
rotatable.** If lattices fall, the roots — which are *not* lattice-based — sign
a new authority list under whatever replaces ML-DSA. The hash-based anchor sits
exactly where it must and nowhere it is expensive. The property ADR-0001 bought
is preserved in full: the recovery path from a lattice break never depends on a
lattice.

**Signatures are domain-separated by tier**, under `"karst-bedrock-v1 root"`
and `"karst-bedrock-v1 authority"`, following `identity.ControlContext`'s
precedent. A root signature must never be a valid authority signature and vice
versa. This is specified rather than left to the algorithm split precisely
*because* the authority tier is rotatable: the day it rotates, the algorithms
may coincide, and by then the separation must already exist.

**Signing is deterministic in both tiers**, departing from the hedged signing
`identity.go` uses for the control channel. A control-channel key signs
continuously on a networked server, where faults can be induced without holding
the machine; a Bedrock key signs a handful of times during a deliberate
ceremony on a machine with no network interface, so a fault attack requires
physical possession — at which point the key itself is available and the fault
buys the attacker nothing. Determinism buys reproducibility in exchange: a
second admin can re-run a ceremony and compare bytes, which is the only
practical check that the bundle an admin signed is the bundle they were shown.

### Implementation

Verified against the pinned toolchain rather than assumed:

- **Go, root tier: `cloudflare/circl` v1.6.5.** `identity.go` predicted this
  ("it will come back for Bedrock"). Confirmed: go1.27rc3 ships `crypto/mldsa`
  but has **no `crypto/slhdsa`**, and no `crypto/internal/fips140/slhdsa`
  either — there is not even an internal implementation awaiting export. circl
  is BSD-3-Clause, already on the allowlist, ACVP-tested, and wrapped thinly in
  `bedrock/sign.go` so the swap is one file when the standard library catches
  up.
- **Go, authority tier: `crypto/mldsa`.** No new dependency.
- **Rust, both tiers: RustCrypto `slh-dsa` and `ml-dsa`**, `MIT OR Apache-2.0`.

**`slh-dsa` is pinned to `=0.2.0-rc.5`, a release candidate, and that is the
correct choice rather than a concession.** A stable `0.1.0` exists and is the
worse option: it pins `hybrid-array 0.2.0-rc.8` and `signature 2.3.0-pre.4`,
which would put a second incompatible copy of both crates in a workspace where
`ml-dsa 0.1` already uses `hybrid-array 0.4` and `signature 3` — and it does
not compile against the current registry, because the pre-release dependencies
it names have since moved. `0.2.0-rc.5` resolves onto exactly the versions
`ml-dsa` already uses. The exact pin also satisfies `deny.toml`'s
`wildcards = "deny"`. Revisit when `slh-dsa` 0.2.0 is released.

**Cross-implementation agreement was measured, not assumed.** circl and
RustCrypto produce byte-identical public keys from the same private key bytes
and **byte-identical deterministic signatures** over the same message and
context. That is a stronger result than mutual verification, and it is why
`spec/vectors/bedrock-v1.json` pins exact signature bytes: a vector that only
asserts "both implementations verify this" still passes when one side signs the
wrong message under the right key.

### Alternatives rejected

**SLH-DSA for the authority tier as well.** The 48 MB figure above. It also
buys less than it appears to: a network whose authority tier is unrotatable is
*harder* to recover from a lattice break, not easier, because there is then no
cheap tier to rotate.

**ML-DSA for the root tier as well.** Discards the assumption diversity that is
ADR-0001's stated reason for choosing SLH-DSA at all, and does so at the one
place in the system where cost genuinely does not matter — roots sign a handful
of times in the lifetime of a deployment.

**A threshold signature scheme instead of `k`-of-`n` separate signatures.**
Smaller on the wire and considerably harder to verify, audit, and implement
twice. `k` separate signatures are inspectable by a human reading the log.

**Public keys in each signature rather than an index into the active list.**
1 948 bytes per signature to re-state something the log already says.

---

## Consequences

### Positive

- The hash-based root survives a lattice break, and the expensive algorithm is
  confined to the tier that signs rarest.
- A thousand-node log is ~10 MB rather than ~48 MB, which keeps full
  replication and verification viable on the constrained nodes that are half
  the audience (ADR-0001's Q6 framing).
- The Go SLH-DSA dependency is one file wide and marked for deletion.
- Deterministic signing makes ceremonies reproducible and makes the shared
  vectors able to pin signature bytes.

### Negative

- **Two signature algorithms in the verification path**, in two languages —
  four implementations that must agree. The mitigation is the shared vectors,
  and the measured byte-identical agreement above is what makes those vectors
  strong enough to be worth having.
- **circl returns to the Go module** after `identity.go` removed it. This was
  anticipated and is confined to the root tier, but the module now carries a
  post-quantum signature dependency the standard library does not yet provide.
- **A release-candidate dependency sits in a fail-closed crypto path.** Argued
  above as the lesser evil; it is still a pre-1.0 crate, and the pin must be
  revisited when 0.2.0 ships.
- **Root keys cannot be rotated** (`spec/bedrock-v1.md` §9). Losing `k` of `n`
  roots is unrecoverable **by design** — a recovery path would be a bypass —
  and this is the sentence a future reader most needs: *if you lose your roots,
  the network lock can never be disabled and no new node can ever be added.*

### Reconsider if

- `crypto/slhdsa` lands in the Go standard library — delete the circl wrapper.
- A deployment needs root rotation badly enough to accept the added surface.
- Lattice cryptography is broken, at which point this ADR's central bet is
  called and the roots sign a new authority list under its replacement.
- Log size becomes a problem at a scale ML-DSA does not solve, at which point
  the answer is log compaction, not a smaller signature.
