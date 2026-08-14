# ADR-0009: Fork NetBird for the control plane; keep the datapath greenfield

- **Status:** Accepted — spike substantially reported, see
  [Spike 0001](../spikes/0001-netbird-fork-evaluation.md). No abort criterion
  tripped. Two amendments below under **Spike outcome**; the running vertical
  slice remains outstanding.
- **Date:** 2026-08-09
- **Deciders:** TBD
- **Related:** ADR-0003 (greenfield rationale — scope narrowed by this ADR), ADR-0007 (licensing), PLAN.md §4, §8, §10

---

## Context

The OBJECTIVE has two halves: a post-quantum Tailscale, **and** administrative
and user-management applications. The plan currently builds both from scratch.

ADR-0003 chose a greenfield Rust implementation. Its reasoning was that a PQ
handshake breaks WireGuard's single-datagram, stateless-responder framing
(quantified in ADR-0004: 2.4 KB messages against a 148-byte original). **That
argument is about the datapath.** It says nothing about the coordination
server, the ACL model, SSO integration, or the admin console — and it was
applied more broadly than it supported.

Reviewing the field for prior art surfaced two projects:

- **ThreeFold Mycelium** — Apache-2.0, Rust, but a Yggdrasil-style *public
  routed overlay* with crypto-derived `400::/7` addresses, no control plane, no
  per-node access control (its "private network" mode is one PSK for the whole
  network), no user management, and no post-quantum cryptography
  (`x25519-dalek`, `aes-gcm`, `blake3`). Wrong product category; rejected as a
  base. It does, however, own the name — see §Naming below.
- **NetBird** — BSD-3, self-host-first, **Go backend with a React console**,
  which is precisely the stack chosen for this project. It already ships a
  management server, admin console, OIDC/SSO (Zitadel default, any OIDC IdP),
  identity-based ACLs, MagicDNS-equivalent DNS, posture checks, activity logs,
  and a relay with QUIC fallback plus coturn STUN/TURN.

NetBird covers a substantial share of PLAN.md §4 and §8 — the half of the
OBJECTIVE that is *not* differentiated by post-quantum cryptography, and
therefore the half where building from scratch buys the least.

---

## Decision

**Split the build along the line where differentiation actually lies.**

| Layer | Approach | Rationale |
|---|---|---|
| Datapath, handshake, crypto, relay, disco | **Greenfield Rust**, as decided | ADR-0003's reasoning holds here and only here |
| Coordination server, ACL model, IdP/SCIM, console, portal, audit | **Fork NetBird** | Undifferentiated by PQ; already built in our exact stack |
| Bedrock, crypto posture, netmap PSK schedule | **Net new** | No upstream counterpart |

### What actually transfers

The management server, admin console, OIDC/SCIM integration, ACL data model
and evaluator, DNS configuration management, and activity log.

### What does not

Be clear-eyed about this — it is more than it first appears:

- **Their clients do not transfer.** NetBird's agent is Go and wraps WireGuard.
  Our datapath is Rust speaking PHREATIC. The client is a rewrite, which we were
  doing anyway.
- **Their identity model assumes 32-byte WireGuard keys.** Ours are ML-KEM-768
  (1184 B) and ML-DSA-65 (1952 B) plus a `peer_id_hint` (ADR-0005). This
  ripples through the schema, the API surface, and the console.
- **Netmap extension is net new:** per-pair PSKs and epochs (§2.6), the
  compiled packet filter, relay and TURN credential distribution (ADR-0008).
- **Bedrock has no counterpart** (§4.5). Quorum signing, the hash-chained
  log, and client-side enforcement are entirely new.
- **The crypto posture view** (§8.1) is new, and it is the product's central
  claim.

PQ on the Go side is feasible: `crypto/mlkem` is in the Go standard library as
of 1.24, and ML-DSA is available via Cloudflare CIRCL.

### Licensing: resolving the collision with ADR-0007

NetBird is BSD-3; ADR-0007 chose AGPL-3.0-or-later for our control server. BSD-3
is one-way compatible with AGPL, so distributing the combined work under AGPL
is permitted provided BSD-3 notices are retained. But relicensing a permissive
project's work under copyleft, and then being unable to give anything back, is
exactly the behaviour ADR-0008 rejected in another context.

**Policy:** we distribute the combined server under AGPL-3.0-or-later as
planned, **and we offer our own contributions upstream under BSD-3.** We own
our changes and may license them twice; nothing prevents contributing a fix to
NetBird under their licence while distributing our fork under ours. Generic
improvements — bug fixes, IdP integrations, performance, accessibility — are
offered upstream by default. PQ-specific work is ours and stays ours.

This is recorded as an obligation, not an aspiration: **"did we upstream what
was generically useful?" is a release-checklist item.**

### Attribution

The fork is disclosed prominently in `README`, `LICENSING.md`, and the console's
about screen. We do not describe the control plane as built from scratch.

---

## Decision Gate

This ADR is **conditional**. Fork-and-adapt is worth it only if adaptation
costs materially less than greenfield; forks that fight upstream's data model
routinely cost more than a rewrite while also incurring a permanent rebase tax.

**Timeboxed 3-week spike in Phase 0**, producing:

1. A schema diff for PQ-sized identities against NetBird's peer model.
2. A working vertical slice: one Rust node registering against a forked
   management server with an ML-DSA identity, receiving a netmap.
3. An estimate of console rework for the crypto posture and Lock views.
4. A measured rebase-tax estimate from replaying 6 months of upstream commits
   against the adaptation.

**Abort criteria — return to greenfield §4/§8 if any hold:**

- Adaptation is estimated above **60%** of the greenfield build cost.
- The identity-size change requires touching more than ~30% of upstream files.
- Upstream's release cadence makes the rebase tax exceed roughly one
  engineer-week per month.

### Honest estimate, pending the spike

Greenfield §4 + §8 is Phase 3 (8 weeks) plus most of Phase 5 (10 weeks) on the
critical path. Fork-and-adapt plausibly removes **8–12 weeks**, not the full
18 — schema and identity migration, netmap extension, console adaptation, and
the Rust management-protocol client together consume much of the saving.

Anyone quoting "half the plan is already built" is misreading it. The saving is
real and worth pursuing; it is not transformative.

---

## Consequences

### Positive

- Removes the least-differentiated work from the critical path.
- Inherits a matured ACL model, IdP integration surface, and console —
  categories where subtle design errors are expensive and slow to discover.
- Effort concentrates on the PQ protocol, which is the actual product.

### Negative

- **Permanent upstream divergence tax.** Every rebase carries risk, and PQ
  identity sizes touch the data model broadly.
- Inheriting someone else's data model constrains the Lock and netmap designs
  in ways not yet fully known — the spike exists to bound this.
- A security product now depends on an external codebase's security posture.
  NetBird enters the dependency review cycle (§11) as a first-class component,
  not a library.
- Two licences and two provenance stories to explain clearly to users.

### Spike outcome — two amendments

Measured against `netbirdio/netbird` @ `f65f7b34` (v0.76.3);
see [Spike 0001](../spikes/0001-netbird-fork-evaluation.md) §5.

**1. Fork-and-diverge, not fork-and-track.** 173 of 609 upstream commits in six
months (**28%**) touch the 24 files where our identity spine diverges, with
+20,437/−3,462 lines of churn. Continuously tracking that is expensive and the
benefit is uncertain, since most of it lands on code we will have rewritten.
Fork once at a known tag; cherry-pick **security fixes only**, deliberately.

Two consequences recorded above therefore change:

- "Inherits a matured ACL model and IdP integration surface" is a **one-time**
  benefit, not an ongoing one.
- "NetBird enters the dependency review cycle" becomes **stronger**: under
  fork-and-diverge we are the only party patching our copy.

**2. Delta netmap push is new work that this ADR did not cost.** NetBird pushes
**full** network maps — it optimises fan-out, not payload. At Karst's ~3200 B
per peer (32 B hint + 1184 B ML-KEM + 1952 B ML-DSA + 32 B PSK, roughly 100×
NetBird's 32-byte WireGuard key), a 1,000-peer tailnet would push 3.2 MB to
every notified peer on every membership change. Delta push must be built.

The risk profile also **inverted** against prediction: the identity refactor is
small and localised (24 of 1403 files, **1.7%**, against a 30% threshold),
while the ongoing divergence cost is the real exposure.

Net effect on the estimate: **unchanged at 8–12 weeks**, with composition
shifted — cheaper refactor, new delta-push work, rebase tax largely eliminated
by diverging rather than tracking.

### Naming

This ADR's review of prior art settled PLAN.md §13 Q5. ThreeFold's daemon
binary is literally `myceliumd` — identical to the name this project originally
used, in the same category and the same language. The project was renamed to
**Karst** as a result; see
[ADR-0010](0010-project-name-and-component-naming.md).
