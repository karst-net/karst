# ADR-0006: Cryptographic agility layer

- **Status:** Accepted
- **Date:** 2026-08-09
- **Deciders:** TBD
- **Related:** ADR-0001 (algorithm selection), ADR-0002 (hybrid), ADR-0004 (out-of-band KEM profile), PLAN.md §1.2, §8.1

---

## Context

Karst's algorithm choices will not survive the life of the project. Four
foreseeable changes:

1. **CNSA 2.0 alignment** — ML-KEM-1024, ML-DSA-87, AES-256-GCM, SHA-384.
2. **A lattice cryptanalytic advance** — needing a fast swap under pressure.
3. **The out-of-band-key profile** from ADR-0004 (Classic McEliece static).
4. **Retiring X25519** if hybrid is eventually judged unnecessary (ADR-0002).

None is urgent. Q6 established no customer under a CNSA mandate and no
deadline. But retrofitting agility into a deployed protocol is far harder than
building it in, and the migration mechanics are what actually take time — not
the algorithm swap itself.

There is a strong counter-pressure. Cryptographic agility has a bad safety
record: TLS's cipher-suite proliferation enabled FREAK and Logjam, and JWT's
`alg` field produced the `alg: none` catastrophe. **Agility mechanisms are
themselves attack surface.** The design problem is getting migration ability
without building a negotiation system an attacker can drive.

---

## Decision

Build a **narrow, closed agility layer**. Explicitly *not* a crypto plugin
system.

### Suite registry

- Algorithms are selected only as a **complete, named suite** — never
  negotiated per-primitive. A suite fixes KEM, signature, AEAD and hash
  together.
- Suites are identified by a small integer from a **fixed allowlist compiled
  into `karst-crypto`**. There is no runtime-extensible registry, no algorithm
  OIDs on the wire, no user-supplied parameters.
- Unknown suite IDs are rejected, not negotiated around.

This is the primary defence against the TLS/JWT failure mode: an attacker
cannot express a weak combination because weak combinations have no
representation.

### Suites at v1

| ID | Name | Contents |
|---|---|---|
| 1 | `KARST_1_X25519_MLKEM768_MLDSA65_CHACHA20_SHA512` | Default (ADR-0001) |
| 2 | `KARST_2_X25519_MLKEM768_MLDSA65_AES256GCM_SHA512` | AES-NI hardware |
| 3 | `KARST_3_MLKEM1024_MLDSA87_AES256GCM_SHA384` | CNSA 2.0 profile, PQ-only |

Suite 3 is defined now and implemented in Phase 7. Defining it early forces
the layer to be genuinely general rather than accidentally shaped around
suite 1.

### Downgrade protection

- The suite ID is **bound into the transcript hash**, so stripping or
  substituting it invalidates the handshake.
- The control server publishes a **minimum acceptable suite** in the netmap;
  nodes enforce it locally and refuse anything below it. Enforcement is at the
  node, not the server — a compromised server can raise the floor but not
  lower it below what nodes have already accepted.
- Nodes advertise supported suites in the netmap; initiators select the
  highest mutually supported.
- Every session's negotiated suite is reported to the console's **crypto
  posture view** (§8.1), which is the operator-facing half of this mechanism.
  An agility layer whose state cannot be observed is not manageable.

### Trait design

- `Kem`, `Signature`, `Aead`, `Hash` traits in `karst-crypto`, with the suite
  registry mapping IDs to concrete implementations.
- `Kem` carries `KEY_DISTRIBUTION: InBand | OutOfBand` (ADR-0004), so the
  handshake codec branches on whether a public key travels in the message.
  This is what keeps the Classic McEliece profile reachable without shipping
  it.
- Backend selection (`libcrux-ml-kem` ↔ `aws-lc-rs`) is a build-time feature,
  not a runtime negotiation — implementation choice is an operator decision,
  not an attacker-influenceable one.

### Key storage

All persisted key material carries an **algorithm tag**. Keys are never stored
as bare bytes whose interpretation depends on context — that assumption is what
makes migrations dangerous.

### Migration mechanics

The part that actually needs designing:

1. Operator raises the *supported* set on the control server; new suite is
   distributed via netmap.
2. Nodes upgrade at their own pace, advertising both old and new.
3. Once telemetry in the crypto posture view shows universal support, the
   operator raises the *minimum* suite.
4. Nodes refuse the old suite; stragglers fail closed and are visible in the
   console.

The rollback path is symmetric, and lowering the minimum requires an explicit
operator action that is recorded in the audit log.

**Migration must be a configuration change plus a rolling restart — never a
protocol revision.** Phase 7 validates this by shipping suite 3 through the
mechanism rather than by patching.

---

## Consequences

### Positive

- CNSA 2.0, Category 5, and PQ-only are configuration outcomes rather than
  forks.
- A cryptanalytic emergency has a rehearsed path rather than an improvised one.
- The out-of-band-KEM profile stays reachable without being built.
- Operators can see the cryptographic state of their network, which is the
  product's central claim made observable.

### Negative

- Suites multiply the protocol test matrix. Every suite needs its own KATs,
  fuzz targets, and interop tests, and the migration path needs testing in both
  directions.
- Defining suite 3 before implementing it risks it being wrong in ways only
  discovered in Phase 7.
- Agility is itself attack surface. The closed-allowlist design mitigates this
  but does not eliminate it, and the negotiation logic belongs in the ProVerif
  model (§2.5) alongside the handshake — **including the downgrade case**.

### Anti-goals, recorded explicitly

- No runtime-pluggable algorithms.
- No per-primitive negotiation.
- No suite defined outside the compiled allowlist.
- No "flexible" or operator-defined parameter sets.

If a future contributor proposes any of these as a feature, this section is the
answer.
