# ADR-0002: Hybrid key agreement, but not hybrid signatures

- **Status:** Superseded by ADR-0018
- **Date:** 2026-08-09
- **Deciders:** TBD
- **Related:** ADR-0001 (algorithm selection), ADR-0004 (PSK hedge), ADR-0006 (agility layer)

---

## Context

> **Superseded, 2026-09-05.** [ADR-0018](0018-cnsa-2-0-as-the-sole-suite.md) makes CNSA 2.0 the sole PHREATIC suite and removes all application DH keys. This ADR is retained as the historical rationale for the former hybrid.

Having chosen ML-KEM-768 and ML-DSA-65 (ADR-0001), a separate question follows:
should classical algorithms be combined with them, or should Karst be
post-quantum *only*?

The question is genuinely contested. NSA's CNSA 2.0 guidance does **not**
require hybrid constructions and has expressed the view that they add
complexity without proportionate benefit. The counter-position, dominant in
the TLS ecosystem's `X25519MLKEM768` deployment, is that lattice cryptography
is young and a hybrid costs almost nothing.

The relevant evidence is that ML-KEM's *implementations* have already had
serious problems even though the *algorithm* has held: the KyberSlash timing
vulnerabilities (disclosed late 2023/early 2024) came from non-constant-time
division in widely-used reference code. The primitive was fine; the deployment
was not.

---

## Decision

**Hybrid for key agreement. Not hybrid for signatures.**

### Key agreement: X25519 + ML-KEM-768

Both shared secrets are mixed into the same HKDF chain, along with the
transcript hash and the per-pair PSK (ADR-0004). The construction must be such
that the session key is secure if **either** input is secure — neither may be
able to determine the output alone.

Cost: 32 bytes of public key and roughly 50 µs of X25519 per handshake, against
a message already 2378 bytes and a KEM operation already dominating. The
insurance is close to free.

What it protects against, precisely:

- A cryptanalytic break of ML-KEM → X25519 still protects against classical
  adversaries.
- An implementation flaw in our ML-KEM backend (the KyberSlash scenario) →
  same.
- A break of X25519 by a quantum adversary → ML-KEM protects, which is the
  entire point of the project.

### Signatures: ML-DSA-65 alone, with an SLH-DSA root

No classical signature is combined with ML-DSA. The reasoning is an asymmetry
that is easy to miss:

**Signatures cannot be broken retroactively.** A recorded session can be
decrypted years later once the KEM falls — that is the harvest-now-decrypt-later
threat, and it is why confidentiality needs hybrid protection *today*. But
forging a signature requires breaking the scheme *while the signature is still
being relied upon*. There is no stockpiling attack against authentication.

So the deadline that justifies hybrid key agreement does not exist for
signatures, and the costs are higher: hybrid signatures would roughly double
sizes on the Bedrock chain, which already carries 3309-byte ML-DSA signatures
and 16224-byte SLH-DSA root signatures.

Diversity for authentication is instead provided **vertically**: the offline
root uses SLH-DSA, whose security rests on hash functions rather than lattices
(ADR-0001). If ML-DSA falls, the root of trust survives and can re-key the
network. That is a stronger guarantee than a classical co-signature, which
would itself be broken by the quantum adversary we are defending against.

### Three independent hedges, by design

| Layer | Mechanism | Survives |
|---|---|---|
| Key agreement | X25519 hybrid | Classical break of ML-KEM |
| Key agreement | Per-pair PSK (ADR-0004) | Quantum break of ML-KEM, absent server compromise |
| Authentication | SLH-DSA offline root | Break of ML-DSA |

### Downgrade protection

The negotiated suite identifier is bound into the transcript hash, so an
attacker cannot strip the classical or PQ half of the hybrid without
invalidating the handshake. The control server publishes a minimum acceptable
suite that nodes enforce locally (ADR-0006).

### Sunset

Hybrid is often framed as transitional. **Karst keeps it for v1 and sets no
sunset date.** Removing X25519 later is a suite-registry change through the
agility layer, requiring no protocol revision. Given no customer mandate and no
deadline (Q6), there is no reason to shed the insurance early.

---

## Consequences

### Positive

- No single algorithm's failure — by cryptanalysis *or* by implementation
  bug — breaks session confidentiality.
- Aligns with the `X25519MLKEM768` construction the wider ecosystem is
  deploying and reviewing.
- Signature sizes stay as small as post-quantum allows, which matters on the
  Bedrock path.

### Negative

- **Diverges from CNSA 2.0 guidance**, which does not call for hybrid. A
  customer under a strict CNSA reading might require PQ-only; the agility layer
  makes that a suite selection rather than a fork. Recorded here so the
  divergence is deliberate and visible.
- Two key-agreement code paths to implement, test and review.
- The "secure if either holds" property is a real proof obligation, not an
  assumption — it must be discharged in the Verifpal and ProVerif models
  (PLAN.md §2.5), not asserted.
