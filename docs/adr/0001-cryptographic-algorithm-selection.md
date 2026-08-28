# ADR-0001: Cryptographic algorithm selection

- **Status:** Accepted
- **Date:** 2026-08-09
- **Deciders:** TBD
- **Related:** ADR-0002 (hybrid rationale), ADR-0004 (MTU strategy), ADR-0006 (agility layer), PLAN.md §1.2

---

> **Amended 2026-08-25 by [ADR-0015](0015-cnsa-2-0-as-a-mandate.md): CNSA 2.0
> is now a mandate.** The Context below rests on PLAN.md §13 Q6's original
> answer — no CNSA mandate, no compliance date — and that answer has been
> overturned. The algorithm table and the reasoning for each choice stand for
> deployments under no mandate; the Category 3 default, the ChaCha20-Poly1305
> default and the "Category 5 is reachable through the agility layer" framing
> all now carry ADR-0015's caveat. **ADR-0015 also opens a question this ADR
> cannot answer: SLH-DSA is not in CNSA 2.0, so the offline root's
> assumption-diversity property and CNSA compliance may be in direct
> conflict.**
>
> **Further superseded the same day by [ADR-0015](0015-cnsa-2-0-as-a-mandate.md)
> item 7: ChaCha20-Poly1305 is gone from the data plane.** The reasoning below
> for choosing it — constant-time by construction, fast without AES-NI — was
> and is correct on its own terms, and it lost to a term this ADR did not have
> to weigh: it is not a NIST algorithm, so no deployment under a mandate could
> ever select the suite it was in. AES-256-GCM is the only data-plane AEAD.
> The software-AES cost this ADR was avoiding is now paid by any node without
> AES-NI or ARMv8 crypto extensions, knowingly. ChaCha20-Poly1305 survives only
> on the control channel, which item 4's version 2 will also move.

## Context

Karst's premise is that every long-term cryptographic dependency is
post-quantum. The driving threat is **harvest-now-decrypt-later**: traffic
captured today and decrypted once a cryptanalytically-relevant quantum computer
exists (PLAN.md §1.1).

NIST finalised the core standards in August 2024 — FIPS 203 (ML-KEM), FIPS 204
(ML-DSA), FIPS 205 (SLH-DSA) — which makes this a selection problem rather than
a research problem. The task is choosing parameter sets and filling the gaps
the standards do not cover.

The audience is **hobbyists and security-minded commercial organisations**
(PLAN.md §13 Q6), with no identified CNSA 2.0 mandate and no compliance
deadline. That pushes toward defaults that are safe without a security team and
performant on modest hardware, with stronger parameters available through the
agility layer rather than imposed on everyone.

---

## Decision

| Purpose | Algorithm | Sizes | Category |
|---|---|---|---|
| Session key agreement | **X25519 + ML-KEM-768** (hybrid) | X25519 pk 32 B; ML-KEM pk 1184 B, ct 1088 B | 3 |
| Node identity signing | **ML-DSA-65** | pk 1952 B, sig 3309 B | 3 |
| Offline root (Bedrock) | **SLH-DSA-SHA2-192s** | pk 48 B, sig 16224 B | 3 |
| Assumption-diversity hedge | **Per-pair PSK** | 32 B | — |
| Data-plane AEAD | **ChaCha20-Poly1305** default, **AES-256-GCM** option | 256-bit key | — |
| Hash / KDF | **SHA-512 / HKDF-SHA-512** | 512-bit | — |
| Control-channel transport | **TLS 1.3 with `X25519MLKEM768`** | — | 3 |

Everything targets **NIST Category 3** (~AES-192 equivalent). Category 5
parameters are reachable through the agility layer (ADR-0006), not shipped as
the default.

### Correction to the original plan: SLH-DSA parameter set

PLAN.md originally specified **SLH-DSA-SHA2-128s** (Category 1) for the offline
root, while everything beneath it is Category 3. That inverts the trust
hierarchy: the root of trust would have been the *weakest* link in the system.

Corrected to **SLH-DSA-SHA2-192s**. The signature grows from 7856 B to 16224 B,
which is irrelevant — Bedrock signatures are produced rarely, by humans, on
offline media, and never travel in a handshake (ADR-0005). There is no reason
to economise on the one key that anchors everything else.

### Why each choice

**ML-KEM-768, not 512 or 1024.** 512 is Category 1 — too weak to be the default
for a product whose entire claim is post-quantum security. 1024 costs 384 more
bytes of public key and 480 more of ciphertext per handshake, which given the
fragment budget in ADR-0004 buys a security margin nobody has asked for. 768 is
also what the industry has converged on for `X25519MLKEM768` in TLS.

**ML-DSA-65 over FN-DSA/Falcon.** Falcon's signatures are dramatically smaller
(~666 B at Category 1 versus 2420 B for ML-DSA-44), which would be attractive
for the Bedrock chain. Rejected on implementation risk: Falcon signing requires
floating-point Gaussian sampling, which is notoriously difficult to make
constant-time, and FIPS 206 was not final. For a project whose credibility
rests on getting cryptography right, a known side-channel hazard is the wrong
trade for smaller signatures.

**SLH-DSA for the offline root, specifically because it is not lattice-based.**
Its security rests only on hash function properties — a completely different
mathematical foundation from ML-KEM and ML-DSA. If lattice cryptography falls,
the root of trust and the ability to re-key the network survive. This is the
same diversity logic as the per-pair PSK (ADR-0004) applied to authentication.

**ChaCha20-Poly1305 as the data-plane default.** Constant-time by construction
in software, and fast without AES-NI — which matters for the hobbyist half of
the audience running Raspberry Pis, ARM routers and OpenWrt. AES-256-GCM is
offered for AES-NI hardware and for CNSA 2.0 alignment. Both are 256-bit;
Grover reduces that to 128-bit effective, which is acceptable.

**SHA-512 rather than WireGuard's BLAKE2s-256.** Grover halves preimage
resistance, so a 256-bit hash gives 128-bit post-quantum preimage security.
512-bit output keeps ≥256 bits. BLAKE2b-512 is available as an alternative
where performance matters more than ubiquity.

### Rejected

| Algorithm | Why not |
|---|---|
| **Classic McEliece** | 524 KB public keys break memory, mobile, rotation, offline operation and the CNSA path. Retained as an optional profile only — ADR-0004 |
| **HQC** | NIST's backup KEM, but ~2.2 KB pk / ~4.5 KB ct at Category 1 — worse for a packet budget than anything chosen |
| **FrodoKEM** | Conservative but far too large for a handshake |
| **NTRU / sntrup761** | Comparable sizes to ML-KEM with no NIST standardisation |
| **FN-DSA / Falcon** | Floating-point signing side-channel risk; standard not final |

### Implementation

**Amended 2026-08-09 — the default backend is chosen by licence, not by
cryptography.**

This ADR originally named `libcrux-ml-kem` as the default because it is
formally verified via hax/F*, which is consistent with gating release on a
ProVerif proof of the protocol. Implementing the KEM trait surfaced a conflict:

| Crate | Licence | GPLv2-compatible? |
|---|---|---|
| `libcrux-ml-kem` | **Apache-2.0 only** | **No** |
| `ml-kem` (RustCrypto) | Apache-2.0 **OR** MIT | Yes, via the MIT arm |

ADR-0007 chose `MIT OR Apache-2.0` for the Rust crates **specifically** to keep
GPLv2 compatibility for the in-kernel datapath ADR-0003 lists under
*Reconsider if*. An Apache-only dependency inside `karst-crypto` would forfeit
that for the entire datapath — a decision taken deliberately in one ADR, undone
silently by a dependency choice in another.

- **`ml-kem` (RustCrypto) is the default.** Dual-licensed, MSRV 1.85 matching
  our pinned toolchain, and a stable 0.3 release line.
- **`libcrux-ml-kem` remains available behind a feature** for deployments that
  value the verified implementation and do not need kernel compatibility.
- **`aws-lc-rs`** as a further backend for deployments wanting a FIPS-track
  implementation.
- Backends are build-time features, not runtime negotiation (ADR-0006): which
  implementation runs is an operator decision, never an attacker-influenceable
  one.

The cost is accepted knowingly: the default is *not* the formally verified
implementation. Anyone weighing that trade should note it is reversible with a
feature flag, whereas losing GPLv2 compatibility would only be discovered years
later when the kernel datapath was attempted.

`cargo deny check licenses` enforces the allowlist and passes on the current
dependency graph.
- All key material in `Zeroizing<>`; NIST KAT vectors in CI; differential
  testing against PQClean.

---

## Consequences

### Positive

- Entirely standardised primitives — no bespoke cryptography, no unvetted
  parameter sets.
- Category 3 throughout, with the trust root no longer weaker than what it
  anchors.
- Defaults perform well on low-end hardware, matching the hobbyist audience.
- Diversity of mathematical foundations across confidentiality (PSK hedge),
  authentication (SLH-DSA root), and the classical hybrid (ADR-0002).

### Negative

- ML-KEM sizes are what force fragmentation and its DoS mitigations
  (ADR-0004). This ADR is the upstream cause of that complexity.
- Category 5 and CNSA 2.0 need a configuration change and a rolling restart —
  acceptable given no customer mandate (Q6), but not zero-cost.
- Lattice cryptography is younger than the classical curves it replaces.
  ADR-0002 and the PSK hedge exist because of this.
