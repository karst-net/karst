# Karst — Implementation Plan

**A post-quantum mesh VPN with self-hosted coordination, admin console, and user management.**

Status: draft v1 · Plan date: 2026-08-08 · Schedule re-anchored 2026-08-18 ·
Owner: TBD

---

## 0. Summary

Karst is a Tailscale-equivalent overlay network in which every long-term
cryptographic dependency is post-quantum. It consists of:

| Component | Language | Role |
|---|---|---|
| `karst-core` | Rust | PQ handshake, key schedule, wire formats, AEAD datapath |
| `karstd` | Rust | Node agent: TUN device, peer state, routing, DNS |
| `karst` | Rust | Node CLI |
| `karst-relay` | Rust | DERP-equivalent encrypted relay (**Ponor** protocol) |
| `karst-control` | Go | Coordination server: registration, policy, keys, SSO, audit |
| `karst-console` | React/TypeScript | Admin console |
| `karst-portal` | React/TypeScript | End-user self-service portal |

**Decisions locked in for this plan** (from scoping):

1. Greenfield Rust data plane — not a fork of wireguard-go/tailscale. Includes
   relay infrastructure, NAT traversal, and MagicDNS-equivalent name service.
2. Control plane is Go (HTTP/JSON + gRPC), UI is React + TypeScript.
3. First deployment target is a **self-hosted, single-tenant coordination
   server** (Headscale-shaped). Multi-tenant SaaS and air-gapped/CNSA-strict
   variants are explicitly deferred, but the data model is built so they are
   additive, not a rewrite.

**Why greenfield is defensible here:** the PQ handshake changes message sizes by
~20×, which breaks WireGuard's single-datagram, zero-allocation,
stateless-responder handshake design. Retrofitting fragmentation and revised
DoS defenses into wireguard-go is comparable work to writing a clean datapath,
without the freedom to fix the framing. The cost we are accepting: no upstream
maintenance sharing, no interop with existing WireGuard peers, and a much larger
client-platform surface to build ourselves (§9).

---

## 1. Threat model and cryptographic objectives

The full threat model lives in [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) —
assets, adversary tiers, trust boundaries, a compromise-yield matrix, accepted
risks and the residual risk register. This section is the summary.

### 1.1 Adversary

| Capability | In scope | Notes |
|---|---|---|
| Passive network capture, indefinite retention | **Yes** | Primary driver — harvest-now-decrypt-later (HNDL) |
| Future cryptanalytically-relevant quantum computer (CRQC) | **Yes** | Applied retroactively to captured traffic |
| Active MITM at time of connection | **Yes** | Classical only; a CRQC-in-the-moment is a stated non-goal for v1 auth |
| Compromised coordination server | **Yes** | Must not be able to silently add a node — see Bedrock (§4.5) |
| Compromised relay | **Yes** | Relays are untrusted; they see ciphertext and metadata only |
| Malicious peer inside the aquifer | **Yes** | Contained by ACL enforcement at both ends |
| Endpoint compromise / malicious admin with root | No | Out of scope |
| Traffic-analysis / metadata-hiding beyond padding | No | Documented non-goal for v1 |

The asymmetry to internalize: **confidentiality needs PQ today, authentication
needs PQ before a CRQC exists.** Recorded traffic can be broken later;
a signature can only be forged in real time. We ship PQ for both, but
confidentiality is where the deadline is real, and it drives sequencing.

### 1.2 Algorithm selection

| Purpose | Algorithm | Sizes | Rationale |
|---|---|---|---|
| Session key agreement | **Hybrid X25519 + ML-KEM-768** (FIPS 203) | X25519 pk 32 B; ML-KEM pk 1184 B, ct 1088 B | Hybrid so a break of either leaves the session secure. Matches the `X25519MLKEM768` industry consensus. |
| Node identity signing | **ML-DSA-65** (FIPS 204) | pk 1952 B, sig 3309 B | Lattice signature, fast, well-supported |
| Node static DH key | **X25519** | pk 32 B | Classical authentication in the handshake. Added 2026-08-09 — without a *static* DH key the hybrid is ephemeral-only and authentication rests entirely on ML-KEM, defeating ADR-0002's premise. Zero wire cost; see `spec/phreatic-v1.md` §13.1 |
| Offline root / network lock | **SLH-DSA-SHA2-192s** (FIPS 205) | pk 48 B, sig 16224 B | Hash-based, conservative, different math from ML-DSA. Category 3, matching everything it anchors — see the correction in [ADR-0001](docs/adr/0001-cryptographic-algorithm-selection.md). Signed rarely by humans on offline media, so the 16 KB signature is irrelevant. |
| Assumption-diversity hedge | **Per-pair PSK** from the coordination server | 32 B | Symmetric secrets are PQ-safe. Mixed into the key schedule at zero wire cost so a total lattice break is not a total break. See ADR-0004. |
| Data-plane AEAD | **ChaCha20-Poly1305** (default), AES-256-GCM (opt) | 256-bit keys | Grover reduces to 128-bit effective — acceptable. AES-256-GCM path exists for CNSA 2.0 and AES-NI hardware. |
| Hash / KDF | **SHA-512 / HKDF-SHA-512**, BLAKE2b-512 alt | 512-bit | ≥256-bit collision resistance post-Grover |
| Control-channel transport | TLS 1.3 with `X25519MLKEM768` | — | Go 1.24+ and rustls/aws-lc-rs both support this |

A **crypto agility layer** is mandatory from day one
([ADR-0006](docs/adr/0006-cryptographic-agility-layer.md)): algorithms are
selected only as complete, named suites drawn from a **fixed allowlist compiled
into `karst-crypto`** — never negotiated per-primitive, never runtime-extensible.
The suite ID is bound into the transcript hash and the control server publishes
a minimum acceptable suite that nodes enforce locally. Migration to ML-KEM-1024
/ ML-DSA-87 (CNSA 2.0) must be a config change plus a rolling restart, not a
protocol revision. Agility is deliberately narrow: TLS's cipher-suite
proliferation and JWT's `alg: none` are what an open negotiation system buys
you.

### 1.3 Explicit non-goals for v1

- WireGuard wire-protocol interoperability.
- Metadata privacy beyond fixed-size padding buckets.
- FIPS 140-3 validated module (we use validated *implementations* where
  available — `aws-lc-rs` — but pursue no validation of our own boundary).
- Mobile clients (iOS/Android) — Phase 7.

---

## 2. Protocol design: the PHREATIC handshake

### 2.1 Foundation

Based on **PQNoise** (Angel, Dowling, Hülsing, Rösler, Schwabe, CCS 2022),
which adapts Noise patterns to KEMs, since Noise's DH-based patterns cannot
express a KEM. We use the `pqIK`-shaped pattern, augmented with a classical
X25519 DH mixed into the same chaining key — so the transcript hash and key
schedule bind both the KEM shared secrets and the DH output.

Prior art to read before writing a line of protocol code:

- **PQ-WireGuard** (Hülsing et al., IEEE S&P 2021) — the security proof we
  should be mirroring.
- **Rosenpass** — production PQ key exchange feeding PSKs into WireGuard.
  Their design notes on DoS resistance and stateless responders are directly
  applicable. Their choice of Classic McEliece (156-byte ciphertext, 524 KB
  public key held by the responder) to keep packets small was evaluated and
  rejected as our default in ADR-0004; see §2.3.

### 2.2 Message flow

```
Initiator                                          Responder
  |-- msg1 (~2378 B, 2 fragments):                     |
  |     type, sender_idx, suite_id, psk_epoch,         |
  |     eph_kem_pk (1184), eph_x25519_pk (32),         |
  |     kem_ct_to_static_S (1088),                     |
  |     enc(peer_id_hint || timestamp)                 |
  |     [each fragment carries its own MAC]            |
  |--------------------------------------------------->|
  |                                                     | decaps, derive
  |<-- msg2 (~2236 B, 2 fragments):                     |
  |      type, sender_idx, receiver_idx,                |
  |      kem_ct_to_eph (1088),                          |
  |      kem_ct_to_initiator_static (1088),             |
  |      eph_x25519_pk (32), enc(empty)                 |
  |<----------------------------------------------------|
  |-- transport data (ChaCha20-Poly1305, 64-bit ctr)    |
  |<--------------------------------------------------->|
```

Key schedule: HKDF chain over protocol label → suite id → responder static key
hash → each KEM shared secret → X25519 output → **per-pair PSK**. The PSK is
mixed last so it gates the final session key (§2.6).

Design points:

- **No static public key in the handshake**
  ([ADR-0005](docs/adr/0005-identity-model-and-peer-presentation.md)).
  WireGuard's `IK` encrypts the initiator's 1184-byte static key in msg1;
  carrying it here would push msg1 to 3530 B and a third fragment. We instead
  send `peer_id_hint = H(protocol_label || static_kem_pk)`, 32 bytes, inside
  the AEAD payload — a lookup key into the netmap, not a decryption selector.
  The hint is **unsalted** and **session-independent**; binding it to the
  session would turn the responder's O(1) lookup into O(N) work per handshake.
  Identity confidentiality matches WireGuard against every adversary and
  exceeds it under responder-key compromise or a retroactive lattice break,
  where it degrades to pseudonymity rather than full identification. Hint
  misses are dropped silently so nodes are not roster-membership oracles.
- **Three KEM encapsulations** give forward secrecy (to ephemeral),
  responder authentication (to responder static), and initiator
  authentication (to initiator static) respectively.
- **1-RTT to first data packet**, matching WireGuard.

### 2.3 The MTU problem — the single largest protocol risk

**Decided in [ADR-0004](docs/adr/0004-handshake-mtu-and-kem-selection.md).**

msg1 and msg2 exceed the 1280-byte IPv6 minimum MTU, so both fragment.
WireGuard's DoS story depends on handshakes being single, stateless,
unfragmented datagrams; the governing risk is not packet loss but the
**pre-authentication reassembly state** an attacker can force us to allocate
from spoofed sources.

Classic McEliece (156-byte ciphertext, 524 KB public key distributed out of
band) was evaluated as the way to avoid fragmentation entirely, and rejected as
the default: it would additionally force the *ephemeral* KEM down to
ML-KEM-512 to fit a datagram, and 524 KB × N peers breaks the memory target,
mobile viability, cheap rotation, offline operation, and the CNSA 2.0 path all
at once. It is retained as an optional profile (§2.6).

Required mitigations:

1. **Application-layer fragmentation sublayer.** 24-byte fragment header,
   1208 B usable payload per datagram, hard cap of 4 fragments, explicit
   reassembly ID, 3-second timeout, bounded per-source budget. Never IP-layer
   fragmentation.
2. **Per-fragment authentication.** Each fragment carries its own MAC,
   replacing WireGuard's message-level `mac1`/`mac2`, so invalid fragments are
   dropped before touching a reassembly buffer.
3. **Stateless responder under load.** Above a queue threshold the responder
   buffers nothing: it discards the fragment and emits a ~64-byte cookie reply
   (stateless HMAC over source address + rotating secret). Reassembly state is
   allocated only for cookie-validated, address-validated sources. Costs one
   extra RTT on first contact under load; reduces the attack surface to
   on-path adversaries, matching WireGuard's posture.
4. **Anti-amplification invariant:** never emit more bytes than received from
   an unvalidated source, and never act on a partial reassembly. msg1 > msg2
   natively (2378 vs 2236 B) so no padding is needed — but the margin is
   142 bytes, so the invariant is asserted in tests and will constrain future
   field additions.

### 2.4 Rekeying

- Rotate session keys every **120 seconds** or 2⁶⁰ messages, whichever first
  (WireGuard's parameters, retained).
- A full PQ handshake is expensive; a **symmetric ratchet** covers routine
  rekeys, with a fresh KEM handshake forced every 10 minutes to re-establish
  post-compromise security.
- Downgrade protection: the negotiated cipher suite is bound into the
  transcript hash, and the coordination server publishes a minimum acceptable
  suite that nodes enforce locally.
- Per-pair PSKs rotate every 24 hours and on any Bedrock event;
  responders accept epoch *n* and *n−1* during the transition.

### 2.5 Formal verification

The handshake gets a **Verifpal** model and a **ProVerif** model, **both in
Phase 1**. ProVerif was originally scheduled for Phase 3; it was pulled forward
after drafting `spec/phreatic-v1.md` surfaced two design gaps by hand (§13.1,
§13.2) that a model should have caught. Verifpal gives fast feedback on design
blunders; ProVerif reasons over unbounded sessions with an explicit equational
theory. Both live in `spec/models/`
and are checked in CI. If the ProVerif model does not verify, the protocol
does not ship — this is a hard gate, not a best-effort task.

The **PSK-absent fallback (§2.6) must be modelled explicitly** — a
downgrade-to-zero-PSK attack is the obvious thing an adversary would reach for.

**The rule generalised, 2026-08-14: every Karst protocol gets a ProVerif model
before it ships, and every model gets a deliberately-broken sibling.** All three
now have one — PHREATIC, KARST-CONTROL and Ponor — and in each case the exercise
paid for itself: `phreatic-v1.md` §13.3, `karst-control-v1.md` §9, and
`ponor-v1.md` §12.2, where the field the plan expected to be load-bearing turned
out not to be and a different one was.

The siblings are as important as the models. `karst-control-nofs.pv` and
`ponor-norelayid.pv` exist to **fail**, and CI asserts the number of failing
queries rather than the absence of passing ones, so a change that quietly
stopped them failing is caught rather than celebrated.

### 2.6 Assumption diversity: per-pair PSKs

Everything above rests PQ confidentiality on lattices alone. Because symmetric
secrets are post-quantum safe, we hedge that at zero wire cost:

- The coordination server derives
  `psk(A,B,epoch) = KDF(master, min(A,B), max(A,B), epoch)` and ships it in the
  netmap. Deriving rather than storing keeps server state at O(1) instead of
  O(N²); per-node cost is 32 B × peers (6.4 KB at 200 peers).
- Mixed **last** into the chaining key, gating the final session key. A
  4-byte `psk_epoch` in msg1 selects the version.
- If a node holds no PSK for a peer (new peer, stale netmap), it falls back to
  an all-zero PSK so connectivity survives. Such sessions are lattice-only and
  are **flagged in the console's crypto posture view** (§8.1).

Security claim, stated precisely:

- Against a **classical** attacker: secure if X25519 **or** ML-KEM holds.
- Against a **quantum** attacker: secure if ML-KEM holds, **or** the attacker
  does not hold the PSK.

Honest caveat: because the server derives the PSKs, *server compromise plus a
total lattice break* is a full break. Server compromise alone is not. This is a
weaker hedge than a code-based static KEM, whose security is independent of the
server — that weakening is the price of the operational benefits. It also means
**the netmap now carries secrets**: encrypted at rest on nodes, never logged,
master key in an HSM/KMS where available (§12).

**Optional high-assurance profile.** The agility layer must be able to express a
KEM whose public key is distributed out of band and never appears on the wire —
concretely, a `KEY_DISTRIBUTION: InBand | OutOfBand` associated constant on the
`Kem` trait, with the codec branching on it. No Classic McEliece implementation
ships in v1; this is a Phase 1 design constraint that keeps the option open for
small, fixed, server-class aquifers that want code-based security.

---

## 3. The Rust data plane

### 3.1 Crate layout (Cargo workspace)

```
crates/
  karst-crypto/     KEM/sig/AEAD traits, suite registry, zeroization
  karst-proto/      wire formats, fragmentation, codec, no_std-friendly
  karst-noise/      PHREATIC handshake state machine (sans-io)
  karst-transport/  UDP sockets, GSO/GRO, sendmmsg, endpoint mgmt
  karst-disco/      NAT traversal: AVEN probing, path selection
  karst-relay-proto/ Ponor framing and handshake, both sides
  karst-dns/        KarstDNS resolver + split-DNS
  karst-tun/        platform TUN/TAP abstraction
  karst-node/       daemon: state machine, config, IPC, netmap ingest
                       + encrypted netmap cache (holds per-pair PSKs, §2.6)
  karst-control-client/ typed client for the Go control API
bins/
  karstd/           node daemon
  karst/               CLI
  karst-relay/      relay server
```

**Sans-io discipline:** `karst-noise` and `karst-proto` do no I/O. They
take bytes and time in, emit bytes and timer requests out. This is what makes
the protocol testable, fuzzable, and formally checkable, and it is worth the
extra plumbing.

### 3.2 Crypto implementation choices

- **`libcrux-ml-kem`** — formally verified (hax/F*) ML-KEM. Preferred default.
- **`aws-lc-rs`** — alternative backend, FIPS-track, for customers who need it.
- **`ml-dsa` (RustCrypto)** or PQClean bindings for ML-DSA-65; benchmark both.
- **`slh-dsa` (RustCrypto)** for the offline root.
- All key material in `Zeroizing<>` wrappers; `#![forbid(unsafe_code)]` in
  every crate except `karst-tun` and the GSO paths in `karst-transport`, where
  each `unsafe` block carries a `// SAFETY:` justification.

**On the Go side** (decided 2026-08-13, while implementing the control channel):

| Primitive | Implementation |
|---|---|
| ML-KEM-768 | **`crypto/mlkem`** — Go standard library, FIPS 203 |
| HKDF-SHA-512 | **`crypto/hkdf`** — standard library |
| ChaCha20-Poly1305 | `golang.org/x/crypto` — already a direct dependency |
| ML-DSA-65 | **`crypto/mldsa`** — Go standard library, FIPS 204 (since 1.27) |
| SLH-DSA-SHA2-192s | **`cloudflare/circl`** — no standard-library path exists |

The KEM half needed no new dependency. ML-DSA did, temporarily, and **that
migration is now done — 2026-08-18, on Go 1.27rc3.**

Go 1.26 implemented ML-DSA-44/65/87 in `crypto/internal/fips140/mldsa`,
ACVP-tested, and did not export it; `internal/` cannot be imported from outside
the standard library. So the control channel shipped on `cloudflare/circl`
v1.6.5 behind `channel.Signer` and `channel.Verifier`, with
`management/internals/karst/identity` written as a deliberately thin shim so
that the swap would be one file.

**It was one file, and the pre-planning is the whole reason.** Go 1.27 shipped
the public `crypto/mldsa`; `identity.go` now wraps it and circl left the module
entirely — nothing else imported it. It **returns for Bedrock**, which needs
SLH-DSA-SHA2-192s (ADR-0001) and which the standard library has no
implementation of, internal or otherwise. So this is a dependency deferred to
Phase 5, not one avoided.

**The swap was checked for byte-compatibility rather than assumed.** Both
libraries implement FIPS 204, which is a strong argument that a seed derives
the same key under each and not a proof — and it matters more than usual here,
because a node's handle is a hash of its public key. A disagreement would not
have failed; it would have silently re-identified every enrolled node, and the
symptom would have been a fleet that cannot authenticate for reasons no log
line explains. The circl-derived public key digest was captured *before* the
swap and is now pinned by `TestSeedIsStableAcrossTheCirclMigration`; a
circl-produced signature is pinned beside it and must still verify. Both pass,
and the Rust↔Go interop suite — where the `ml-dsa` crate checks the Go server's
signatures — passes unchanged.

Two operational notes came out of it. `go.mod` needs an explicit
`toolchain go1.27rc3` line: with only `go 1.27` the toolchain tries to fetch a
`go1.27.0` that does not exist and fails with "toolchain not available", which
names the symptom and not the cause. And `crypto/mldsa` is **unavailable under
FIPS 140-3 module v1.0.0**, where every constructor returns an error — the
right failure, since a build that cannot do ML-DSA cannot run Karst's control
plane, but one to know about before someone sets `GODEBUG=fips140=v1.0`.

An earlier prune also removed a stale `replace` directive pinning circl to a
2023 codeberg fork that predates FIPS 204 — dead weight even then, since the
prune had already left circl with zero packages in the build graph.

### 3.3 Performance targets

| Metric | Target | Method |
|---|---|---|
| Single-flow throughput, x86-64 | ≥ 3 Gbps | **Concurrency first** (per-peer locking), then UDP GSO/GRO, `sendmmsg`/`recvmmsg`, batch AEAD |
| Handshake latency (LAN) | < 3 ms | ML-KEM is fast; cost is packets, not cycles |
| Handshakes/sec/core (responder, under cookie) | ≥ 5,000 | |
| Idle CPU, 200 peers | < 1% of one core | |
| Memory, 200 peers | < 60 MB RSS | |

Datapath MTU is **1280** (fixed) as with Tailscale — the floor, not a choice:
RFC 8200 §5 requires 1280 on any link carrying IPv6, and nodes are assigned a
ULA IPv6 (§4.2).

A full-size tunnel packet therefore produces a **1384-byte** datagram on the
wire, not 1280. Draft 0.2 of the spec assumed both numbers could be 1280 at
once; sizing the TUN interface showed they cannot, and
[spec §13.6](spec/phreatic-v1.md) records the resolution: the minimum-MTU cap
binds handshakes (where the §9 DoS analysis lives), while an unfragmented
transport message may use the larger budget. Paths below 1384 will black-hole
full-size data packets — the same exposure WireGuard and Tailscale carry, and
the reason path MTU discovery is Phase 6 rather than optional.

### 3.4 First throughput measurement — 2026-08-11

Measured with `scripts/two-host-test.sh` between two 48-core Xeons on a 3 Gbps
bonded link (Ubuntu 24.04, release build, iperf3):

| Path | Throughput |
|---|---|
| Underlay, single flow | **943 Mbps** |
| Underlay, 4 flows | **1889 Mbps** |
| **Karst tunnel, single flow** | **298 Mbps** |
| **Karst tunnel, 4 flows** | **290 Mbps** |
| Karst tunnel, aarch64 → x86-64 through NAT | **309 Mbps** |

The bond is 3×1G, so a single flow hashes to one slave and 943 Mbps is line
rate for it; four flows reach 1889 Mbps. The tunnel manages **32% of
single-flow line rate**, roughly 29,000 packets/s at the 1280-byte MTU.

The cross-architecture figure being *the same* is itself informative: whatever
limits this is not per-architecture crypto throughput. (That row first read
45 Mbps, which was a **debug build** on one side — a 7× difference, and a
reminder that any number from `target/debug` is meaningless. The two-host
script builds `--release` for this reason.)

**Four flows are no faster than one, and that is the finding.** Per-packet cost
would still scale with concurrency on a 48-core machine; a flat line means
*serialisation*. During transfer only two daemon threads are busy (80% and 60%
of one core each) while 46 cores idle. A UDP control at the same 1232-byte
datagram size reached 782 Mbps (79,000 packets/s) on the same path, so neither
the NIC nor the packet rate itself is the ceiling. The bottleneck is the
datapath's shape, not its arithmetic:

1. **One mutex around the whole engine.** Every packet in both directions
   serialises on it. This is the flat line.
2. **One syscall per packet.** No `sendmmsg`/`recvmmsg`, no GSO/GRO.
3. **Allocation per packet** — `seal` copies the plaintext, `fragment` returns
   a `Vec<Vec<u8>>`.

None of this is surprising: `run.rs` was written as the simplest correct loop
over a sans-io core, precisely so it could be replaced without touching the
protocol. It is now measured rather than assumed, and (1) is the first thing to
fix — per-peer locking is likely worth more than batching, and is a smaller
change.

#### Fixes applied, re-measured the same day

The global lock is gone: per-peer session locks, atomic counters, and the
reassembler off the outbound path. Same hosts, same method:

| Change | Single flow | 4 flows |
|---|---|---|
| Baseline | 298 Mbps | 290 Mbps |
| **1. Engine-wide lock removed** (per-peer locking) | **393 Mbps** (+32%) | 364 Mbps |
| **2. Fragment MAC no longer covers the payload** (spec §13.8) | **473 Mbps** (+59% total) | — |
| **3. HMAC schedule pre-keyed per session** | 455–470 Mbps — **no change** | — |
| **4. `sendmmsg`/`recvmmsg` batched I/O** | 481–493 Mbps (**+3%**) | — |
| **5. TUN segmentation offload (`IFF_VNET_HDR` + TSO)** | 521–540 Mbps (**+10%**) | — |
| **6. One allocation per packet, cached AEAD ciphers** | 495–571 Mbps — **no change** | 502–517 Mbps |
| **7. AEAD moved outside the per-peer lock** | **668–707 Mbps** (+33%) | 699–709 Mbps |

**Four flows still do not beat one, and that is expected rather than a
disappointment.** All four go to the *same peer*, so they share that peer's
session lock; per-peer locking buys scaling across peers, and this benchmark has
one. The +32% on a single flow is what removing the engine-wide lock was
actually worth — the two directions of one peer no longer serialise against each
other.

**Change 2 came out of a profile, not a guess.** `perf` on a loaded node put
`sha512_compress` at **23.4% of CPU** — against 2.9% for ChaCha20 and 1.5% for
Poly1305. The §9.2 fragment MAC cost roughly *five times the AEAD it gates*,
because §9.2's cost argument ("1–2 µs against the 20–50 µs ML-KEM decapsulation
it gates") was computed for the handshake and never revisited for the data path,
where there is no ML-KEM to amortise against. The MAC now covers the header
only; spec §13.8 records the full security argument, and flags it for external
review as the one change made on performance grounds.

**Change 3 is the useful negative result.** After (2), SHA-512 was still the
largest single symbol at 11.8%: HMAC costs four SHA-512 compressions even for a
7-byte input, because the `ipad` and `opad` blocks were re-absorbed per packet.
Pre-keying once per session and cloning the keyed state halves that — and the
profile confirms it did, **11.8% → 6.1%**.

Throughput did not move at all.

That is the finding: **freeing 6% of CPU bought nothing, so CPU is no longer the
constraint.** The profile is now **63% kernel time** against 32% in Karst's own
code, with no single userspace hotspot above 6%, and the datapath threads sit in
`S` (sleeping) rather than `R` (running) at 80% and 50%. The pipeline is
**syscall-bound**: one `read` from the TUN and one `sendto` per packet, ~46,000
of each per second per direction.

Batching is therefore the only remaining lever of any size, and it is now
evidenced rather than assumed — which is the opposite of where this section
started, when batching was prescribed before anything had been measured. The
pre-keying is kept: it is strictly cheaper, and it will matter again once
syscalls stop dominating.

**Change 4 delivered far less than that reasoning predicted: +3%.** The reason
is that only *half* the syscalls can currently be batched. Per packet the
datapath still performs:

| | Sender | Receiver |
|---|---|---|
| TUN | 1 `read` | 1 `write` |
| UDP | 1 `sendto` | `recvmmsg`, amortised ✅ |

`recvmmsg` is the only one of the four that batching reached. A single flow
hands the engine one packet at a time, so `sendmmsg` has nothing to group —
`dispatch` uses it for handshakes (two fragments) and falls back to `send_to`
for the single-datagram case, which is every data packet. Both TUN syscalls
remain per-packet because a TUN device returns exactly one packet per `read`.

Getting further therefore needs **`IFF_VNET_HDR` on the TUN device**: with
virtio-net headers the kernel coalesces several TCP segments into one read and
accepts several in one write, which is what finally gives `sendmmsg` and GSO
something to batch. That is the design wireguard-go and Tailscale use, and it is
the next increment. The socket-side machinery it depends on now exists and is
tested.

#### Change 5 — offload works, and moves the bottleneck off syscalls entirely

`IFF_VNET_HDR` with `TUN_F_TSO4`/`TSO6` is in, and it does what it was supposed
to. Measured with `strace -c` on a loaded node at ~52,700 packets/s:

| Syscall | Calls/s | Packets per call |
|---|---|---|
| `read` (TUN) | ~1,000 | **~52** |
| `sendmmsg` (UDP) | ~1,000 | ~32 (the batch cap) |
| `sendto` | ~12 | — |

Against roughly 46,000 `read` + 46,000 `sendto` per second before, that is a
**~50× reduction in syscalls**. Throughput rose 10%.

**Those two numbers together are the result.** Removing 98% of the syscalls
bought a tenth, so the datapath is no longer syscall-bound in any meaningful
sense — the cost is now per-packet work in userspace: an AEAD, a MAC, and
several allocations for each of 52,700 packets a second.

#### Change 6 — allocations were not it either

`seal` went from three allocations and two copies per packet to one of each
(encrypt in place, tag detached), the `ChaCha20Poly1305` instances are keyed
once per session rather than per packet, and the TUN write path uses
`write_vectored` instead of joining a buffer. Run-to-run spread (495–571 Mbps)
now exceeds any effect. **No measurable change.**

#### What the ceiling actually is

Two measurements settle it:

| | Underlay | Tunnel |
|---|---|---|
| 1 flow | 943 Mbps | ~530 Mbps |
| 4 flows | 1889 Mbps | 517 Mbps |
| 8 flows | **2824 Mbps** | 502 Mbps |

The link will carry 2.8 Gbps. **The tunnel sits at ~500 Mbps and does not move
with flow count** — the same flat line that identified the engine-wide lock in
the first place, and for a related reason: there is one peer, so every flow
shares that peer's session lock. A `TransportSession` is inherently serial in
its counter and its replay window, and the AEAD is currently done *inside* that
lock rather than outside it.

So ~500 Mbps is a **per-peer-pair ceiling of our own making**, not a property of
the link.

#### Change 7 — the lock, again

`TransportSession` now synchronises itself: an `AtomicU64` for the nonce counter
and a `Mutex` around the replay window alone. `seal` and `open` take `&self`, so
the engine clones an `Arc` under the peer lock — one refcount bump — and runs the
cryptography with no lock held. §8 is unaffected: decryption still completes
before the replay window is touched, and the window's own lock is taken only to
record the counter.

**668–707 Mbps, up from ~530: +33%**, and multi-flow now matches single-flow
rather than falling below it. Against the 884 Mbps ceiling computed below, that
is **80% of what the link can physically carry**.

Two of the seven changes so far were locks, and both were worth more than
everything else combined. The three micro-optimisations between them — pre-keying,
allocation removal, batched syscalls — bought 3% between them despite removing
98% of syscalls and most of the allocations. The lesson is recorded because it
is the opposite of the intuition §3.3 was written with.

**On the ≥ 1 Gbps exit criterion itself** — restated on 2026-08-13 as a
fraction of the link's computed ceiling; see Phase 2's exit block for the
replacement wording and why. For a *single flow* the original number is not
reachable on this hardware at all, and that is arithmetic rather than
engineering. The bond is 3×1G and hashes a flow to one slave, so a single flow
has 1 Gbps of wire. The tunnel's 1280-byte inner MTU carries 1240 bytes of TCP
payload per 1402 bytes of wire time (1336 UDP + 8 + 20 IP + 14 Ethernet + 4 FCS
+ 20 preamble/IFG), which is 88.4% — a **884 Mbps ceiling**. The same model
predicts 941 Mbps for the untunnelled 1500-byte path against 943 measured, so
it is trustworthy.

**Aggregate does not rescue it, and an earlier draft of this section was wrong
to say it would.** Re-measured 2026-08-13, after change 7:

| | tunnel |
|---|---|
| 1 flow | 686 Mbps |
| 4 flows | **708 Mbps** (+3%) |

The underlay carries 2824 Mbps across 8 flows, so the link has room the daemon
does not use. Reading the bar as "≥ 1 Gbps aggregate" therefore fails too — at
708 Mbps it is no more met than the single-flow reading. The suggestion in the
previous draft was an inference from "multi-flow now matches single-flow"; it
was never measured, and measuring it says the opposite of what was hoped.

**And it is not CPU-bound.** During the 4-flow run the two datapath threads sit
at **70% each** — 1.4 cores of 48 — while retransmits rise from 624 to 10679.
Something serialises the datapath that is neither the engine lock (removed,
change 1) nor the session lock (removed, change 7), and it gives up before it
runs out of CPU. Two threads is itself the likeliest answer: one reads the TUN
and one reads the UDP socket, so *all* flows for *all* peers funnel through a
single encrypt path and a single decrypt path regardless of how many flows or
cores exist. Confirming that, and sharding the datapath if so, is **Phase 7**
work — it is a redesign, not a tuning pass, and Phase 2 does not need it.

The ≥ 3 Gbps target in §3.3 remains a **4× gap** from here, and closing it
means the sharding above rather than more tuning. That is the honest position.

Note that §3.3 originally named only offload and batching as the method, which
was written before anything had been measured. Every one of those remedies
attacks (2) — cost *per trip through the datapath*. The measurement says the
datapath only makes one trip at a time, so batching first would make each trip
carry more bytes while still discarding the concurrency. **Contention was fixed
first, and it was Phase 2 work** because no throughput criterion could be met
while it stood — the two lock removals moved 298 → 707 Mbps between them.

That prescription is now spent. Both locks are gone, batching and offload are
in, and the datapath still does not scale with flow count while leaving 30 CPU%
per thread unused. What remains is **concurrency of a different kind** — more
datapath threads, not less locking within two of them — and that is the Phase 7
sharding item. io_uring stays there too, where a second pass belongs.

---

## 4. Control plane (Go)

This is a **fork of NetBird** (BSD-3, Go + React — our exact stack) rather than
a greenfield build, per [ADR-0009](docs/adr/0009-control-plane-fork-vs-greenfield.md)
and [Spike 0001](docs/spikes/0001-netbird-fork-evaluation.md). The management
server, ACL model, IdP/SCIM integration, DNS config, activity log and TURN
credential distribution transfer; PQ-sized identities, the netmap PSK schedule,
Bedrock, the crypto posture view and **delta netmap push** do not.

Forked at a known tag and **diverged, not tracked** — security fixes are
cherry-picked deliberately; routine upstream churn is not merged. Our generic
improvements are still offered upstream under BSD-3.

### 4.1 Services

```
cmd/
  karst-control/    API server + coordination
  karst-ctl/        admin CLI (server-side operations, migrations)
internal/
  auth/                OIDC, sessions, API keys, auth keys
  tenant/              org model (single-tenant now, multi-tenant-shaped)
  device/              node registration, key rotation, expiry
  netmap/              network map computation and delta push
  psk/                 per-pair PSK derivation, epoch rotation, master custody (§2.6)
  policy/              ACL parse, compile, evaluate
  lock/                Bedrock (network lock) signature chain
  dns/                 name allocation, split-DNS config
  relay/               relay registry, health, region map
  audit/               append-only audit log
  provisioning/        SCIM 2.0, group sync
  store/               GORM (from the fork), Postgres 16+
```

> **Amended 2026-08-13.** This section previously specified "`pgx` + `sqlc`
> (no ORM)". That preference was written for a greenfield build and **did not
> survive the decision to fork** — NetBird is GORM throughout. Rewriting a
> working store layer would forfeit much of what forking is for, so the fork's
> ORM is inherited and this line now says so. See Spike 0001 §5.5.
>
> **One rule follows from it:** new Karst tables (PSK schedule, Bedrock, crypto
> posture) go through **GORM as well**. Two persistence idioms in one binary is
> the outcome nobody chose and the easiest one to reach by accident.

Stack: Go 1.24+, `chi` router, **GORM** (inherited from the fork; Postgres 16+
via `gorm.io/driver/postgres`), NetBird's migration layer,
`go-oidc` for SSO, `slog` for structured logs, OpenTelemetry traces,
Prometheus metrics. gRPC only for the node↔control long-poll stream;
everything else is HTTP/JSON with an OpenAPI 3.1 spec that generates both the
TypeScript client and the Rust client.

### 4.2 Node lifecycle

1. `karstd` generates an ML-DSA-65 identity keypair + ML-KEM-768 static
   KEM keypair, sealed at rest with an OS keystore or a passphrase-derived key.
2. Registration via either an **auth key** (pre-shared, reusable/ephemeral/
   tagged, expiring) or an **interactive OIDC flow** in the browser.
3. Control server verifies, assigns a stable node ID, a 100.64.0.0/10 CGNAT-
   range IPv4 and a ULA IPv6, and a KarstDNS name.
4. If Bedrock is enabled, the node key must additionally be countersigned
   by a quorum of lock keys before peers will accept it (§4.5).
5. Node opens a long-lived stream and receives **network map deltas**: peer
   list, public keys, endpoints, relay assignments, DNS config, ACL-derived
   packet filter, expiry.

### 4.3 Access control policy

HuJSON policy document, Tailscale-compatible in shape so the concepts transfer:

```hujson
{
  "tagOwners": { "tag:prod": ["group:sre"] },
  "groups":    { "group:sre": ["alice@example.com"] },
  "acls": [
    { "action": "accept", "src": ["group:sre"], "dst": ["tag:prod:22,443"] },
  ],
  "ssh": [ /* Phase 6 */ ],
  "nodeAttrs": [ /* posture, exit-node permissions */ ],
}
```

The compiler turns the policy into a **per-node packet filter** shipped in the
netmap and enforced in the Rust datapath on **both** ingress and egress. The
control server is a distributor of policy, not an enforcement point — a
compromised server can misroute but cannot read traffic.

Policy tooling: a `karst policy test` command running policy unit tests, a
dry-run diff in the console showing which flows a proposed change adds or
removes, and versioned policy history with one-click rollback.

### 4.4 User and group management

- **Identity providers:** OIDC (Okta, Entra ID, Google Workspace, Authentik,
  Keycloak), plus a built-in local IdP for air-gapped and small deployments.
- **Provisioning:** SCIM 2.0 for user/group create/update/deprovision; group
  sync drives ACL `group:` membership automatically.
- **Roles:** Owner, Admin, Network Admin, IT Admin, Auditor (read-only),
  Member. Enforced by a central authorization middleware with a table-driven
  permission matrix that is unit-tested exhaustively.
- **Deprovisioning is a security control, not a UX feature.** Removing a user
  in the IdP must expire their node keys and drop their sessions within 60
  seconds. This gets its own integration test.

### 4.5 Bedrock (aquifer-lock equivalent)

Defends against a compromised coordination server injecting a rogue node.

- Designated admin devices hold **SLH-DSA offline root keys**; a subset are
  kept on hardware tokens or offline media.
- Roots sign an authority list; a quorum (`k` of `n`) of authority keys must
  countersign each node's ML-DSA identity key.
- Nodes verify the signature chain locally and **refuse to peer with any node
  the chain does not cover**, regardless of what the netmap says.
- Key rotation, revocation, and quorum changes are themselves signed
  operations appended to a hash-chained log that every node replicates and
  verifies — so the server cannot equivocate about history.

This is the feature that makes "self-hosted" honest. It ships in Phase 5, not
as a stretch goal.

---

## 5. Relay infrastructure (`karst-relay`, **Ponor** protocol)

Untrusted packet relays for peers that cannot establish a direct path (~5–15%
of connections in practice, higher on mobile/CGNAT).

**Normative specification: [spec/ponor-v1.md](spec/ponor-v1.md).** This section
is the summary and the rationale; where the two disagree the spec governs. Two
points below have been tightened by it and are marked in place: strict-mode
admission is no longer a mode (spec §5.3), and relay identity does not rest on
the TLS certificate (spec §4.2).

The design owes a clear debt to Tailscale's **DERP** — mesh presence,
home-relay selection, relay-first-then-upgrade — which is credited as prior art
here and in `spec/phreatic-v1.md`. We borrow the design and **not** the protocol or
the fleet: [ADR-0008](docs/adr/0008-relay-infrastructure-and-funding.md) rules
out both, and `karst-relay` must never gain a DERP compatibility mode.

- Transport: HTTPS/TLS 1.3 with hybrid `X25519MLKEM768`, upgrading to a binary
  frame protocol. Port 443 so it survives restrictive networks. HTTP/3 +
  QUIC datagrams as a Phase 6 alternative for better loss behavior.
- Relays are **addressed by node ID** — the 32-byte hash of the identity key,
  the same value as the KARST-CONTROL handle (spec §5.1). *Amended 2026-08-14:
  this line previously said "by node public key", which was written before the
  identity model settled; a 1952-byte ML-DSA key on every forwarded frame was
  never the intent.* Relays hold no long-term state and see only PHREATIC
  ciphertext. What the operator learns is enumerated in spec §11 rather than
  summarised — "and nothing else" was too generous, since the traffic graph, the
  timing and the exact packet sizes are all visible and none of it is padded.
- Every connection begins over a relay and **upgrades to a direct path** when
  discovery succeeds, with no packet loss during the switch (the datapath
  keeps both paths warm and cuts over on receipt of the first direct packet).
- Region map: multiple relays per region, latency-probed by clients, published
  by the control server so self-hosters can add their own.
- Mesh mode: relays in a region gossip client presence so a peer connected to
  relay A in region X can be reached via relay B.
- Abuse controls: per-key rate limits over **both bytes and frames** (a flood of
  minimum-size frames is cheap in bandwidth and expensive in per-frame work, so
  a bytes-only limit is one an attacker sizes around), per-connection byte
  accounting, and admission only for keys present in a signed aquifer roster.
  *Amended 2026-08-14: "strict mode is mandatory for community-pool relays" is
  obsolete — spec §5.3 removed the mode.* Admission is now structural for every
  relay: `ClientAuth` carries no public key, so a relay cannot verify a node it
  has no roster entry for. An open relay is an abuse conduit that hands its
  operator traffic they cannot inspect and did not agree to carry, and it is now
  a configuration that cannot be reached rather than one that must be chosen
  against.
- Forwarding is scoped **per aquifer** (spec §5.4): source and destination must
  be in the same one. Without that rule a multi-tenant relay is a
  general-purpose message bus between any two keys it has ever been told about.
- **Standard TURN (RFC 8656) as a pluggable sustained-fallback datapath.** The
  answer to regional coverage and SPOF without anyone donating bandwidth: point
  at coturn you already run, or rent commodity TURN for cents. Supplement, not
  replacement — DERP-style always-connected presence has no TURN equivalent, so
  `karst-relay` keeps bootstrap and presence. ChannelData framing (4-byte
  header) to minimise MTU impact; ephemeral HMAC credentials minted by the
  control server and shipped in the netmap, never static ones (one more netmap
  secret — see §2.6).
- Relay registry validation rejects `derp://` endpoints.

**Deployment default: the relay is co-located with the coordination server.**
The self-hoster already runs a public-IP host, so marginal infrastructure cost
is zero. Ship it in the same `docker-compose` and the same static binary, so a
self-hoster is relaying in under five minutes without deciding anything. This
is both the adoption lever and the answer to who pays for bandwidth (§13 Q4).

A community relay pool is supported but opt-in, with the metadata-privacy cost
disclosed at the point of configuration rather than in documentation: a
volunteer operator learns who talks to whom. There is deliberately **no default
public Karst fleet** — ADR-0007 forecloses the revenue that would fund the
egress.

---

## 6. NAT traversal (`karst-disco`, **AVEN** protocol)

The hard, unglamorous part where most mesh VPNs actually fail. Budget generously.

**Normative specification: [spec/aven-v1.md](spec/aven-v1.md).** This section is
the summary; where the two disagree the spec governs. One point below is
tightened by it: probes are authenticated with a **per-pair disco key derived
separately from the PSK** (spec §5.1), and a node holding no disco key for a
peer does not probe it at all — the pair stays on the relay rather than
probing unauthenticated.

- **Endpoint discovery:** local interface enumeration, STUN against our relays
  for the server-reflexive address, and peer-reported observed addresses.
- **Discovery protocol:** small authenticated probe messages (`ping`/`pong`)
  carrying a call-me-maybe of candidate endpoints, sent over the relay to
  bootstrap and directly thereafter. Authenticated with a per-peer disco key
  so probes cannot be spoofed to redirect traffic.
- **Path selection:** continuous latency probing across candidate paths, with
  hysteresis to prevent flapping; prefer direct over relay, IPv6 over IPv4,
  lower latency over higher.
- **Hole punching:** simultaneous open, birthday-paradox port prediction for
  symmetric NATs, and port-mapping via **UPnP-IGD, NAT-PMP, and PCP** when the
  gateway offers them.
- **Test matrix** (netns + nftables, run in CI on every commit):
  full-cone, restricted-cone, port-restricted-cone, symmetric,
  symmetric-behind-CGNAT, hairpinning-broken, IPv6-only, NAT64/DNS64,
  double-NAT, and UDP-blocked (relay-only fallback).

Success criterion: **≥ 90% direct-connection rate** across the matrix,
with graceful, invisible relay fallback for the remainder.

---

## 7. KarstDNS

- Assigns each node `<hostname>.<aquifer>.karst.` names, resolvable only inside
  the mesh.
- The node agent runs a **local stub resolver on 100.100.100.100:53**,
  intercepting queries for the mesh suffix and forwarding others upstream.
- Platform integration is the actual work, and it is fiddly:
  `systemd-resolved` (D-Bus), `/etc/resolv.conf` direct rewrite,
  NetworkManager, macOS `/etc/resolver/` + `scutil`, Windows NRPT via
  registry/PowerShell.
- **Split DNS:** route specific domains to specific internal resolvers reachable
  over the mesh.
- Global nameservers, search domains, and per-node DNS overrides pushed via
  netmap.
- Handles the classic failure modes explicitly: VPN-flap leaving stale resolver
  config, DNS leaks to the LAN resolver, and captive portals. Each gets a test.

---

## 8. Admin console and user portal (React/TypeScript)

Shared component library, two apps, one design system.

**Stack:** Vite, React 19, TypeScript strict, TanStack Router + Query,
Tailwind, Radix primitives, generated OpenAPI client, Playwright for E2E,
Vitest for units. No state-management library beyond Query — server state is
server state.

### 8.1 Admin console (`karst-console`)

| View | Contents |
|---|---|
| Machines | Node list with status, version, OS, IPs, tags, expiry, last seen; per-node detail with live path status (direct vs relay), throughput, and route advertisements |
| Users | Roster, role assignment, IdP linkage, per-user device list, deprovision |
| Groups | IdP-synced and manual groups, membership, ACL usage cross-reference |
| Access controls | HuJSON editor with schema-aware autocomplete, inline lint, **preview diff of affected flows**, versioned history, rollback |
| Auth keys | Create/revoke, reusable/ephemeral/pre-authorized/tagged, expiry, usage audit |
| DNS | Nameservers, split DNS, search domains, MagicDNS toggle |
| Relays | Registry, health, region map, self-hosted relay onboarding |
| Bedrock | Key inventory, quorum config, pending node signing requests, signed-log viewer |
| Crypto posture | Per-node negotiated suite, PQ coverage percentage, flagged legacy/downgraded sessions, **lattice-only (PSK-absent) session indicator** (§2.6), minimum-suite enforcement |
| Audit log | Filterable, exportable (JSON/CSV), streaming to SIEM via webhook/syslog |
| Settings | Org profile, SSO config, SCIM token, key expiry defaults, webhooks |

The **crypto posture view is a differentiating feature, not a nicety.** The
entire value proposition is "your network is post-quantum" — the product must
be able to prove that claim, per-session, on screen, to an auditor.

### 8.2 User portal (`karst-portal`)

Deliberately small: download the client for your platform, see and name your
own devices, run the add-device flow, revoke a lost device, view which network
resources you can reach and why, and see your own session history. Nothing an
end user can do here should be able to affect anyone else.

### 8.3 Accessibility and quality bar

WCAG 2.2 AA, keyboard-navigable throughout, dark mode, no color-only status
encoding (a red/green dot for connection state fails colorblind users — pair
with shape and text).

---

## 9. Platform support

| Platform | Mechanism | Phase |
|---|---|---|
| Linux (x86-64, arm64) | `/dev/net/tun`, systemd unit, .deb/.rpm | 2 |
| Docker/Kubernetes | userspace mode, sidecar + operator | 4 |
| macOS | `utun`, LaunchDaemon, signed+notarized pkg; App Store NetworkExtension variant later | 5 |
| Windows | Wintun, Windows service, MSI, WinTUN driver signing | 5 |
| FreeBSD | `tun` | 6 (best-effort) |
| iOS / Android | NetworkExtension / VpnService, Rust core via UniFFI | 7 |

Mobile is where a greenfield Rust core pays off — one UniFFI-generated binding
serves both platforms — but it is still a full quarter of work per platform
including store review, background-execution behavior, and battery tuning.
It is correctly placed last, and the plan does not pretend otherwise.

---

## 10. Phased delivery

Assumes a team of **7–9 engineers**: 3 Rust (protocol/datapath), 2 Go
(control), 2 frontend, 1 security/crypto, 1 SRE/release (shared). Dates are
relative to a start of **2026-08-10**; adjust the anchor, keep the durations.

**Phases 0–3 are complete and carry no dates.** They were scheduled against a
2026-09-01 anchor that events overtook, and re-stating that schedule now would
be describing a plan rather than what happened — the record of what was
actually built and measured is in each phase's entries and in
[`docs/measurements/`](docs/measurements/). Dates below apply to Phase 4
onwards, anchored on the week of 2026-08-10.

---

### Phase 0 — Foundations (3 weeks) — ✅ complete

- Monorepo: Cargo workspace + Go module + pnpm workspace, unified via `just`.
  Nix flake for reproducible dev shells (optional to use, maintained).
- CI: GitHub Actions — `cargo clippy -D warnings`, `cargo deny`, `go vet`,
  `staticcheck`, `tsc --noEmit`, ESLint, unit tests, coverage gates.
- ADR process established (`docs/adr/NNNN-*.md`). Every decision in §2 gets one.
- [Threat model](docs/THREAT-MODEL.md) reviewed and signed off — drafted
  2026-08-09, covering all seven trust boundaries and eight residual risks.
- ⚠️ **NetBird fork-evaluation spike — substantially reported**
  ([Spike 0001](docs/spikes/0001-netbird-fork-evaluation.md)). No abort
  criterion tripped: identity refactor is 1.7% of files, well under the 30%
  threshold. Two amendments: **fork-and-diverge, not fork-and-track** (28% of
  upstream commits touch the divergence surface), and **delta netmap push is
  new work** — NetBird pushes full maps, and Karst's per-peer payload is ~100×
  larger. Outstanding: the running vertical slice, which needs Go and Rust
  toolchains.
- Licensing in place per [ADR-0007](docs/adr/0007-licensing.md): SPDX headers on
  every file, `LICENSES/` texts fetched from canonical sources, DCO sign-off
  check in CI, and `cargo deny` / `go-licenses` allowlists enforced.
- `SECURITY.md` with a disclosure policy and an explicit safe harbour for
  good-faith research.
- ✅ **Trademark clearance for "Karst" — complete, 2026-08-09**
  ([ADR-0010](docs/adr/0010-project-name-and-component-naming.md)). Remaining:
  register the mark, reserve package/org names before the first public commit,
  and publish a usage policy at first release. ADR-0007 leaves the mark as the
  project's only defensive instrument, so these are not optional tidying.
- **Exit:** `just check` is green on an empty skeleton; ADR-0001 through
  ADR-0010 (algorithm selection, hybrid rationale, greenfield rationale,
  MTU strategy, identity model, agility layer, licensing, relay
  infrastructure, control-plane fork, naming) are merged; the project has its final
  name; CI
  rejects a test commit carrying a GPL dependency and one missing a sign-off.

### Phase 1 — Crypto core and protocol spec (6 weeks) — ✅ complete

- 🔶 `karst-crypto`: **suite registry, downgrade protection, `Kem` trait and a
  working ML-KEM-768 backend done** (21 tests). Backend is RustCrypto `ml-kem`,
  not libcrux — see the ADR-0001 amendment; the choice is licence-driven.
  Remaining: signature/AEAD traits, ML-DSA-65, SLH-DSA, libcrux and aws-lc-rs
  backends, NIST KAT vectors.
- ✅ `karst-proto`: **fragment codec, §6.4 invariants, reassembly sublayer,
  fragment MACs and stateless cookies** (37 tests, panic-free, invariants
  asserted at compile time, fuzzed). The reassembler allocates all memory at
  construction and never grows, so a flood causes rejections rather than
  exhaustion. Remaining: `no_std`.
- ✅ **Fragmentation wired to the handshake**: a real 2378-byte `HandshakeInit`
  travels as two MAC-authenticated fragments and reassembles byte-exact, with
  anti-amplification measured on the wire (6 integration tests).
- ✅ `karst-node`: **per-peer session state machine** — idle → handshaking →
  established, with capped retransmission, rekey and expiry, and **outbound
  fragmentation** so every emitted datagram is MTU-legal. Plus a
  **deterministic simulation harness** (virtual clock, seeded PRNG, injected
  loss/reorder/duplication) — PLAN.md §11's Phase 2 ask, delivered early
  because it is what found the retry-policy defect (spec §13.5).
- ✅ `karst-noise`: **symmetric state, both handshake roles, transport phase**
  (47 tests). Two in-process peers complete a handshake and exchange
  authenticated data both ways, with replay and forgery rejected.
- Written protocol specification in `spec/phreatic-v1.md` — normative, with
  message diagrams, state machine, and all constants.
- ✅ **Verifpal models written and passing** — `phreatic.vp` plus
  `phreatic-kem-broken.vp` and `phreatic-dh-broken.vp`, which verify ADR-0002's
  "secure if either family holds" claim by breaking each family in turn. All
  6/6 under an active attacker, wired into CI.
- 🔶 **ProVerif**: base model and the X25519-broken variant both pass **4/4**
  (unbounded sessions; confidentiality, PSK secrecy, injective agreement,
  session-key agreement). The **ML-KEM-broken variant does not terminate**, so
  ADR-0002's either-family claim is proved for a classical break and only
  Verifpal-verified for a lattice break. Carried into the external review brief;
  see `spec/models/README.md`.
- ✅ **ProVerif model** (`phreatic.pv`) plus KEM-broken and DH-broken variants —
  **pulled forward from Phase 3**, base model passing.
- **Fragmentation DoS suite** (replaces the McEliece spike, now decided in
  ADR-0004): spoofed-source flood tests, reassembly-budget exhaustion,
  amplification-ratio assertions, `kani` proof obligations on the reassembler.
- `Kem` trait carries `KEY_DISTRIBUTION: InBand | OutOfBand` so the
  out-of-band-key profile (§2.6) stays expressible.
- ✅ **`cargo-fuzz` targets built and running** on all three
  pre-authentication surfaces: fragment codec, reassembler, and `respond()` —
  the handshake parser, which is the deepest, since it runs ML-KEM
  decapsulation, X25519 and an AEAD open on unauthenticated bytes. Clean at
  58.6M / 3.6M / 114k executions. **The handshake target is corpus-seeded from
  real messages** (`--example dump_corpus`); unseeded it stalled at the length
  check with 380 covered edges against 1038 seeded. Wired into CI; OSS-Fuzz
  enrolment outstanding.
- **Exit:** two in-process peers complete a handshake and exchange authenticated
  data; both messages fit in 2 fragments with the anti-amplification invariant
  asserted; a spoofed-source flood allocates zero responder state; **Verifpal
  and ProVerif both verify** secrecy, mutual authentication, injective
  agreement and no-PSK-downgrade, including under a total break of either
  cryptographic family; **✅ fuzzers clean for 24 core-hours** — 24.01 core-hours
  on 2026-08-10 (3 targets × 15 workers × 1921 s, ~6.7 billion executions),
  **zero crash artefacts**.

### Phase 2 — Node agent, first packets (8 weeks) — ✅ complete

- 🔶 **`karst-transport` — real UDP, first packets over the wire** (8 tests). A
  complete handshake and authenticated data exchange between two loopback
  sockets: a 2378-byte `HandshakeInit` split into two MTU-legal datagrams,
  MAC-verified, reassembled, answered, followed by data. Over-sized sends are
  refused locally rather than left to the kernel — IP fragmentation would defeat
  §5 and the DoS analysis built on it. Remaining: GSO/GRO and batched I/O.
- ✅ **Datapath concurrency — the first measured bottleneck (§3.4).** The engine
  sat behind one mutex, so every packet in both directions serialised on it.
  Replaced with per-peer session locks, atomic counters, and the reassembler off
  the outbound path; the engine now takes `&self` throughout and the run loop
  shares it by reference with no outer lock. **Measured: 298 → 393 Mbps** on a
  single flow. This had to precede GSO/GRO, which cannot recover concurrency
  already thrown away.
  - A compile-time `Sync` assertion and a threaded test guard the property: a
    regression to a global lock fails to build rather than merely running slowly.
- ✅ **Fragment MAC cost — found by profiling** (spec §13.8). `sha512_compress`
  was 23.4% of node CPU, five times the AEAD it gates, because §9.2's cost
  argument was written for the handshake and applied to the data path. The MAC
  now covers the header only, at constant cost. **Measured: 393 → 473 Mbps.**
  Flagged for external review — it is the one protocol change made on
  performance grounds rather than to fix a defect.
- ✅ **HMAC schedule pre-keyed per session.** Halves the remaining SHA-512
  (11.8% → 6.1% of CPU) by cloning a keyed state instead of re-absorbing the
  `ipad`/`opad` blocks per packet. **No throughput change** — which is the
  point: it proved the datapath had left the compute-bound regime and is now
  syscall-bound (63% kernel time). Kept because it is strictly cheaper and will
  matter once batching lands.
- 🔶 **Batched socket I/O** (14 tests). `sendmmsg`, `recvmmsg` and UDP GSO in
  `karst-transport`, using ADR-0003's `unsafe` allowance — confined to `sys.rs`
  with a `SAFETY:` note per block, as in `karst-tun`. **Measured: +3% only**,
  because a single flow gives `sendmmsg` nothing to group and both TUN syscalls
  are still per-packet (§3.4). Two real bugs found on the way, both described
  below.
  - **Receive-side UDP GRO is deliberately not enabled.** It coalesces datagrams
    and requires the receiver to parse a `UDP_GRO` control message to split them
    again. Enabled without that, every unit test passed and two real hosts went
    to **100% packet loss**.
- ✅ **TUN segmentation offload** — `IFF_VNET_HDR` + `TUNSETOFFLOAD`, with the
  coalesced-segment splitter in `karst-tun::vnet` (33 tests). One read now
  yields ~52 packets, cutting syscalls ~50×. **Measured: ~490 → ~540 Mbps.**
  Negotiated best-effort: a kernel that declines gets a plain device rather than
  no device.
  - The splitter rewrites IPv4 total length and identification, IPv6 payload
    length, TCP sequence, `PSH`/`FIN`, and both checksums per segment — every
    one of which fails *silently* when wrong, so it is a pure function tested
    directly, including verifying checksums the way a receiver does.
  - **`TUN_F_CSUM` sets `NEEDS_CSUM` on unsegmented packets too**, leaving only
    a pseudo-header partial sum. Passing those through unchanged broke TCP
    through the tunnel completely while ICMP kept working — `ping` fine,
    `iperf3` hung. Regression-tested.
- ✅ **Per-packet allocation and cipher setup.** `seal` now builds the whole
  message in one allocation with a detached in-place AEAD; ciphers are keyed
  once per session; the TUN write path uses `write_vectored`. **No measurable
  throughput change** — run-to-run spread exceeds the effect — but strictly less
  work per packet, and it ruled allocation out as the constraint.
- ✅ **AEAD moved outside the per-peer lock.** `TransportSession` synchronises
  itself — an atomic nonce counter, a mutex around the replay window alone — so
  `seal`/`open` take `&self` and the engine holds the peer lock only long enough
  to clone an `Arc`. **Measured: ~530 → ~707 Mbps (+33%)**, and multi-flow no
  longer falls below single-flow. That is **80% of this link's physical ceiling
  for one flow** (§3.4).
- ✅ **`karst-tun` — the Linux TUN device** (16 unit + 8 integration tests).
  Interface creation, MTU, flags and IPv4/IPv6 address assignment via `ioctl`;
  one bare IP packet per read (`IFF_NO_PI`); an adversarial-input inner-packet
  parser for peer selection. **Six of the tests run against a real kernel
  device** under `CAP_NET_ADMIN` — the host routes genuine IPv4 and IPv6 packets
  onto the interface and a full 1280-byte packet arrives whole. They are
  `#[ignore]`d by default and run by a dedicated privileged CI job, because a
  kernel-facing crate whose kernel tests never execute is a green suite over an
  untested datapath.
  - `unsafe` is confined to `sys.rs`, which carries the crate's only
    `allow(unsafe_code)`; every block states its argument, per ADR-0003. The
    packet parser — which reads bytes decrypted from a peer — cannot contain
    any.
  - **Sizing the interface exposed a contradiction in the spec.** Draft 0.2 set
    both the datagram cap and the tunnel MTU to 1280 while §8 promised transport
    messages never fragment; all three cannot hold, and the tunnel MTU cannot be
    lowered without breaking IPv6 inside the tunnel. Resolved in
    [spec §13.6](spec/phreatic-v1.md) — see §3.3 above.
- 🔶 **`karstd` — the node agent** (37 unit + 11 integration tests). Config,
  cryptokey routing, the datapath engine, and a threaded I/O loop over a
  sans-io core. **Two daemons in network namespaces route real IP traffic**:
  `ping` crosses the tunnel in both directions, and a 1280-byte packet with DF
  set crosses unfragmented — the §13.6 case, on a real kernel path. Wired into
  the privileged CI job.
  - **Cryptokey routing enforced in both directions.** Outbound by longest
    prefix; inbound, a packet from a peer whose source address that peer does
    not own is dropped and counted. Authentication proves a packet came from
    *some* peer on the roster — it does not entitle that peer to speak for
    another, and omitting the second check is the classic mistake.
  - Config refuses key material in files readable beyond their owner, redacts
    every secret from `Debug`, and rejects unknown fields rather than defaulting
    past a typo. `karstd genkey`/`pubkey`/`check` work before a roster exists.
  - **Building it found a protocol defect** — the fragment MAC was keyed by the
    handshake's *responder* rather than by each message's *recipient*, which is
    unimplementable for a node that plays both roles. Recorded as
    [spec §13.7](spec/phreatic-v1.md); the simulation harness now drives both
    ends through real sessions, which is what let the defect hide.
- ✅ Static peer config (no control server yet) — a hand-written TOML roster,
  documented in [docs/karstd-example.toml](docs/karstd-example.toml).
- ✅ **`karst` CLI and the local control socket.** `karst status` reports the
  interface, tunnel MTU (spec §13.6 requires it be reportable), listen address,
  per-peer session state and counters; `karst down` stops the daemon cleanly;
  `karst version`. The socket carries administrative access, so the directory
  is created `0700` **before** the bind — that, not the socket's own mode, is
  what closes the window in which it would otherwise be reachable. Status output
  carries no key material, which is tested rather than asserted.
  - `karst up` is deliberately absent: bringing the tunnel up means running
    `karstd` with a configuration, which is a service-manager job.
  - `ping`/`netcheck` remain outstanding — both belong with NAT traversal
    (Phase 4), not with a static roster.
- ✅ **Rekeying** (7 tests on a virtual clock). Sessions rekey at
  `REKEY_AFTER_TIME` **without interrupting traffic**: the live session stays
  usable until its replacement completes. Three defects found here:
  - the rekey **replaced** the session it was starting, stalling every flow for
    a round trip every two minutes — the code did the opposite of its own
    comment;
  - `established_ms` was hard-coded to `0`, so every session appeared to expire
    180 s after the *daemon* started, whatever time it was made;
  - a `HandshakeResponse` that failed to authenticate **destroyed the
    handshake**. `frag_mac` is keyed by a public key (§9.2), so an off-path
    attacker could have stopped every connection on the network from completing.
    `Initiator::try_finish` now advances the key schedule on a clone, so a
    forged response changes nothing.
- ✅ **Process-restart recovery** — a killed node rebuilds its tunnel unaided,
  including recovering from its own stale control socket. Under privileged CI.
- ✅ **An idle peer is re-dialled** — found while checking soak readiness.
  `connect_all` runs once at startup, so a session that expired
  (`REJECT_AFTER_TIME`, reachable via a single rekey lost to packet loss) or
  whose handshake gave up returned to `Idle` and **stayed there for the life of
  the process**. Over a 12-hour soak that is ~360 rekeys per peer and one bad
  sequence ends the run — worse, in production it is a tunnel that never comes
  back. `Engine::poll` now re-dials any idle peer that has an endpoint.
- ✅ **Interface-flap recovery** — three privileged tests in `two_nodes.rs`:
  - **underlay flap**: the veth is taken down, traffic stops, the daemon
    survives (`ENETUNREACH` on a send is an ordinary event, not a reason to
    exit), and the tunnel resumes unaided when the link returns;
  - **TUN flap**: `ip link set karst0 down/up` under a daemon holding the
    device's descriptor — the session is unchanged either side, since no key
    material was involved;
  - **an outage that outlives the session** (200 s, past `REJECT_AFTER_TIME`):
    the session expires, and the peer is re-dialled and rebuilds the tunnel.
    This one is the reason the re-dial fix above matters — without it the
    session sat in `Idle` and the tunnel never returned.
- ✅ **The simultaneous-rekey race — found only by the 12-hour soak, and the
  strongest argument for running it.** Both ends rekeyed on their own timer.
  Each then adopted the *other* side's handshake as responder while discarding
  the one it had initiated, so the two nodes ended up holding sessions derived
  from **different exchanges** and could no longer read each other. The tunnel
  recovered only when the broken sessions aged out at `REJECT_AFTER_TIME`.

  It cost **9 stalls of 253–765 s across 7.9 hours — 13.3% of samples** — and
  nothing reported it: `state` read `established` throughout and every counter
  sat at zero, because a packet that fails to decrypt was silently dropped.
  No unit test could see it either; both ends have to be real, on real clocks,
  for their timers to collide.

  **Fix: only the initiator rekeys** (`initiated: bool` on the established
  state). The responder stays passive; if the initiator disappears, the
  responder's session expires and it dials out itself, becoming the new
  initiator. This is WireGuard's rule and it exists for exactly this reason.
  Two tests pin it: the responder stays silent across eight ticks while the
  initiator rekeys, and across four successive rekeys. The re-run then held
  **~360 rekeys over 12 hours with zero loss**.
- ✅ **Soak harness** (`scripts/soak.sh`) — continuous iperf3 load, per-minute
  sampling of session state, counters, RSS and RTT, and a pass/fail verdict.
  Two harness bugs had to be fixed before it ran: `setsid ... &` left the ssh
  channel open so the script hung forever on the first daemon it started
  (`setsid --fork` returns once the parent has forked), and a `~` in double
  quotes expanded against the *local* home directory before being sent.
- ✅ **A `decrypt_failures` counter**, added because its absence is what made
  the rekey race below invisible. A sustained rate there means the two ends
  disagree about their keys — otherwise indistinguishable from a quiet peer.
- ✅ netns integration harness (`bins/karstd/tests/two_nodes.rs`) **and a
  two-host harness** (`scripts/two-host-test.sh`) that brings a tunnel up
  between real machines and measures it. iperf3 regression alarms in CI are
  still outstanding — CI has no second host.
- ✅ **Verified on real hardware, both architectures.** Two x86-64 hosts
  (48-core Xeon, Ubuntu 24.04) over a 3 Gbps bonded link, and an aarch64 VM to
  x86-64 **through NAT**. See §3.4.
- **Exit:** two Linux hosts on the same LAN route real IP traffic through
  Karst at **≥ 75% of the link's computed goodput ceiling**, survive a 12-hour
  soak with rekeying, and recover from interface flaps and process restarts.

  **The throughput bar was restated on 2026-08-13**, replacing "≥ 1 Gbps". The
  original number was written before any measurement and is not a statement
  about Karst on hardware like this: a 1280-byte tunnel MTU costs 11.6% to
  framing no matter how good the code is, and a 3×1G bond gives one flow one
  slave. 1 Gbps single-flow needs a link carrying ≥ 1.13 Gbps for one flow,
  which this lab does not have. A criterion no implementation can satisfy on
  the hardware it is tested on measures the lab, not the software.

  The replacement is **hardware-independent and falsifiable**:

  > `ceiling = (measured untunnelled single-flow goodput) × 88.4%`, where 88.4%
  > = 1240 bytes of TCP payload per 1402 bytes of wire time. Karst must reach
  > **≥ 75%** of that ceiling.

  The 88.4% figure is not a fudge factor — the same model predicts 941 Mbps for
  the untunnelled 1500-byte path against 943 measured. On this link the ceiling
  is 884 Mbps and the bar is 663 Mbps.

  **The absolute ≥ 1 Gbps number is not abandoned, it is deferred to Phase 7**,
  to be measured on a link whose single-flow capacity exceeds 1.13 Gbps. It
  sits with the ≥ 3 Gbps target in §3.3, which remains a 4× gap and is the
  honest statement of how far there is to go.

  **Status, measured 2026-08-13.**

  | Criterion | State |
  |---|---|
  | Two Linux hosts route real IP traffic | ✅ two 48-core Xeons over a 3 Gbps bond; 0% loss both ways, 0.75 ms RTT |
  | …at ≥ 75% of the goodput ceiling | ✅ **686 Mbps single-flow = 78% of this link's 884 Mbps ceiling** (from 298 Mbps, +130%). Sustained **720 Mbps mean over the full 12-hour soak**. See §3.4 |
  | …at ≥ 1 Gbps absolute | ⬜ **deferred to Phase 7** — needs a link carrying ≥ 1.13 Gbps single-flow. Not reachable here, and **not reachable as an aggregate either**: 4 flows give 708 Mbps against 686 for one (+3%), with both datapath threads at 70% CPU. See §3.4 |
  | Rekeying | ✅ no traffic interruption; 7 tests, and **~360 consecutive rekeys under continuous load in the 12-hour soak** with zero loss |
  | 12-hour soak | ✅ **PASS, 2026-08-12/13.** 700 samples over 12.0 h, 3.04 billion packets (~3.9 TB): 0 lost pings, 0 sessions lost, 0 malformed / decrypt / MAC / source-violation failures. **RSS flat at 5352 kB from the 6-minute mark onward — no leak.** Throughput by quarter 725/720/717/718 Mbps — no degradation. The run before it found the rekey race below (13.5% loss, 9 stalls in 7.9 h). Both series in [`docs/measurements/`](docs/measurements/) |
  | Recover from process restarts | ✅ under privileged CI |
  | Recover from interface flaps | ✅ three tests under privileged CI — underlay flap, TUN flap, and an outage outliving the session |

  Additionally verified, beyond what the criterion asks:

  - **Cross-architecture.** An **aarch64** node and an **x86-64** node
    interoperate, in both directions, including full-MTU packets with DF set.
    The full suite (199 tests) and both privileged suites pass on x86-64 as
    well as aarch64, so the hand-written `ifreq` layouts and the wire format
    carry across ABIs.
  - **Through NAT.** The aarch64 node sits behind NAT and is unreachable
    inbound. It is configured with no endpoint on the far side, and the
    responder learns it from the handshake — `192.168.68.79:61449`, a
    translated port. Traffic then flows *both* ways through that mapping.

### Phase 3 — Coordination server and netmap (8 weeks) — ✅ complete

- Go control server: schema, migrations, node registration, auth keys, OIDC
  login, netmap computation and delta streaming, IP allocation.
- Per-pair PSK derivation and epoch rotation; master key custody via KMS/HSM
  with a documented software fallback for small self-hosters.
- Encrypted netmap cache on the node (OS keystore or passphrase-derived key),
  with PSK material excluded from all logs, traces, and `karst bugreport`.
- Rust `karst-control-client` consuming the same OpenAPI spec.
- ACL parser, compiler, and evaluator with a large table-driven test suite.
- Audit log (append-only, hash-chained).
- ~~ProVerif model~~ — **moved to Phase 1** (§2.5).

  **Started 2026-08-13.** Spike 0001 is closed — its outstanding deliverable,
  the identity-separation question, was answered by compiler-driven measurement
  (§5.2a): making the identity opaque breaks 44 sites, of which a one-line
  `String()` method fixes 32, leaving **5 genuine crypto sites in 2 files**, all
  on the NaCl-box response path reached through one function (`parseRequest`).
  The separation is clean. Fork baseline verified: `netbirdio/netbird` at
  `f65f7b34` (v0.76.3) builds and runs under Go 1.24.6, gRPC + HTTP on one port,
  SQLite store, migrations clean.

  Both open questions were settled the same day: **GORM is inherited** and
  §4.1 amended, and the fork is **pruned to the management server on the way
  in** rather than vendored whole (35 MB → 9.6 MB, 586 files, 133 packages).

  **Control channel designed and the crypto core implemented.**
  [ADR-0011](docs/adr/0011-control-channel-authentication.md) replaces
  NetBird's NaCl-box envelope. The decisive constraint was found in this plan's
  own risk register: **the netmap carries per-pair PSKs**, so the simplest
  option — delete the inner layer and let TLS carry it — would hand every PSK
  in the network to any TLS-terminating proxy. The inner layer stays, and it
  becomes post-quantum.

  Landed in `server/management/internals/karst/channel/`, **15 tests passing**:
  the ML-KEM-768 double encapsulation (static for implicit server auth,
  ephemeral for forward secrecy), HKDF-SHA-512 key schedule with separate keys
  per direction, and the ChaCha20-Poly1305 record layer with sequence-number
  replay rejection. `crypto/mlkem` and `crypto/hkdf` are Go stdlib, so the KEM
  half needed no new dependency.

  **ML-DSA-65 landed** in `server/management/internals/karst/identity/`, on
  `cloudflare/circl` v1.6.5 — see §3.2 for why the standard library could not
  be used at the time, and for the 2026-08-18 migration to `crypto/mldsa` that
  replaced it. **28 tests** now pass
  across the two packages, including the channel driven end to end by real
  ML-DSA-65 rather than the Ed25519 stand-in.

  Measured handshake cost, asserted in `TestHandshakeSizes` so a regression
  shows up as a diff:

  | | Size |
  |---|---|
  | `ChannelHello` | ~1232 B |
  | `ChannelInit`, registration (identity presented) | ~7437 B |
  | `ChannelInit`, steady state (identity looked up) | ~5485 B |

  Signatures are **hedged** (FIPS 204 permits deterministic or randomized; the
  randomized form does not hand a fault-injection attacker a repeatable
  target), and carry a FIPS 204 context string so a control-channel signature
  cannot be replayed as a Bedrock countersignature over the same bytes.

  **The channel is served over gRPC** — `KarstControlService`, a bidirectional
  stream, in `server/management/internals/karst/control/`. **36 tests, race-
  clean**, running against a real gRPC server on a real socket with real
  ML-KEM-768 and ML-DSA-65: registration, many requests on one channel,
  concurrent independent channels, and the rejections — envelope before
  handshake, wrong identity, wrong pinned server key, re-handshake mid-stream.

  **It did not require editing the fork.** Diffing the vendored tree against
  the pruned fork shows **two changed files, `go.mod` and `go.sum`** — no
  forked `.go` file touched. The plan had assumed the refactor meant replacing
  `parseRequest` in forked code; Spike 0001 §5.2a's finding made a better
  option visible. The identity fusion is confined to the gRPC layer, and the
  business layer beneath it is string-keyed — `LoginPeer` and
  `GetAccountIDForPeerKey` take the peer handle as a plain `string`. So a
  *parallel* service reuses that layer untouched, and the 28%-of-upstream-
  commits cherry-pick surface measured in Spike 0001 §5.3 stays clean.

  **Registration reaches the business layer.** `LoginHandler` calls
  `accountManager.LoginPeer` with a Karst node handle, and the node gets back
  an assigned address. **50 tests, race-clean**, still with **no forked `.go`
  file modified** — the diff against the pruned fork remains `go.mod` and
  `go.sum` alone.

  The bridge between the two identity models is the **node handle**:
  `base64(SHA-256("karst-node-handle-v1" ‖ identity_pk))`, which is exactly 44
  characters — the length of a WireGuard key — so it drops into the forked
  schema's `peers.key` column and its uniqueness index without a migration
  change. A 1952-byte ML-DSA key could not. The full identity key lives in
  `karst_node_identities`, a Karst-owned GORM table, because verifying a
  signature on reconnect needs the real key.

  The handle is derived from the key the node **proved possession of** during
  the handshake, never from anything the request body claims, so a request
  cannot ask to be another node.

  **Validated against the real account manager, not a fake.** The earlier
  registration work was tested only against a one-method stub, which proves the
  contract Karst depends on but not that the real manager accepts a Karst
  handle. `TestRegistrationAgainstTheRealAccountManager` now builds the actual
  `DefaultAccountManager` over a real store from upstream's fixture and drives
  a node through the PQ handshake until a peer row exists:

  ```
  handle=WsQUzqj8sBBhwbsMHorhsymelZf9+NuNUxKHnlOFuMQ=  ip=100.64.226.32  dns=karst-node
  ```

  A 44-character handle in the WireGuard-key column, a real address from the
  100.64.0.0/10 range (§4.2 step 3), and the row retrieved by the fork's own
  unmodified `GetPeerByPeerPubKey`. **51 tests, race-clean.**

  Doing this exposed a **defect in the prune**: it had deleted all three
  `testdata/` directories, because fixtures contain no Go code and the prune
  walked the package graph. Neither `go build` nor `go vet` catches it — vet
  compiles test files but never runs them — so upstream's tests were silently
  unrunnable, which is the exact failure the prune's own rationale claims to
  prevent. 216 KB restored; the lesson is that a pruned fork needs its tests
  *run*, not merely compiled.

  **The control channel is modelled, and the model found a real flaw.**
  `spec/models/karst-control.pv` (ProVerif 2.05) now discharges four queries,
  including content secrecy in both directions under **post-session compromise
  of the server's static key**. Getting there required fixing the protocol.

  ADR-0011 had left `eph_kem_pk` unsigned, reasoning that substituting it makes
  the channel fail closed. Sound about authentication, worthless about forward
  secrecy: **the attacker rewrites `ChannelHello` so the "ephemeral" key is the
  server's own static public key**, read off the wire. The node then
  encapsulates both ciphertexts to one long-term key, and every recorded
  session decrypts when that key later leaks. The channel does die — after the
  node has already sent its auth key. The attacker needs no key material at
  all.

  Fixed: the server holds an ML-DSA-65 identity and signs
  `H("karst-control-hello-v1" ‖ server_random ‖ eph_kem_pk)`; nodes pin that
  verification key alongside the KEM key and abort before transmitting.
  `spec/models/karst-control-nofs.pv` drops `ss_eph` and is *expected* to fail
  the secrecy queries while still passing both authentication queries — an
  executable demonstration that the ephemeral encapsulation buys forward
  secrecy and nothing else. Both are wired into `just verify` / `verify-slow`.
  **54 tests**, race-clean, including a regression test for the exact
  substitution the model found.

  This is the argument for modelling before shipping, not after: the flaw was
  in a design that had already been reviewed, written up, implemented and
  tested, and no test would have caught it, because every test agreed with the
  same wrong reasoning.

  **Specified**: [`spec/karst-control-v1.md`](spec/karst-control-v1.md), draft
  0.1, alongside `phreatic-v1.md`. Normative message formats, key schedule,
  record-layer rules and error handling; §9 records the flaw above and §11
  lists seven open items, of which the largest — as with PHREATIC — is that no
  external cryptographic review has happened. Its constants were checked
  against the implementation rather than transcribed: every label, the nonce
  layout, the 16-byte key id and the measured message sizes agree.

  Handshake cost, asserted in `TestHandshakeSizes`: `ChannelHello` 4541 B,
  `ChannelInit` 7437 B registering and 5485 B in steady state — ~12 KB to open
  a channel against PHREATIC's 4614 B per session, affordable because it is
  amortised over a long-lived stream rather than paid per peer per rekey.

  **Per-pair PSK derivation landed** — `server/management/internals/karst/psk/`,
  implementing §2.6's `psk(A,B,epoch) = KDF(master, min(A,B), max(A,B), epoch)`
  over HKDF-SHA-512. Server state stays O(1). Handles are sorted so both ends
  of a pair derive the same key without coordinating, and every field is
  length-prefixed so `("ab","c")` and `("a","bc")` cannot collide onto one PSK.
  Master-key custody is a `Custodian` interface, so a KMS or HSM can hold the
  material and only ever perform derivations; `SoftwareMaster` is the
  documented fallback, and its doc comment says plainly why it is a fallback —
  Go cannot pin or reliably zero memory.

  **`psk.Key` cannot be printed.** `String`, `GoString`, `MarshalText`,
  `MarshalJSON` and `fmt.Formatter` all redact, so even `%x` and `%#v` yield
  `psk(redacted)`. Phase 3's exit criterion requires a scan of logs, traces and
  a bugreport to find zero PSK bytes; the reliable way to pass that is a value
  that is unprintable **by construction** rather than a rule every call site
  must remember. Twelve formatting routes are tested, including inside structs,
  slices and behind a pointer, each asserting the raw bytes, the hex encoding
  and an 8-byte prefix are all absent. **63 tests**, race-clean.

  **The netmap ships, and it carries PSKs.** `NetmapHandler` assembles a
  node's peers with their allowed IPs, DNS names, PHREATIC keys and a per-pair
  PSK, and returns them over the channel — the point at which ADR-0011 stops
  being an argument and becomes load-bearing. **75 tests**, race-clean.

  Building it exposed a gap in what registration collected. `phreatic-v1.md`
  §4 is explicit: *"A node MUST know, for every peer it may communicate with,
  that peer's `peer_id_hint`, `S_pk`, `D_pk` and current per-pair PSK. These
  are distributed in the netmap."* **`KarstLoginRequest` collected none of the
  data-plane key material** — only the ML-DSA identity, which PHREATIC
  deliberately does not use. A node could register, get an address, and be
  impossible for any peer to handshake with. Registration now requires the
  static ML-KEM-768 and X25519 keys and refuses a login without them, because
  the alternative failure mode is "the peer never appears in anyone's netmap",
  which looks like a routing bug rather than a registration error. They rotate
  independently of the identity, under the same handle.

  The properties the tests pin, each of which fails invisibly if broken:

  - **The PSK a node gets for a peer equals the one that peer gets for it.**
    Asymmetry here fails every handshake between them and presents as a key
    mismatch.
  - **Peer order is stable**, so a node can distinguish a real change from map
    iteration order — the precondition for delta push later.
  - **A node never appears in its own netmap**, and peers with no data-plane
    keys are omitted rather than shipped as unusable entries with live PSKs.
  - **The netmap is scoped to the authenticated identity**, never to anything
    the request claims, so a node cannot ask for PSKs it has no business
    holding.
  - **A derivation failure is an error, not a silent fall back to the all-zero
    PSK.** That fallback is a real security state (§2.6) flagged in the console
    as lattice-only; manufacturing it here would disguise a server bug as a
    degraded session.

  **The Rust node speaks the same protocol, and it is pinned to the Go server
  by vectors.** `crates/karst-control-client` implements the key schedule, both
  signing inputs, the record layer, handle derivation and PSK derivation, and
  `spec/vectors/karst-control-v1.json` — generated from the Go server's own
  code, not from a second implementation of the spec — holds it to them.
  **9 Rust vector tests**, and the two implementations agreed byte-for-byte on
  the first run.

  Scope is deliberate: **no gRPC transport yet.** Transport failures are loud —
  a refused connection, a status code. What fails *silently* is two
  implementations disagreeing by a byte: a label with the wrong text, a missing
  length prefix, the nonce in the wrong half of the buffer. None of that
  produces an error; it produces a handshake that never completes. So the part
  carrying the interop risk was built and pinned first, and adding `tonic` +
  `prost` to a deliberately lean workspace stays a separate decision.

  The vectors were **mutation-tested** rather than assumed to have teeth.
  Three realistic interop bugs, each injected and confirmed caught:

  | Injected bug | Caught by |
  |---|---|
  | Length prefix dropped from the hash | 3 tests |
  | Nonce written to the wrong half of the buffer | 2 tests |
  | The two direction labels swapped | key schedule |

  **Netmap versioning is now a content hash, and unchanged fetches cost
  nothing.** This began as delta push and found a defect first: the `version`
  shipped earlier was `known_version + 1`, which increments on every request
  whether or not anything changed — so it could never answer the only question
  a version exists to answer. It is now
  `SHA-256("karst-netmap-version-v1" ‖ epoch ‖ self ‖ peers)`, truncated to 64
  bits, so identical netmaps always yield the same version and any change
  yields a different one.

  A node whose `known_version` matches gets `unchanged = true` and no peer
  list. That is not a delta, and it is most of the value: a node polls
  repeatedly, the answer is usually identical, and re-shipping a 1184-byte KEM
  key and a PSK per peer each time is pure waste. It also keeps the O(1) server
  state §2.6 chose — a true delta needs bounded per-node history to say what
  *changed* rather than only whether anything did, and that is still open.

  Two properties worth naming:

  - **The version is not a function of secret material.** PSK bytes are
    deliberately excluded from the hash. A PSK is determined by (pair, epoch,
    master), so hashing the peer set and epoch detects exactly the same changes;
    feeding a secret into a value sent in clear buys nothing. Preimage
    resistance would almost certainly make it safe, and "almost certainly safe"
    is not a reason. A test changes the master and asserts the version does not
    move.
  - **`unchanged` is distinct from an empty peer list.** An empty list is a real
    state — a node alone in its network — that a node must act on by dropping
    every peer it holds. Conflating the two would leave a removed peer
    configured forever.

  **82 tests** on the Go side, race-clean; the 9 Rust vector tests still agree.

  **The PSK leak scan runs in CI**, closing part of the §2.6 exit criterion —
  the part that says explicitly *"the log scan runs in CI, not as a one-time
  check."* `TestNoPSKBytesReachTheLogs` drives a node through registration and
  a netmap fetch over the real channel with logging at Trace, then asserts none
  of the PSKs the server just distributed appear in the captured output as raw
  bytes, hex, upper hex, base64, base64url, a Go byte-slice literal, or an
  8-byte prefix.

  Its first version **captured zero bytes and passed**, which is the failure
  mode a leak scan must not have: a scan over an empty buffer is a tautology
  that reads as assurance. It now drives the branches that actually log — a
  malformed payload, a forged envelope, a failed handshake — and **fails if it
  captures less than 64 bytes**, so it cannot silently decay into a no-op. A
  companion test plants a real leak (`log.Infof("%x", k.Bytes())`) and asserts
  the scanner catches it.

  **Three CI gaps found while wiring this up:**

  - **There was no Go job at all.** 82 passing tests that CI never ran. Added,
    with `go vet` as well as `go build` — vet compiles test files, and the
    prune once dropped a test-only package that build alone could not see —
    plus an upstream smoke test that fails if the `testdata` fixtures go
    missing again.
  - **Vendoring the fork silently broke the `spdx` job.** It scans `server/`
    for `.go` files, so **587 of 652 files would have failed**. Upstream
    licenses per-repository, not per-file, and adding headers to 580 files is
    the opposite of fork-and-diverge. The scan now covers Karst's own additions
    under a `karst` path and leaves the fork alone: 65 files, 0 missing.
  - **Nothing checked Go/Rust wire agreement.** A `vectors` job now runs both
    sides on every commit, because a drift is a handshake that never completes
    and produces no diagnostic.

  **PSK epoch rotation is seamless**, closing a second part of the §2.6 exit
  criterion. Reading `phreatic-v1.md` §7.3 while implementing it showed the
  netmap was **non-compliant as built**: *"Responders MUST accept epoch n and
  n−1 and MUST reject any other"*, and the netmap shipped only epoch n.

  The consequence was worse than an outage. §7.3 resolves a missing PSK by
  falling back to 32 zero bytes, so a rotation would not have broken
  connectivity — it would have **silently downgraded the entire fleet to
  lattice-only** for as long as nodes disagreed about the epoch, with the only
  signal being the crypto posture view nobody was watching yet. A failure that
  looks like success is the expensive kind.

  Each peer now carries `psk` and `psk_previous`. The decisive test asserts
  that what a node is handed as `psk_previous` after a rotation is exactly what
  it held as `psk` before it — if those disagree, a peer mid-rotation is
  rejected. Epoch 0 ships no previous, because zeros there would be
  indistinguishable from the all-zero fallback, which is a real and different
  security state.

  The leak scan was extended in the same change: it checked only `psk`, so a
  newly-added secret field would have gone unexamined while the scan went on
  passing. **88 tests**, race-clean.

  **The node side of both landed too**, in `karst-control-client`:

  - **Epoch selection** implements §7.3's accept-*n*-and-*n−1* rule, and the
    rejection is as load-bearing as the acceptance: because §7.3 resolves a
    *missing* PSK with the all-zero fallback, accepting an arbitrary epoch
    would let an attacker name one the node has never held and steer every
    session into the lattice-only path. `epoch 0` does not wrap to `u32::MAX`,
    which is tested.
  - **`PskChoice` is an enum, not a `Psk`.** §7.3 says implementations "MUST
    NOT silently treat a zero PSK as equivalent to a real one". A function
    returning bytes lets a caller fall back and forget to flag it; different
    types mean the caller cannot reach the bytes without having named which
    case it got.
  - **The encrypted netmap cache** seals opaque bytes rather than parsing —
    a cache that understands the format is a second decoder to keep in step
    with the first. Tamper detection is tested by flipping every single bit in
    a sealed file. Key custody is the caller's, deliberately: keystore
    integration is per-platform and a password KDF is a tuning decision, and
    neither belongs behind an API that would hide a bad default.

  **262 Rust tests**, clippy clean at `-D warnings`, fmt clean.

  **The hash-chained audit log landed** —
  `server/management/internals/karst/audit/`, another listed Phase 3
  deliverable. Each entry commits to its predecessor, so modification,
  insertion, reordering or deletion from the middle all break the chain, and
  `Verify` reports *which* entry broke rather than merely that something did.
  Every field is length-prefixed, so two different events cannot hash
  identically by concatenating the same way. There is deliberately **no update
  and no delete method**: append-only is a property of the API surface rather
  than a convention, and an absent method is cheaper to audit than a correct
  one.

  **The honest limitation is tested, not buried.** A hash chain does not detect
  truncation of its own tail — delete the last k entries and the rest verifies
  perfectly, because nothing in it commits to how long it should be. That is
  inherent to the construction, and `TestTailTruncationIsNotDetectedByVerifyAlone`
  asserts it, so the property cannot quietly change without the documentation
  being wrong. `Head` returns an anchor to publish off-box and `VerifyFrom`
  checks it, which is what actually closes the gap; Bedrock's quorum signing
  (§4.5) is the intended long-term home for that anchor.

  **99 Go tests**, race-clean.

  **The ACL compiler landed** — `server/management/internals/karst/policy/`,
  the last of Phase 3's big listed deliverables to be started. Parses the
  §4.3 document, resolves groups and tags, and compiles a **per-node** packet
  filter. Per-node matters for more than size: a node learns nothing about
  rules that do not involve it, so the netmap does not leak the shape of the
  rest of the network. §4.3's table-driven suite is there — **111 Go tests**
  overall, race-clean.

  The decisions worth recording:

  - **Default deny, with no deny rule.** Every ACL is an accept, so ordering
    carries no meaning and the result is a union; a deny form would make order
    significant and is deliberately absent until something needs it. A filter
    with no matching rule denies, so a policy typo removes access rather than
    granting it.
  - **A rule whose sources resolve to nobody produces no rule**, never a rule
    with an empty source list — which a permissive evaluator could read as
    "any". An empty group is legal and grants nothing.
  - **An undefined group in `src` is a parse error**, not an empty match. The
    failure mode otherwise is a policy that reads correctly and silently grants
    nothing.
  - **A tag with no owners is rejected**: it can never be applied, so every
    rule naming it is dead code that compiles quietly to nothing.
  - **Tagged nodes are never group members.** Tags replace user ownership
    rather than adding to it, so a server's access does not follow whoever
    happened to enrol it.
  - **Destinations split from the right**: `tag:prod:22` is `tag:prod` on port
    22, not `tag` on `prod:22`. Writing it the other way would compile every
    tagged rule into something matching nothing.
  - **Compilation is deterministic.** Unsorted output would change the netmap's
    content hash on every recompilation and defeat the unchanged-fetch
    optimisation entirely.

  **The filter now ships in the netmap**, as §4.3 requires, and the netmap
  version covers it. That last part is not a detail: without it a policy edit
  would leave the version identical, every node would be told `unchanged`, and
  the new rules would never arrive — an edit that appears to apply and does
  not. A test asserts a policy change bumps the version and that a node holding
  the old one is not told nothing changed.

  A nil policy compiles to an empty filter, which is **default deny, never
  "unfiltered"**. A server that has not yet loaded a policy therefore denies
  traffic, and the symptom is a network that does not work rather than one that
  works too well. **115 Go tests**, race-clean.

  **OIDC registration landed** — the half of Phase 3's exit criterion that
  reads "a node registers via OIDC against a self-hosted server". The
  interactive flow itself (device authorization or PKCE, browser, IdP) is the
  fork's and is unchanged; what is new is carrying its result over the
  post-quantum channel and binding it to a Karst node identity. By the time it
  runs, the node has already proved possession of its ML-DSA key — the token
  answers *who the operator is*, which is a different question.

  Reading the fork's path closely mattered here. It calls `claimLoginToken`,
  which is easy to skip as bookkeeping and is in fact **single-use enforcement**:
  without it a captured ID token enrols unlimited nodes. It is kept, and
  **fails closed** when the claim store is unavailable, because proceeding
  would drop the guarantee at exactly the moment its enforcer is broken.

  The error taxonomy is deliberate, since each case tells an operator to fix
  something different:

  | Case | Code |
  |---|---|
  | Token invalid, or carries no user | `Unauthenticated` |
  | Valid user, no permitted group | `PermissionDenied` |
  | Token replayed, expired, or without an expiry | `Unauthenticated` |
  | Claim store unavailable | `Unavailable` |
  | Account resolution failed | *not* an auth code — the server is at fault, not the operator |

  **A token that fails validation is fatal and never falls back to the setup
  key.** Falling through would register the node with no user while the
  operator believes they authenticated as themselves. A server with no OIDC
  configured refuses a token rather than ignoring it, for the same reason.
  Group-sync failure is deliberately *not* fatal — membership refreshes next
  login, and an IdP hiccup should not become an outage.

  **128 Go tests**, race-clean.

  **True delta push landed, without giving up O(1) server state.** The obvious
  design — remember what each node was last sent — costs O(nodes x history) and
  forfeits the property §2.6 chose deliberately. Instead **the request carries
  the state**: the node sends one 8-byte digest per peer it holds, and the
  server replies with only what differs plus a list to remove. At 200 peers
  that is a 1.6 KB request against a ~480 KB response, and two servers behind a
  load balancer answer identically because neither remembers anything.

  The digest deliberately excludes the PSK bytes — a value the node computes
  and *transmits* must not be a function of secret material — and covers the
  epoch instead, which detects a rotation because a PSK is determined by
  (pair, epoch, master). **It follows that rotating the master without
  advancing the epoch would leave every digest unchanged and every node holding
  a stale PSK**; that constraint is recorded on the wire format itself.

  `delta` is a separate flag from "the peer list is empty", for the same reason
  `unchanged` is: a delta with nothing removed and a full netmap listing every
  peer are otherwise indistinguishable, and reading one as the other either
  strands removed peers or drops live ones.

  **The two implementations now actually talk.** `tonic` + `prost` are in, the
  Rust client is generated from the same `.proto` the Go server compiles, and
  `tests/interop.rs` spawns the real Go server and completes a real ML-KEM-768
  + ML-DSA-65 handshake over a real socket — including the negative cases: a
  wrong pinned verification key is refused *before anything is sent*, and a
  wrong pinned KEM key fails closed at the first envelope, because FIPS 203
  implicit rejection means it cannot be caught earlier.

  Three things this turned up:

  - **The RPC was named `Connect`**, which generates a client method colliding
    with tonic's own `connect` constructor. Renamed to `Session`: a protocol
    whose method names depend on the code generator is fragile, and nothing is
    deployed yet.
  - **The MSRV moved 1.85 → 1.88** for tonic 0.14. It was pinned in two files
    with no documented rationale anywhere; tonic 0.13 would have avoided it,
    and the newer version was chosen deliberately rather than by accident.
  - **Rust 1.88's clippy found a `single_match_else` in `karst-tun`** that 1.85
    did not. Fixed.

  **268 Rust tests** (264 plus 4 interop), **137 Go tests**, all clean.

  **`KarstControlService` is wired into the real daemon**, and still with **no
  forked file modified**. Two seams the fork already exposes do it:
  `cmd.SetNewServer`, which replaces the server constructor, and
  `BaseServer.RegisterGRPCExtension`, documented as "a generic extension point
  with no knowledge of any specific service". A new Karst-owned
  `server/cmd/karst-control` calls both; `management/main.go` is untouched.

  Verified against the running daemon, not a fixture: it registers the service
  on the real gRPC port, and a Rust node completes a post-quantum handshake
  against it and reaches the business layer, which correctly refuses an
  unregistered node.

  **Server keys persist, and that is the property that matters most here.**
  Nodes *pin* the public halves, so regenerating them on restart does not
  degrade gracefully — it breaks every enrolled node at once, each reporting
  that the server failed to authenticate. An outage that looks like an attack.
  They live in a singleton `karst_server_keys` row; a restart was checked to
  produce byte-identical pins.

  **The PSK epoch is a pure function of the clock** — `unix / 86400`, matching
  §2.6's rotation period. Every instance computes the same value, rotation
  happens on schedule with nothing to run, and a restart cannot lose its place.
  The cost is a dependence on the clock, and because §7.3 accepts *n* and
  *n−1*, the tolerance is exactly one full period: **24 hours of NTP skew**.
  That number is asserted in a test, because it is what an operator needs when
  deciding how much clock failure is survivable.

  Two defects the wiring exposed:

  - **`control.PeerLister` had the wrong shape.** Peer listing lives on the
    *store*, not the account manager — and the test fake satisfied the invented
    interface, so nothing caught it until real code had to implement it. The
    same class of gap `TestRegistrationAgainstTheRealAccountManager` exists to
    close for `LoginPeer`. Fixed with a `storePeers` adapter.
  - **`AutoMigrate` is not safe against itself.** Two replicas starting against
    a fresh database race, and the loser gets "table already exists" — so a
    deployment with replicas would crash-loop on first start. The migration
    error is now only fatal if the table is still unusable afterwards, which
    the subsequent read establishes. Found by a concurrency test, not in
    production.

  **144 Go tests**, race-clean.

  **The node holds a netmap, and enforces the ACLs in the datapath.**
  `karstd` gained `netmap` — the assembled network view — and `filter`, the
  compiled packet filter evaluated on every packet in both directions.
  `karstd` now depends on `karst-control-client`, so the wire types come from
  the same `.proto` the Go server compiles rather than a second definition.

  **The netmap has three shapes and they are not interchangeable.** A response
  is `unchanged`, a `delta`, or a complete set — and *all three can carry an
  empty peer list*, meaning something different by it each time. A node alone
  in its network gets a full netmap with no peers and must drop everyone; a
  node whose view has not moved gets `unchanged` with no peers and must drop
  nobody. Reading either as the other strands a removed peer forever or tears
  down a working network on every poll. Both flags are read explicitly and
  neither is inferred from emptiness, with a test per case.

  **The node checks the server's arithmetic.** After applying a response it
  recomputes the content hash over its assembled state and refuses one that
  does not reproduce the version the server reported. Without that check a
  disagreement would be **permanent and invisible**: the node reports a version
  describing a netmap it does not hold, the server answers `unchanged` for
  ever, and a peer added afterwards is never delivered — with nothing logged
  and no counter moving. The recovery is to discard the view and ask again from
  scratch, because a repaired view is one whose relationship to the server's is
  unknown.

  That made `netmapVersion` a **function both ends compute**, so it is exported
  as `NetmapVersion`, lives beside `peer_digest` in `karst-control-client`, and
  is **pinned by vectors** — four new cases, including two netmaps differing
  only by their PSK bytes, which must hash identically because the version is
  sent in clear.

  **The ACL work is in the datapath, not the server.** §4.3 makes the server a
  distributor of policy; `bins/karstd/src/filter.rs` is what enforces it.
  Two rule sets, and neither is derivable from the other — Karst's ACLs are
  unidirectional grants, so a node's inbound rules say nothing about what it
  may send. The netmap therefore gained an `egress_filter`, compiled by
  `Document.CompileEgress`, alongside the existing inbound one.

  The **receiver's** check is the one carrying the security property: a
  compromised peer will ignore its own filter. The **sender's** check makes a
  denied flow fail locally and immediately rather than vanish after a round
  trip, and keeps forbidden traffic away from a peer's cryptography entirely.
  Both are proven end to end through the real engine, not just in unit tests.

  Four things this turned up:

  - **Fragmenting would have been a filter bypass.** A non-first IP fragment
    carries no transport header, so its "ports" are two arbitrary payload
    bytes. `karst_tun::ip::ports` distinguishes *"this protocol has no ports"*
    — ICMP, which reports port 0 and is perfectly classifiable — from *"the
    ports cannot be established"*, which is denied. The same applies to an
    encrypted ESP payload and to an IPv6 extension chain longer than its cap.
  - **The version hash needed a separator between the two rule lists.**
    Concatenated, a rule moving from "who may reach me" to "whom may I reach"
    produces an identical byte stream: the version would not move, every node
    would be told "unchanged", and the inverted policy would never be
    delivered. A vector case now pins exactly that.
  - **"No policy" and "a policy granting nothing" are different states**, and a
    type that let them look alike would eventually let one be read as the
    other. `PacketFilter::unrestricted()` is the static TOML roster, which has
    no notion of an ACL; an empty netmap filter compiles to **deny-all**. They
    are separate constructors, render differently in `karst status`, and have a
    test each asserting the opposite verdict on the same packet.
  - **An empty source list must never widen to "any".** A rule naming only
    peers this node does not hold is discarded, not converted into a wildcard —
    the third occurrence of the same trap in this phase, after a nil policy and
    an empty peer list.

  **321 Rust tests** and **150 Go tests**, race-clean, with the fork still
  untouched: the only regenerated protobuf is Karst's own `karst_control.*`,
  which is a separate file from `management.proto` for precisely this reason.

  **The node now fetches its own netmap.** `karstd` gained `control` — the
  node's ML-DSA-65 identity, registration, the netmap fetch and the encrypted
  cache — and `Config::from_netmap`, which turns what the server sent into the
  same `Config` the TOML roster produces. That was the promise `config.rs` made
  in Phase 2 and it held: **the datapath did not change to accommodate the
  second source**, and nothing below `Config` can tell where a peer came from.
  The two sources are mutually exclusive, and a file naming both is refused
  rather than merged.

  `bins/karstd/tests/control.rs` drives it end to end against the real Go
  handlers on a real socket: a node with no configuration beyond a server URL
  and two pins registers, receives a netmap, and ends up with a routable
  configuration naming peers it was never told about, with the server's ACLs
  enforced and every PSK present. **That is the exit criterion's second and
  third clauses**, less the OIDC path, which has its own tests on the server
  side.

  Three defects, and the interesting ones are about what happens when something
  is wrong rather than when everything works:

  - **A node's own address needs the on-link prefix, and the server was not
    sending it.** Addresses were shipped bare, which parses as a `/32`: the
    interface comes up, the node has an address, *no peer is on-link*, and
    nothing routes. The symptom is indistinguishable from a handshake failure.
    The netmap now carries the account's `/16` and `/64`, read from the account
    rather than assumed — and a server that cannot read them **fails** rather
    than falling back to a bare address, because a node that comes up and
    reaches nothing is worse than one that does not come up.
  - **One unusable peer took down the whole netmap.** `node.Register` validated
    the data-plane keys by *length*, so a node could enrol 1184 bytes of
    anything, and that key was then shipped to every peer in the account. The
    node refused the entire netmap over it — so a single bad registration would
    take every node in the account off the network. Fixed at both ends: the
    server now **parses** the key (FIPS 203 gives the check for free, and the
    standard library already does it), and the node **skips** an unusable entry
    loudly instead of refusing the netmap. Skipping costs reachability to that
    one peer, which it costs anyway — nobody can handshake with a key that does
    not parse.
  - **A skipped peer is still reported as held.** The datapath drops it; the
    netmap keeps it. Claiming otherwise would make the server resend it on
    every poll for ever.

  Two properties worth recording because they are what an operator will lean
  on. **The node comes up on its cache when the server is down** — a
  coordination-server outage should not take every tunnel with it, and a netmap
  goes stale slowly. And the **cache is bound to the node's identity**, so
  copying it to another machine gains nothing; a cache that exists and will not
  open is reported loudly, because it means the sealing key changed and every
  later start will do the same.

  The control plane is the only async code in the daemon, on a current-thread
  runtime that never shares a thread with the datapath — `tonic` is async, and
  reimplementing HTTP/2 to avoid a runtime would be a poor trade.

  **344 Rust tests** (plus 9 needing a Go toolchain) and **153 Go tests**,
  race-clean, fork still untouched.

  **A netmap change now reaches a running daemon.** `Engine::reconfigure`
  swaps the peer set, the routing table and the compiled filter as one unit,
  and `karstd` polls for a new netmap on its own thread.

  **The point is what it does *not* disturb.** A peer present before and after
  keeps its live session and its learned endpoint. Adding one peer must not
  cost a rehandshake with every other: on a large aquifer a single enrolment
  would otherwise produce a fleet-wide reconnect, each costing two ML-KEM
  operations and a window where traffic is dropped for want of a session. "The
  same peer" means the same **KEM public key** — what `peer_id_hint` derives
  from and what a handshake actually authenticates — so a peer whose key
  changed is a different peer wearing the same name, and gets a fresh session.

  **A PSK epoch rotation does not interrupt anything**, which §7.3 requires in
  as many words. The running session keeps the keys it derived from the old
  PSK; only the *next* handshake uses the new one. A handshake already in
  flight completes against the PSK both ends agreed on, because it holds its
  own reference to the peer it started with — a property that fell out of the
  refactor below rather than needing to be arranged. Tearing sessions down on
  rotation would turn a routine scheduled event into a fleet-wide reconnect,
  which is the outage the two-epoch rule exists to avoid.

  Getting there meant **removing a lifetime that ran through three crates**.
  `Initiator<'a>` → `Session<'a>` → `Engine<'a>` all borrowed the node's static
  keys and the peer's public half, which pinned the entire peer set to one
  owner for the life of the process. They are now shared by `Arc` — not owned
  copies, because `StaticKeys` holds this node's private key and cloning it per
  peer would put the same secret in N places to be zeroized. The change is
  mechanical and the logic is untouched; the rekey and simulation suites, which
  are what caught the 9-stall rekey race, pass unchanged.

  The engine keeps its concurrency. The roster sits behind an
  `RwLock<Arc<Roster>>` and every method clones the `Arc` out on entry, so the
  lock is held just long enough to bump a refcount — not across the crypto,
  which is the thing PLAN.md §3.4 measured as flattening throughput completely.

  Two things worth recording:

  - **`PeerPublic` could derive `Clone` all along.** The engine carried a
    comment saying it could not, and rebuilt the key through its serialisation
    to work around it. That was true of an earlier KEM backend and had
    outlived it.
  - **Nothing in the refresh loop is fatal.** A server that has gone away, a
    netmap that will not configure a datapath, a cache that cannot be written —
    each leaves the node running on what it already had, which works. Taking
    the tunnel down because the control plane hiccuped would turn a
    coordination-server outage into a network outage, which is precisely what
    the cached netmap exists to prevent.

  **350 Rust tests** (plus 9 needing a Go toolchain) and **153 Go tests**,
  race-clean.

  **Routes landed**, over rtnetlink in `karst-tun`. Assigning an address gives
  the kernel a connected route for that address's on-link prefix and nothing
  else, so a peer *inside* the aquifer prefix was reachable for free and a peer
  outside it — a subnet router advertising `192.168.1.0/24`, say — was not.
  Worse than unreachable: without a route the kernel sends that traffic to the
  **default gateway**, so it leaves the host in clear rather than being dropped.

  `karstd` installs a route per off-link peer range and withdraws it when the
  peer leaves, diffing across a reconfiguration. Ranges already covered by an
  interface address are skipped — the kernel routes them from the address
  alone, and a duplicate would be noise in `ip route` for no effect.

  The FFI stays where ADR-0003 put it: `sys` carries the sole
  `allow(unsafe_code)` and every block states its argument. The **message
  encoding is a pure function returning bytes**, tested without privileges,
  because that is the part that fails invisibly: a mis-sized attribute or a
  forgotten alignment byte gets `EINVAL` back with nothing to say which field
  was wrong. The syscall half is then thin enough to read.

  Three things worth recording:

  - **`ESRCH` does not map to `ErrorKind::NotFound`.** Deleting a route the
    kernel does not hold answers `ESRCH`, which arrives in Rust as
    `Uncategorized` — so `remove_route`'s "already absent is not an error"
    branch matched nothing and would have failed on the exact case it was
    written to tolerate. Caught by the encoding tests, fixed by matching the
    raw errno.
  - **An add uses `NLM_F_REPLACE` as well as `NLM_F_CREATE`**, so re-adding a
    route a previous run left behind succeeds. Without it a daemon restart
    would come up missing routes and half its peers would be unreachable for
    no visible reason.
  - **Every request sets `NLM_F_ACK` and the reply's sequence number is
    checked.** Not waiting for the ack would make every failure silent; not
    checking the sequence would let one route operation succeed on the strength
    of another's acknowledgement.

  Verified against the real kernel: `/proc/net/route` and `/proc/net/ipv6_route`
  hold what was added, in both families, and no longer hold it after removal.

  **365 Rust tests** (plus 18 gated on a Go toolchain or `CAP_NET_ADMIN`) and
  **153 Go tests**, race-clean.

  **`karst bugreport` landed, and with it the last exit clause.**

  The design decision is what it *omits*. A bug report is the artefact most
  likely to be pasted into an issue tracker or a vendor's support portal, so it
  reports **facts about** the configuration and never the configuration itself.
  The tempting shortcut — "attach the config file so we can see what they set"
  — would ship every per-pair PSK in a TOML roster and the setup key with it,
  and whoever pasted it would have no way to know. So: no PSK bytes, no private
  keys, no identity seed, no setup key, no file contents. Peers appear as a
  name and eight bytes of `peer_id_hint`, which is enough to correlate two
  nodes' reports and not enough to be a key.

  What it *does* carry is chosen the same way. Whether a peer has a PSK is
  reported, because §7.3 requires a lattice-only session to be surfaced;
  the bytes are not, because the existence is the diagnostic and the value is
  the compromise. Peers the netmap carried and the node could not use are named,
  because from outside they are indistinguishable from peers the server was
  never told about.

  `bins/karstd/tests/leakscan.rs` is the node half of §2.6's scan. It learns
  from both mistakes the server half made: it **drives the code that would
  leak** — a real netmap with real PSKs, a datapath built from it, traffic
  through it, then every diagnostic surface including every `Debug` — and it is
  **checked against a planted leak**, without which finding nothing proves
  nothing.

  That check earned its place immediately: the scanner **missed a PSK written
  with `{:02x?}`**, a thoroughly plausible way to log a key, and would have
  passed while the leak went out the door. The encoding is in the list now.

  `karst bugreport` is also exercised over the real control socket on a running
  two-node tunnel, not only in the unit scan — the two catch different mistakes.

  **372 Rust tests** (plus 27 gated on a Go toolchain or `CAP_NET_ADMIN`) and
  **153 Go tests**, race-clean. The leak scan runs in CI on every commit, on
  both sides, because this is a regression that gets reintroduced rather than
  one that gets fixed once.

  **Phase 3's exit criteria are met**, with one qualification recorded honestly:
  the OIDC clause is proven on the server (`control/oidc.go` and its tests) and
  the node carries the token field, but no end-to-end run drives a browser
  through a real IdP — that needs a deployed IdP and belongs with the console
  work in Phase 5. Everything else is demonstrated end to end: a node registers,
  receives a netmap, reaches peers it was never manually configured for, ACLs
  are enforced at both ends, ProVerif verifies, the cache is encrypted, a PSK
  rotation completes without interrupting a session, and the leak scan is green
  with teeth.

  One known wart: `types.PeerLogin.WireGuardPubKey` now carries a Karst node
  handle, so the field name is a lie; renaming it is a forked-code change and
  so a cherry-pick cost, deferred deliberately.
- **Exit:** a node registers via OIDC against a self-hosted server, receives a
  netmap, and reaches a peer it has never been manually configured for, with
  ACLs enforced on both ends. ProVerif verifies.
- **Exit (netmap secret handling, §2.6):** the on-disk netmap cache is
  encrypted and unreadable without the node's sealed key; a PSK epoch rotation
  completes with no session interruption; and an automated scan of logs,
  traces, and a generated `karst bugreport` over a full registration-to-handshake
  run finds zero PSK bytes. The log scan runs in CI, not as a one-time check —
  this is a regression that gets reintroduced, not one that gets fixed once.

### Phase 4 — Relays and NAT traversal (10 weeks · Aug–Oct 2026) — 🔶 in progress

- ✅ **Ponor v1 specified** — `spec/ponor-v1.md`, normative, with framing,
  mutual post-quantum authentication, admission, presence, mesh and relay
  selection. §13 lists nine open items honestly; the two that matter are
  roster freshness/revocation, which §5.3 makes load-bearing and then does not
  specify, and §13.3 — that Ponor derives no session key, so the handshake's
  authentication does not extend to the frames after it. §1.2's argument for
  omitting an inner layer is about confidentiality and is correct; draft 0.1
  applied it silently to integrity, which it does not cover. Recorded rather
  than fixed, because fixing it means a session key and a record layer and that
  case should be made deliberately.

  Three decisions are worth surfacing out of it.

  **There is no inner encryption layer, and that is a deliberate asymmetry with
  KARST-CONTROL.** The payload is already PHREATIC ciphertext and TLS covers
  the hop. `karst-control-v1.md` §1.2 justified its inner layer by the netmap
  carrying PSKs past a TLS terminator the *server* was nonetheless trusted
  with; there is no equivalent secret here, and a third layer would hide
  metadata from a terminator but not from the relay, which is the party the
  metadata is disclosed to. §1.2 of the new spec records this so the next
  reader does not "fix" the inconsistency.

  **The relay is not authenticated by its TLS certificate** (§4.2). It signs
  with an ML-DSA-65 key published in the relay registry. Three reasons, of
  which the third is the practical one: WebPKI is classical and this would
  otherwise be the one hop in Karst with no PQ authentication; a certificate is
  no evidence of identity behind a shared load balancer; and the realistic
  self-hoster has an internal CA or a self-signed certificate, where pinning a
  key distributed through the netmap works and pinning a chain does not.

  **Admission control is structural rather than a mode** (§5.3). `ClientAuth`
  carries **no public key** — the relay verifies against the key it holds in
  its roster, so a relay with no entry for a node *cannot verify that node's
  signature at all*. ADR-0008 §6 requires signed-roster admission for pool
  relays and PLAN.md §5 had left it optional; carrying the key on the wire
  would have made "verify the presented key and let it in" a two-line change
  that looks like a convenience feature. It is now not expressible. The cost is
  real and named: roster distribution becomes a hard operational dependency.
- ✅ **`karst-relay-proto`** — the sans-io half, both roles, 35 tests.
  Frame codec written to the pre-authentication discipline (panic-free, no
  indexing, over-long frames rejected from four bytes of header before
  anything is sized from an attacker's length field), and the two handshake
  state machines with the client's verify-before-transmit ordering enforced by
  the type rather than left to the caller.

  **§10.1 came out of writing the code, not the spec, and is the more
  interesting half of §5.3.** Uniform rejection *responses* are not enough: the
  natural implementation returns on a failed roster lookup and pays for a full
  ML-DSA-65 verification only on a hit, and that difference is a
  roster-membership oracle readable from off the machine at one connection per
  guess. The relay now verifies against a decoy key on a miss so both paths do
  the same work. The claim is bounded in the spec rather than overstated — it
  closes the lookup asymmetry, not every asymmetry.
- ✅ **Ponor modelled — `spec/models/ponor.pv`, 4/4 in ProVerif 2.05**, seconds.
  Injective authentication in both directions for both roles, against an
  attacker that **operates a relay honest clients legitimately connect to** —
  which is not a contrived adversary but the community pool ADR-0008 §6 offers.

  **The broken variant this phase planned was the wrong one, and finding that
  out was the point.** The plan named `role` as the field to unbind. Building it
  showed role confusion is not reachable: `node_id` and `relay_id` are hashed
  under different domain labels, so the client and mesh directories have
  disjoint key spaces and a role-flipped `ClientAuth` names an id the other
  directory cannot contain. Binding `role` is correct and costs a byte, but it
  defends a misconfiguration, not an attack.

  The load-bearing field is **`relay_id`**, and `ponor-norelayid.pv` fails two
  queries to prove it. The trace: a rogue relay reads the honest relay's
  `relay_random`, replays it inside its *own* hello to a client that has the
  rogue legitimately pinned, and forwards the resulting signature to the honest
  relay — which admits the honest node. The rogue impersonates its own clients
  elsewhere. The client performs the §4.2 identity check in both versions;
  **checking who you are talking to is not the same as binding it into what you
  sign**, and that distinction is the whole of the difference.
- ✅ **The model gates now have teeth on both sides.** `check-proverif.sh` takes
  an expected count of *failing* queries, so the must-fail models are checked
  for still failing. Without it, a change that quietly stopped
  `karst-control-nofs.pv` or `ponor-norelayid.pv` from failing would turn each
  demonstration into a decoration and nothing would notice.

  Two gaps closed while wiring this up: **`karst-control.pv` was never in CI**
  — `spec/karst-control-v1.md` §10's "all four queries verify" rested on
  somebody remembering to run `just verify` — and neither must-fail model was
  either. All five ProVerif models now run on every commit; the
  broken-primitive variants stay nightly because they take minutes to hours.
- ✅ **`karst-relay` runs.** TLS 1.3 on a real socket, the HTTP upgrade, the
  Ponor handshake, forwarding, presence and rate limiting. 108 tests in the
  crate, 515 across the workspace; `cargo deny check` clean on all four checks.

  | Module | Section | What it is |
  |---|---|---|
  | `hub` | §7.2, §7.3, §7.5, §7.6, §8 | Forwarding, presence, mesh, queueing — sans-io |
  | `limits` | §7.4 | Two token buckets, bytes and frames |
  | `roster` | §5.3, §10.1 | Admission, and the decoy key |
  | `sign` | §5.2, §5.5 | ML-DSA-65 identity, hedged |
  | `tls` | §4.1, §4.2 | Post-quantum key exchange, enforced at startup |
  | `http` | §4.1 | The upgrade, hand-rolled and bounded |
  | `server` | — | The only module that touches a socket or a clock |
  | `config` | — | TOML, `deny_unknown_fields` |

  **The queues live in the hub, not in the I/O layer**, and that is the design
  decision worth defending. §7.3 makes queue discipline a *correctness*
  requirement — bounded, drop-oldest, never applying backpressure to the source
  — and a rule that lives in the code that touches sockets is a rule nobody can
  unit-test. `server` is left with genuinely nothing to decide.

  **The roster format derives rather than repeats.** An entry names an
  ML-DSA-65 public key and nothing else; both identifiers are computed from it
  (§5.1, §5.2). Storing the id alongside the key would make a silent mismatch a
  typo away, and its failure mode is a node that cannot connect for reasons no
  log line explains.

  **`X25519MLKEM768` is enforced, not documented.** `tls::provider` refuses to
  start if the build does not offer it, because the group comes from a Cargo
  feature and a feature is exactly what gets changed by somebody solving an
  unrelated build problem. TLS 1.2 is disabled outright: it cannot express the
  hybrid group, so leaving it on would leave §4.1 negotiable. And
  `tests/listener.rs` asserts the group that was *actually negotiated* on a
  live connection — the only place that claim can be checked.

  Two rules tightened while implementing, both now in code and tests: **a
  cross-aquifer destination is indistinguishable from an unknown one** (telling
  them apart is a cross-tenant membership oracle on a shared relay), and **a
  `Forward` from a mesh peer is re-checked against our own roster**, so a
  compromised meshed relay cannot inject cross-aquifer traffic. §8 had left the
  second implicit.

  **Three test layers, because each sees what the others cannot.** Unit tests
  use a stub signature scheme so they can be exhaustive. `tests/end_to_end.rs`
  drives the whole stack with real ML-DSA-65, which is what catches a
  mismatched context string or an identifier hashed under the wrong label — a
  stub agrees with the code that calls it by construction.
  `tests/listener.rs` adds the socket, which is what catches a frame split
  across reads, two frames coalesced into one write, and bytes arriving in the
  same segment as the HTTP head.

  **The rogue-relay case was checked against the defect rather than trusted.**
  Unbinding `relay_id` in the handshake makes exactly that one end-to-end case
  fail and the other eight pass — the same result `ponor-norelayid.pv` gives,
  now against the real signature scheme.

  **`cargo deny check advisories` earned its place.** `rustls-pemfile` — the
  obvious way to read a PEM file, and what most examples still show — is
  deprecated with no safe upgrade (RUSTSEC-2025-0103). The gate failed the
  build, and the dependency was replaced with `rustls-pki-types`' `PemObject`
  rather than allowlisted.

  Still open: **outbound mesh dialling** (the listener admits `role = MESH`
  peers, so the receiving half is done, but nothing dials a configured peer
  yet), Prometheus metrics, `Restarting` on graceful shutdown, and roster
  reload without a restart — which §13.2 makes the consequential one.
- 🔶 **`karst-relay`'s operational surface.** Metrics are done and mesh
  dialling's decision half is; the dialler's I/O, the region map and
  co-location with the control server in the default deployment artefact are
  not.

  🔶 **Mesh dialling — `mesh.rs`, sans-io, 8 tests.** Which peers are due, and
  how long to wait after a failure. The I/O half is not written.

  **§8 says what a mesh connection is and not who opens it, and that gap has a
  failure mode.** If both ends dial, both succeed, and the hub — which keys a
  mesh peer by relay id — replaces one with the other; two relays doing that on
  a timer displace each other indefinitely, resending the presence state on
  every flap. So **the relay whose id sorts lower dials and the other only
  listens**: deterministic, no negotiation, no extra frame, and half the
  connections in a region. A relay id is a hash of an ML-DSA-65 key, so the
  ordering is arbitrary and stable, which is all the rule needs.

  The consequence is a configuration rule worth stating: **every relay in a
  region carries the whole mesh list, addresses included**, and the rule
  decides who acts. An asymmetric file is a puzzle with a silent failure — the
  pair simply never meshes.

  The address is optional and a row without one is still admitted. A relay
  behind a load balancer may be dial-in only, and refusing to admit one nobody
  can dial would make the common cloud deployment unconfigurable. It lives on
  `FileRoster` rather than on `karst-relay-proto`'s `RelayEntry`: where to dial
  a relay is a deployment fact, and a second implementation of Ponor needs the
  identity key and nothing about our topology.

  Two properties the tests pin that are easy to get wrong. A dial in flight is
  not dialled again on the next tick — `due` marks the attempt as it hands it
  out, or every tick between a dial and its outcome starts another. And backoff
  **survives a roster reload**, or a relay refreshing on a timer retries a dead
  peer at full rate for ever, the reload undoing the state meant to slow it.

  ✅ **Prometheus metrics**, on their own listener and off by default. Two
  decisions worth recording.

  **Its own port, and `validate` refuses to let it share the client's.** A
  metrics endpoint on the Ponor listener would put an unauthenticated `GET` on
  the socket carrying the tailnet's traffic, and §5.3's admission is structural
  precisely so that port answers nothing it cannot verify. A misconfiguration
  that shows up only as a strange response to a scraper is worth refusing at
  startup.

  **No per-node labels, and that is disclosure rather than cardinality.** A
  relay in a public pool carries thousands of nodes; a label per node is a
  cardinality problem, but the reason it is forbidden is `ponor-v1.md` §11 —
  an endpoint naming every node by id would publish the tailnet's membership to
  anything that could reach it. There is a test asserting no metric carries a
  label at all.

  The counters had to become monotonic to be useful: `ConnStats` lives on the
  connection and dies with it, so `Hub` now folds a departed connection's
  totals into a retained sum. A counter that falls every time a client
  disconnects reads downstream as a relay restart.

  Rendered by hand rather than through a client library, as `http.rs` beside it
  is: the text format is three lines of rules, and a registry plus a macro layer
  plus a transitive tree is a poor trade in a network-facing daemon where every
  dependency goes through `cargo deny`.

  Checked against the defect: wiring `Hub::totals` to return zero fails
  `the_metrics_endpoint_counts_traffic_the_relay_carried` and nothing else —
  the unit tests render a `Snapshot` somebody constructed and cannot see it.
- ➡️ **TURN fallback — slipped to Phase 6 on 2026-08-20**, exercising the
  option this bullet reserved rather than quietly carrying it.

  The condition it named was met: the NAT matrix work overran, and it overran
  productively — the matrix went from nine rows to thirteen, the `karstd`
  topologies from three to ten, and four defects came out of the extension that
  no unit test could have found. Compressing that to protect a TURN schedule
  would have been the wrong trade, which is precisely what the slip clause
  existed to prevent.

  **The base case is covered without it.** ADR-0008's argument was that the
  co-located relay handles ordinary deployments and TURN buys interoperability
  with third-party infrastructure. Ten topologies now say the relay path is
  automatic and lossless, including the two where no direct path exists at all.
  Nothing in Phase 4's exit depends on TURN.

  Carried forward whole: client-side allocation, permissions, channel binding
  and credential refresh; control-server ephemeral credential minting; coturn
  added to the NAT matrix.
- ✅ **AVEN v1 specified and its codec built** — `spec/aven-v1.md` and
  `crates/karst-disco/`, 51 tests. The NAT-traversal protocol gets a themed
  name per ADR-0010's rule (an *aven* is the shaft connecting a cave system
  upward to the surface); it is a rename away from anything else if the name
  does not appeal.

  **Sharing a socket with PHREATIC is the hard part, and it has no free
  answer** (§4). Disco must run on the same UDP socket and port as the data
  plane — a NAT binding proven on one port says nothing about another — so the
  two protocols need demultiplexing. Neither obvious mechanism works.
  `phreatic-v1.md` §5 begins every datagram with a **CSPRNG-drawn**
  `reassembly_id`, so no fixed magic is reliable; and §2 makes reserved fields
  **ignored on receipt rather than rejected**, deliberately, so no reserved-bit
  pattern makes a datagram invalid PHREATIC either. What actually separates
  them is that **both are authenticated**: each MAC is 16 bytes, so a
  cross-protocol acceptance needs a forgery rather than a coincidence. The
  magic is a hint that makes the common case cost one MAC instead of two, and a
  receiver MUST fall through when it is wrong. Cost, stated: junk forces two
  MACs instead of one.

  **An absent disco key means no discovery, ever** (§5.1). This is the one
  place §2.6's zero-PSK fallback is deliberately *not* mirrored: connectivity
  survives without discovery because the relay carries it, so nothing is bought
  by relaxing, and unauthenticated probing would let an attacker tell a node
  where to send its traffic — which is the whole of what this protocol decides.

  **The sender is named by an 8-byte rotating tag, not a node id** (§5.2).
  A cleartext handle on every probe would give back what ADR-0005 spent a
  design decision buying. The tag also keeps an unmatched datagram to one map
  lookup rather than one MAC per peer, which at 200 peers would be a 200×
  amplifier any unauthenticated source could pull.

  **§7.1 is the rule the crate exists to enforce:** a `Pong` confirms the
  endpoint its `Ping` was sent *to*, never the address the `Pong` arrived
  *from*. `PathSet::on_pong` takes a transaction id and no source address, so
  the mistake is not expressible rather than merely tested against — an
  implementation with that parameter can be walked to any address an on-path
  attacker likes by copying a genuine `Pong` and re-sending it.

  **§8.1 came out of the implementation disagreeing with the spec.** The spec
  says IPv6 wins *within the hysteresis margin* — a tie-break. The first
  implementation made it a hard ordering, and the test written from the spec
  caught it. The deeper problem surfaced in fixing it: "within the margin" is
  **not transitive**, so a comparator written that way can rank A over B over C
  over A, and a minimum over a non-transitive comparator returns whichever
  element it saw first. Path selection would have varied between runs on
  identical inputs. It is now a latency credit, which is a total order.

  The hysteresis tests were checked against the defect rather than trusted:
  dropping the three-consecutive-wins requirement fails exactly the three
  hysteresis tests and nothing else.
- ✅ **AVEN modelled — `spec/models/aven.pv`, 4/4 in ProVerif 2.05.** The
  attacker holds **a different peer of A's disco key** throughout, because a
  aquifer is not a trust boundary (§1.1 lists a malicious peer inside one as in
  scope).

  **The model found a reflector, and draft 0.1 of the spec had no defence.**
  The injective form of "the responder answers only probes the prober sent"
  came back `is false`, with ProVerif noting the non-injective form is true —
  which in words is: *the responder answered a `Ping` the prober really did
  send, more than once.* A `Ping` is authenticated, so it cannot be forged;
  that is true, and it is not the same as saying a genuine one cannot be
  **replayed**. Anyone able to capture one datagram can replay it from any
  address, and the responder answers each copy to wherever the copy came from.
  46 bytes in, 65 out.

  The amplification factor of 1.4 is small, and saying so is part of reporting
  it accurately — this is not a bandwidth attack. It is fixed anyway because
  the fix is free, because it lets an unauthenticated attacker spend a peer's
  probe budget under someone else's name, and because a reflector in a protocol
  running on an open UDP port on every node is not a thing to ship knowingly.
  Spec §7.4 is the rule; `PathSet::on_ping_received` is the implementation, with
  a bounded window so the cache cannot itself become the exhaustion vector.

  **What the model does not claim** is stated in §11.1. Expressing the replay
  rule needs a table and a lock, and adding them makes ProVerif answer "cannot
  be proved" on both agreement queries — in the base model *and* in the broken
  variant, where a demonstration that cannot fail demonstrates nothing. So the
  model stays at the forgery-and-impersonation level, which it proves, and the
  replay half is carried by the implementation and its tests.

  **`aven-headeronly.pv` records a decision that must not be inherited.**
  `phreatic-v1.md` §13.8 took the fragment MAC off the payload on the data
  path — deliberately, after profiling showed it costing five times the AEAD it
  gated. The variant shows what the same saving would cost here: with `tx_id`
  outside the MAC, an attacker rewrites it on a captured `Pong` and confirms a
  path the peer never answered from. Both agreement queries go false, with a
  trace.

  **The variant passed on the first attempt, and that was the bug.** An
  unrelated edit changed the model's indentation and one of the generator's two
  `sed` expressions stopped matching, so only the verifier side was weakened;
  the prober then rejected every genuine `Pong`, nothing was confirmed, and all
  four queries passed **vacuously**. A must-fail model that passes is a signal
  to go and look. `spec/models/README.md` records it, because the failure mode
  is silent and general.
- 🔶 **`karst-disco` probe scheduling** — `engine.rs`, 69 tests in the crate.
  Sans-io and sans-clock like everything below it: `poll` takes a millisecond
  stamp and a closure that mints transaction ids, so a test runs an hour of
  scheduling in a loop with a counter for a CSPRNG and gets the same answer
  every time.

  **Simultaneous open is the one piece of hole punching that lives at this
  layer.** A `CallMeMaybe`'s candidates are probed on the same poll rather than
  on the backoff schedule, because the peer received ours at nearly the same
  moment and is doing likewise — both NATs then see an outbound packet before
  either sees an inbound one, which is the whole trick. A scheduler that
  politely staggered these would defeat it.

  **A mutation test found a weak test rather than a weak implementation**, which
  is the more useful outcome. Flipping the immediate-probe flag off failed only
  one case: for a brand-new candidate the probe is due immediately regardless,
  so the obvious test passes whether the flag works or not. The flag only
  matters for a candidate already waiting out a backoff — the common case,
  where the first probe went to a stale address and the peer has just said
  where it really is. That test now exists and the mutation fails two.

  Two ordinary bugs, both caught by tests written from the spec: the re-probe
  sweep fired on the very first poll and sent every candidate twice, and the
  give-up condition was off by one against §7.5's "immediately, then
  100/300/900".
- 🔶 **The node speaks Ponor, and the netmap carries what discovery needs.**
  `bins/karstd/src/relay.rs` and `relay_tls.rs` are the node half of the
  handshake `karst-relay` already answers: TLS 1.3 with `X25519MLKEM768`
  enforced at startup, the HTTP upgrade, and the pinned ML-DSA-65 Ponor
  identity. The control plane grew two things to feed it — a per-pair
  `disco_key` and a relay registry — and both are now part of the netmap
  version hash on both ends.

  **The disco key is derived under its own label, not reused from the PSK**
  (`psk.Disco`, `karst-disco-v1`). Reusing the PHREATIC PSK would have cost
  nothing to write and would have coupled two independent authenticators, so a
  change to either protocol becomes a cross-protocol key-reuse bug. The Go test
  asserts the two are *unequal* for the same pair, not merely that each is
  derived.

  **A relay entry is checked against itself while the netmap is decoded.**
  `ponor-v1.md` §5.2 defines `relay_id` as a digest of the pinned identity key,
  so `Relay::from_wire` recomputes it and refuses a mismatch. The alternative is
  a registry typo surfacing much later as a handshake failure with nothing in
  any log to explain it.

  **The registry is in the version hash, and the test that matters is the
  negative one**: a node holding the pre-change version must not be told
  "unchanged", or it stays pinned to a retired or compromised relay while every
  poll says its netmap is current.

  `tls_server_name` is carried separately from `address` and §4.2 was amended
  to say so — a self-hoster reaches a relay by IP or through a load balancer
  while the certificate names something else, and Ponor authenticates by the
  ML-DSA key either way.
- ✅ **AVEN closes end to end — two nodes rendezvous over the relay and confirm
  a direct path.** `Disco::reconcile` loads per-peer disco keys from the netmap,
  the node enumerates its own interfaces, the scheduler advertises them, the
  relay carries the advertisement both ways, both ends probe on the same poll,
  and a confirmed path is installed as the peer's endpoint.

  **The test that matters is `tests/rendezvous.rs`**, and the reason it exists
  is that every layer below it had passing unit tests for weeks while the slice
  did nothing: the scheduler produced advertisements nobody carried, the relay
  carried datagrams nobody produced, and selection ran over a candidate set that
  was always empty. Each layer agreed with itself. Nothing looked at the join.

  The fixture found its own version of the same mistake — the first draft
  delivered relayed advertisements and dropped the probes that `poll` returned
  alongside them, and the symptom was one node confirming a path while the other
  silently did not. That is the shape of the whole bug class here, reproduced in
  a test harness in about twenty lines.

  **A relay-carried advertisement has its own entry point, and that is the
  design decision worth defending.** `inbound_from_relay` is separate from
  `inbound` rather than a flag on it, because the two differ in what they are
  allowed to authorise: the AVEN tag proves *who wrote* a message and says
  nothing about whether an arbitrary UDP source is a permitted delivery path for
  a fresh endpoint list. It additionally requires the relay-stamped source id
  and the tag to name the same peer, so one admitted peer cannot replay
  another's authentic datagram under its own relay identity. A relay carrying a
  `Ping` or `Pong` is refused outright.

  **The case that pins that rule is an admitted peer, not a stranger.** The
  first version of the test replayed under an id the node had never heard of,
  which the lookup refuses on its own — so the test passed with the comparison
  deleted. It now uses a peer the node holds a key for, which is the only
  version that fails when the binding is removed.
- ✅ **Candidate gathering, and where the policy lives.** `karst_tun::
  local_addresses` dumps `RTM_GETADDR` and reports what the host holds; the
  daemon decides what is worth advertising. The split is not cosmetic: scope,
  tentative and deprecated are facts about an address — a peer cannot reach any
  of them — while "is the node's own overlay address" is a fact about *this*
  system, and only `karstd` knows what the tunnel is. Advertising a tunnel
  address as a way to reach the tunnel is a loop.

  It lives in `karst-tun` because it needs `AF_NETLINK`, and ADR-0003 puts every
  `unsafe` call in that crate. Anywhere else would mean a second file carrying
  an `unsafe` allow, which is the property that decision buys. The parser is a
  pure function over bytes, tested against a truncation sweep and every
  single-byte buffer, because a malformed dump must cost candidates rather than
  the daemon.

  **`IFA_LOCAL` is read in preference to `IFA_ADDRESS`.** On a point-to-point
  interface the second holds the *peer's* address, and a node that advertised it
  would name somebody else's host as a way to reach itself. It is one line and
  it has its own test.

  A private RFC 1918 address is deliberately kept: two nodes on the same LAN
  behind the same NAT have no other way to find each other, and that is the case
  direct paths help most. §12.3's cost — a `CallMeMaybe` body is not
  encrypted, so the relay operator sees them — is a protocol gap to close, not a
  reason to withhold the candidate that makes local discovery work.
- ✅ **§7.2's reflexive addresses, and the rule the spec was missing.** A node
  behind a NAT never sees its own mapped address; it learns one only from a peer
  that answers a probe. Draft 0.1 said to collect them and said nothing about
  what they compete with — and the list a node builds goes to *every* peer, so
  one peer supplying sixteen fabricated `observed` values would decide what this
  node tells everybody else about itself.

  §7.2 now says interface addresses win the slots and reflexive addresses take
  what is left, and that where several peers report, the most-reported wins. A
  node behind one NAT hears the same mapping from everyone that answers it, so
  agreement is evidence and a single liar is outvoted. With one peer there is
  nothing to cross-check against, which is why the count orders the list rather
  than deciding admission to it.
- ✅ **§12.6 closed** — see the candidate-cap entry below. It is the only one of
  the seven open items in that section that this phase resolved; the other six
  stand.
- 🔶 **Two defects found by review rather than by tests, both now closed.**
  Recorded here because each was invisible to a passing suite, and because the
  shape of both is the same: a boundary that could only express half of what it
  needed to say.

  **A released path had no way to reach the datapath.** `PathSet::select`
  clears the chosen path as soon as nothing is usable, deliberately — but the
  daemon read a *snapshot* of the chosen paths, and a snapshot can only say
  "install this". A direct path that died left the datapath pointed at a dead
  address for the lifetime of the process, which made AVEN a net connectivity
  regression. `Disco::path_changes` now emits transitions, and the two
  directions are deliberately asymmetric: an install displaces whatever was
  there, because a confirmed path beats a learned address; a release is a
  **compare-and-swap**, because the endpoint has a second writer and a peer that
  has just handshaked from elsewhere is better evidence than discovery going
  quiet.

  **Confirmed paths were exempt from the candidate cap**, so every address that
  ever answered a single `Ping` held a slot for good — sixteen fresh addresses
  per interval from a peer with a /64, each answered once, growing the set and
  the per-tick scan over it without limit. The cap now lives in `PathSet`, which
  owns the vector, and eviction runs unconfirmed-first then stalest-confirmed,
  never the path in use. **A length assertion was not enough to pin it**, and
  the first version of the test made that mistake: exempting confirmed paths and
  then refusing new ones bounds the length too, by locking the set to whichever
  addresses answered first — which is a peer pinning us to addresses of its
  choosing. Each clause of the policy now fails a test when removed.
- ✅ **`crypto/mldsa`, and the shim that was built to be deleted was deleted.**
  Go 1.27 shipped the public package ADR-0011 was waiting for; §3.2 has the
  migration and its byte-compatibility check. Recorded under Phase 4 because it
  happened here, not because it is Phase 4 work — it closes a dependency the
  control plane took on in Phase 3 and always intended to give back.
- `karst-disco`: **port mapping (PCP, NAT-PMP, UPnP-IGD). Port prediction is
  recommended for removal** — see FINDINGS.md 24.

  Both were listed here as complementary. Measurement says they are not: Linux's
  symmetric modes scatter external ports across the whole ephemeral range with
  no locality — 24 distinct ports over 24 destinations, not one adjacent pair
  within ±8 — so there is no window for prediction to probe, and RFC 6056
  recommends exactly that unpredictability. Prediction also collides with
  `aven-v1.md` §7.5's normative rule against emitting more probe traffic to a
  peer than it has authenticated to us, which is the rule that stops a malicious
  peer using our probe budget against a third party.

  Port mapping survives the same scrutiny. It extends candidate gathering with a
  port the NAT is holding open **on purpose**, it is deterministic rather than
  probabilistic, and it can be tested against a third-party server rather than
  one we wrote.
- ✅ **`karst-portmap` — the codec for both protocols, 41 unit tests and four
  against a real gateway.** Sans-io like every other protocol crate: bytes to
  typed values and back, plus the renewal arithmetic. No socket, no clock, no
  gateway discovery.

  **The integration test is the point of the crate, not an extra.** A
  round-trip test proves the encoder and decoder agree with each other, which
  is exactly what a shared misreading also produces — and a shared misreading is
  the likely failure here, because these are byte-offset protocols with no
  length fields and nothing self-describing. So `tests/gateway.rs` drives
  **miniupnpd** in a namespace and asserts against what an implementation we did
  not write says. Same argument as the NAT matrix, one layer up.

  It earned its keep twice within an hour of existing.

  It found a **wrong result-code table**: PCP code 4 was listed as "network
  failure", which is 7 — 4 is `UNSUPP_OPCODE`. A gateway that does not implement
  `MAP` would have been retried forever while a genuinely transient failure was
  given up on after one attempt. Both the right and the wrong set look
  reasonable in a diff, which is why it took a real gateway to surface.

  And both mutations of the encoder are caught by it. Sending the wrong client
  address in a PCP `MAP` draws a real `ADDRESS_MISMATCH` (code 12) from
  miniupnpd — the RFC 6887 §8.1 check, performed by somebody else's code.
  Transposing NAT-PMP's internal and suggested-external port fields fails the
  mapping row, but only because the test deliberately asks for two *different*
  numbers; requesting the same port on both sides makes a transposition
  invisible.

  One boundary worth recording. **UPnP-IGD is not in this crate**: it is SOAP
  over HTTP over SSDP, three protocols and an XML parser, against two that are
  a single UDP exchange of fixed-size messages. Putting it here would have made
  the crate depend on an XML parser to serve the protocols that do not need one.

  The security posture is stated in the crate documentation rather than assumed:
  **nothing here is authenticated**. NAT-PMP has no security at all and PCP's
  RFC 7652 authentication is neither deployed nor implemented. That is
  survivable only because of what a mapping is used for — a forged response
  makes a node advertise an address that does not work, which is the same bound
  `aven-v1.md` §7.2 already places on a lying peer, and the reason that section
  forbids treating any reported address as a path.
- ✅ **PHREATIC over the relay, and the upgrade is one rule.** `Output` names a
  destination rather than an address, and `Engine::via` is the only place that
  chooses: a direct endpoint if there is one, the relay otherwise.

  **The upgrade and the fallback are that rule read at different moments**,
  which is why it is two lines and not a state machine. AVEN already owns
  whether a direct endpoint exists — it installs one on a confirmed path and
  withdraws it when the path stops answering — so the two subsystems needed no
  coordination at all. Deciding it in one place is what keeps that true: the
  code before this asked `endpoint(peer)` in four separate places and dropped
  the packet when it was `None`, and a relay arm added to three of them would
  have been a peer that could receive but not send.

  **`inbound_from_relay` is a separate entry point rather than a flag**, because
  the two differ in what they may conclude from where a datagram arrived.
  It learns no endpoint — the source address is the *relay's*, and installing it
  would aim a peer's traffic at a TLS port that is not a PHREATIC listener. It
  attributes by the relay-stamped source instead of guessing from the endpoint
  table. And it reassembles under a key disjoint by construction from every UDP
  source key, which matters exactly during an upgrade, when a relayed and a
  direct stream from the same peer are briefly both in flight.

  **A relayed handshake must name the peer the relay says sent it.** Ponor
  authenticated a node id; the AEAD resolves a `peer_id_hint`; requiring the two
  to agree is what stops one admitted peer replaying another's handshake under
  its own relay identity. The test that pins it uses a peer this node holds a
  key for — a stranger is refused a step earlier by the lookup, so a test using
  one passes with the check deleted. That mistake was made twice in this phase,
  once here and once in the AVEN equivalent, which is why it is written down.

  **The connection is split so the directions cannot block each other.** They
  share one TLS stream but must not share a scheduling point: a worker
  alternating between reading and draining a send queue adds its polling
  interval to every relayed packet, and once this path carries tunnel data that
  interval *is* the tunnel's latency.

  The queue from the datapath to the relay worker is bounded and **drops rather
  than blocks** — these calls happen on the threads carrying the tunnel, and
  waiting on a dead relay would turn a relay outage into a total outage, which
  is the opposite of what a fallback path is for. §7.3 makes the same choice one
  hop further on. The drops are counted and surfaced in `karst status`, because
  the failure this replaces was silent.

  `karst status` now reports `transport` per peer rather than an endpoint alone.
  It is an enum and not a bool on purpose: "relayed" and "no path at all" are
  different problems with different fixes, and a bool merges the second into the
  healthy case.

  **A relay with a self-signed certificate had no working configuration**, which
  is FINDINGS.md finding 16 and was found by trying to write an integration test
  against a real one. `ponor-v1.md` §4.2 names that deployment as the realistic
  self-hosted case and `relay_tls` loaded the system trust store alone.
  `[control] relay_ca_file` now supplements it. It cannot weaken relay
  authentication, structurally rather than by promise: §4.2 already makes the
  certificate insufficient on its own, and the netmap-pinned ML-DSA-65 identity
  is what names the relay.

- ✅ **The published endpoint is discovery's to withdraw** — FINDINGS.md finding
  15, found while building the relay path and closed the same day. `via`
  preferred any endpoint and a netmap-configured one exists from startup, so a
  peer whose published address had gone stale was unreachable even with a relay
  available and the peer connected to it.

  **The root cause was ownership.** AVEN probed that endpoint and knew it did
  not answer; `release_endpoint` withdrew only paths AVEN had *installed*, and
  this one came from the control plane. The information existed and no code
  could act on it. Discovery now adopts it at reconcile, which is what gives it
  the standing to take it away — probing an address nobody owns produces a
  measurement and no consequence.

  **Release is gated on having given up, not on "nothing chosen".**
  `Engine::exhausted` is §7.5's schedule run to its end. Before that, "nothing
  chosen" means "not confirmed yet" — the state every peer is in for the second
  of probing after every roster change — and withdrawing there would drop a
  working endpoint onto the relay each time the netmap moved. Acting on it is
  safe precisely because giving up is not permanent: the 30-second re-probe
  sweep retries everything, so a peer that returns is found again without any
  state remembering it was written off.

  It also **removed** a rule rather than adding one. `PathChange::Release` had a
  `fallback` naming the configured endpoint to revert to, which only made sense
  while that endpoint was exempt from discovery. It is not — it is a candidate
  like any other, so by the time a release fires it has been given up on as
  well, and reverting would hand back an address discovery had just disproved.
  A release now simply clears, and `via` falls through.

  A peer with no disco key keeps its configured endpoint untouched, which is
  §5.1 rather than an exception: no key means no discovery, ever, so there is
  nothing to learn from and nothing that could responsibly take it away. That is
  also what keeps a static TOML roster working.
- 🔶 **NAT matrix — the instrument, validated.** `crates/karst-disco/tests/
  nat_matrix.rs` builds three network namespaces with a masquerading middle and
  two distinct outer addresses, and establishes that each topology behaves the
  way its label says. Five tests, run privileged in CI beside the TUN and
  two-node jobs.

  **This measures the network, not Karst**, using `examples/natprobe.rs` and no
  product code at all. That ordering is the whole point: §6's ≥90%
  direct-connection criterion is a number produced *by* this matrix, and a
  "symmetric" NAT that is quietly endpoint-independent yields a confident
  percentage that means nothing. Once the thing under test is a VPN rather than
  a two-line probe, the mistake is invisible.

  What is established: the topology translates at all; a cone NAT reuses one
  external port across two destinations (endpoint-independent mapping); a
  symmetric NAT does not; an unsolicited datagram does not cross
  (endpoint-dependent filtering, which is what makes it a NAT rather than a
  router); and UDP-blocked blocks UDP. **Checked against the defect**: swapping
  the two NAT types fails exactly the two tests that distinguish them.

  Two things sized honestly rather than papered over. `fully-random` allocates
  ports randomly, so two destinations can collide by chance — about one run in
  28,000, which over enough CI runs is a flake and not an impossibility; the
  test retries three times and needs one pair to differ. And `nft` rejects a
  chain named `fwd`, which is a reserved word.

  **Nine of the ten §6 rows exist.** Port-restricted cone, symmetric,
  UDP-blocked and the plain-NAT baseline are what Linux conntrack gives
  natively. Full-cone, address-restricted, IPv6-only and double-NAT were added
  on 2026-08-18. Adding the first two **corrected a claim this section
  previously made**: it said they
  need endpoint-independent filtering "which netfilter does not do without an
  out-of-tree module". Netfilter does not do it *by itself* — return traffic is
  admitted per flow — but a static `dnat` on the mapped port supplies exactly
  the missing half, and an `nft` set of contacted addresses narrows that to
  address-restricted. Both rows are eleven lines of `nft` and no module. The
  claim was never tested; it was inferred from conntrack's defaults and it was
  wrong.

  Where the construction over-approximates is stated in the code rather than
  hidden: a real full cone opens when the inside first sends, and a static
  `dnat` is open before that too. The matrix measures what happens *after* an
  outbound datagram, where the two are identical — so no test asserts
  reachability without a prior outbound, because that would be testing a port
  forward.

  **IPv6-only** is in the matrix precisely because it is the easy case: nothing
  translates, so the address a peer sees is the address the node has and a
  direct connection needs no hole punching. A rate measured only across NATs is
  measured against a harder network than many users are on, and leaving the row
  out would understate the result in a way that looks conservative and is simply
  wrong.

  **Double-NAT** is the row the exit criterion names by name — a subscriber
  behind their own NAT, behind a carrier's symmetric one, on RFC 6598 shared
  space. Its assertion is not that traffic crosses, which one NAT also manages,
  but that the source is rewritten *twice*: a reflector inside the carrier
  network sees the subscriber NAT's address, one beyond it sees the carrier's.
  A topology that quietly collapsed to a single NAT would pass every
  traffic-crosses check and misreport the difficulty of the whole matrix.

  **The mutation check found the same class of bug twice, and both times in a
  negative assertion.** The address-restricted row's "an uncontacted address
  must not cross" passed with the filter removed: the sender was binding a port
  the reflector already held, so the datagram never left. The double-NAT row's
  "the carrier is symmetric" passed with the carrier made a cone: the two probes
  bound `0.0.0.0:0`, so they had different source ports and the external ports
  would have differed under any NAT at all.

  Neither was a bug in the product and both would have made the matrix lie. The
  generalisation is worth stating: **a positive assertion failing for a bad
  fixture is loud, and a negative one is silent.** Negative assertions are the
  ones to mutate, and every one in this file now has been.

  Hairpinning and NAT64/DNS64 are unbuilt. Hairpinning needs a second host
  inside the same NAT; NAT64 needs an out-of-tree translator — `jool-dkms` is
  packaged but is a kernel module, which is a real CI dependency and a decision
  rather than an afternoon. Both are named here rather than quietly omitted,
  because a matrix that reports nine-for-nine is not the same as one that
  reports nine-of-ten.
- ✅ **The node's relay client, on a real socket** — `bins/karstd/tests/
  relay_live.rs`. `karst-relay` runs in process as a library, with a
  self-signed certificate the node trusts through `relay_ca_file`, and
  `karstd`'s Ponor client connects to it: TLS, the HTTP upgrade, the handshake
  with real ML-DSA-65 on both sides, and a packet forwarded between two
  admitted nodes.

  **None of that code had ever been on a socket.** The codec is tested in
  `karst-relay-proto`, the node session against a stub signature scheme, the
  relay's listener against a hand-rolled client — and a stub agrees with the
  code that calls it by construction. What was untested was the pair, which is
  where a mismatched identifier or a context string differing by one byte would
  live. The first assertion in the file is that the control plane's handle and
  the relay's node id are the same value; they are, and nothing but this
  required them to be.

  **Two comments in it overclaimed and were corrected by mutation testing**,
  which is the part worth keeping. "`split` refuses an unestablished
  connection, so this succeeding is the assertion" — it is not; `connect` loops
  until established, so the check is unreachable and removing it changes
  nothing. And a test named for a pinned *key* actually fails on the pinned
  *id*: disabling the signature check leaves it green. That second one is not a
  gap but §5.1 working — `relay_id` is derived from the key, so an entry naming
  a different key necessarily names a different id and the two cannot be
  separated. Both now say what they prove.

  A third mutation was more instructive than the test: forcing the relay's
  signature check to pass still refuses an unlisted node, and so does making
  the roster return somebody else's entry. Admission needs **both** a roster
  hit and a verified signature, and only breaking both together admits a
  stranger — which is §5.3's structural admission, observed rather than
  asserted.
- **`cargo deny check advisories` was red** and is now green: RUSTSEC-2026-0258
  in `h2` ≤ 0.4.15, reached through `tonic`. Pre-existing rather than
  introduced here, and fixed by a lockfile bump to 0.4.16. Recorded because the
  gate is only worth having if a red result is acted on the day it appears —
  this one had been red without anyone running it.
- ✅ **The whole stack ran, and it works: relay → direct, end to end.**
  Two `karstd` daemons in separate network namespaces, a real `karst-relay`, a
  real Go coordination server, real TUN devices. Nothing stubbed.

  ```
  A: endpoint = "-"                 state = "connecting"  transport = "relay"
  B: endpoint = "-"                 state = "established" transport = "relay"
  ...
  A: endpoint = "10.99.0.2:51820"   state = "established" transport = "direct"
  B: endpoint = "10.99.0.1:51820"   state = "established" transport = "direct"
  ```

  Enrolment, a netmap carrying disco keys and a relay registry, a Ponor
  connection over TLS with a self-signed CA, a PHREATIC handshake **through the
  relay**, an AVEN rendezvous over it, probes on the shared UDP socket, and the
  upgrade. That is the Phase 4 headline and it had never been run.

  It needed two small fixtures the tree lacked: `--listen` on the testserver
  (its nodes live in another namespace and cannot reach its loopback) and
  `--relay ADDR PK`, because the registry row it advertised was a placeholder
  key and no node can connect to a relay whose advertised key is a pattern of
  `0x91`.

  **And it immediately found a High defect that every unit test passed.** The
  packet filter was stateless, so a policy scoped to a destination port permitted
  the request and denied the reply, and **no TCP connection could complete** —
  FINDINGS.md finding 17. Both ends reported `established` and `direct`
  throughout; the tunnel was working perfectly and carrying nothing. §4.3's own
  example policy was the one that failed.

  This is the argument for end-to-end tests stated as a result rather than a
  principle. Nine matrix rows, six relay tests, four discovery tests and a
  hundred and seventy unit tests did not find it, because none of them had a
  *reply* — a reply only exists when something upstream holds a connection open.
- ✅ **Connection tracking, so §4.3's ACLs work at all** — `crate::flow`, and
  the fix for finding 17. A flow is recorded **only when a rule permits a
  packet**, so an attacker cannot open one, and it then permits exactly the
  reverse five-tuple.

  **The stateless alternative was tempting and is wrong.** "Permit a packet
  whose *source* port matches a rule" needs no state and makes TCP work; it also
  hands a permitted peer every port on this node for the price of choosing its
  source port — the old hole in "allow anything from port 53". A grant of
  `A → B:22` must not become a grant of `B → A:*`. `tests/acl_flows.rs` is
  written so that substituting the shortcut fails three of its five tests, and
  the first two to fail are the security ones.

  Per peer and behind its own lock, so §3.4's "two peers never contend" holds;
  bounded at 4096 with a two-minute idle timeout, because flows are state a
  peer's traffic makes this node allocate; and **cleared on reconfiguration**,
  because a flow is a cached permission and an ACL edit that withdrew access
  must not leave the connections it withdrew still running.

  Verified back on the daemons that found it: `RECEIVED: hello over the tunnel`,
  with `acl_denied_out = 0` at both ends where it had been 12.
- ✅ **A node repeats its candidates while it has no path** — FINDINGS.md
  finding 19, found from an asymmetry in the live run above: one daemon reached
  `direct` and the other sat on `relay`. Advertisement was edge-triggered on the
  candidate list *changing*, which on a stable host happens once, ever —
  measured as one advertisement and then zero over a simulated hour. A peer that
  missed it never learned where its counterpart was, and **that is what a node
  joining an existing aquifer does**: it holds no disco key at the moment the
  advertisement is relayed, so it drops it.

  The reasoning was already one function above. The re-probe sweep repeats
  itself and says why — *"without this a node that settles on a relay at boot
  stays there until something else disturbs it"*. Telling a peer where you are
  and asking where it is are the two halves of one job, and only one was being
  repeated. `spec/aven-v1.md` §7.5 now makes it a MUST NOT.
- ✅ **The live run is a test now** — `bins/karstd/tests/aquifer.rs`, wired into
  `just test-privileged`. Four processes: the Go coordination server,
  `karst-relay`, and two `karstd` daemons in separate namespaces with real TUN
  devices. First enrolment to a direct path carrying TCP under a port-scoped
  ACL, in **four seconds**.

  It found a third defect before it first passed. **Nothing learned a candidate
  from an incoming probe**, so only the node that probed first ever got a path:
  the other answered, was confirmed, and then watched its peer stop advertising
  with no candidate of its own and no prospect of one (FINDINGS.md finding 20).
  The address an authenticated `Ping` arrived from is now a candidate — better
  evidence than a `CallMeMaybe`, which is a claim, because that datagram
  actually made the journey.

  **Two things about the fixture are worth keeping.** Its timeout prints both
  nodes' status and every log, because four processes in two namespaces fail in
  ways no assertion message anticipates and the temporary directory is gone by
  the time anyone reads the output — that diagnostic found the next two bugs in
  one run each. And nodes are tracked by name rather than in a `Vec`: an earlier
  version restarted "the last child spawned", which was the wrong daemon, and
  the second copy collided with the first one's TUN device.

  What it does **not** catch is finding 19, and the reason is worth stating: the
  fixture drops nothing, and 19 is about an advertisement that was sent and
  lost. That property lives in `karst-disco`'s unit tests, where loss can be
  expressed. An end-to-end test is not a superset of the ones beneath it.
- ✅ **Hole punching, measured through a real NAT** — `aquifer.rs` grew a second
  topology: node A behind a port-restricted cone, node B and the servers on the
  public side. Every address A can name is private and useless to B, so a direct
  path can only come from the sequence AVEN exists for. Both ends reach
  `transport = "direct"`, and the assertion that matters is **which** address B
  ends up holding: the NAT's mapped one, never A's private one.

  That assertion earned its place immediately. The first version of the
  topology added a route from the public side into the private prefix — "so the
  relay's replies can get back", which they do not need, because they return
  through conntrack's translation. With it, B reached `10.98.1.2` *directly* and
  reported a perfectly healthy direct path that no real NAT would have allowed.
  The test was not a NAT test; it was a router test that said NAT on the label,
  and only the mapped-address check told the difference.

  **What the two rows pin, checked rather than assumed.** Removing finding 20's
  probe-source rule fails the flat row and leaves the NAT row passing, because
  behind a NAT the reflexive path reaches the same place. Removing §7.2's
  reflexive addresses altogether fails **neither** — so the probe-source rule
  subsumes it in both topologies, and `Pong.observed` is currently carried by
  unit tests alone. That is worth knowing before anyone treats a green NAT row
  as coverage of §7.2.
- ✅ **Both nodes behind NATs, and it works** — `aven-v1.md` §7.6 and
  `ponor-v1.md` §7.7, built to close FINDINGS.md finding 21. `aquifer.rs`'s third
  topology is two nodes each behind their own port-restricted cone, which is two
  laptops on two home networks: the ordinary deployment rather than an exotic
  one, and the one that did not work.

  **The bootstrap problem was the whole of it.** Neither node could learn its own
  mapped address: interface addresses are private, `Pong.observed` needs a probe
  to have crossed first and no probe could cross, and the relay could not say —
  Ponor had no frame for an observed address and speaks **TCP**, whose NAT
  binding is not the UDP one AVEN needs. The reflexive mechanism needed a
  working path to bootstrap a working path.

  A **reflector** breaks it from outside: a UDP service a relay MAY run, keyed
  by a 32-byte `reflect_key` minted per Ponor connection and delivered inside
  TLS *after* the relay's ML-DSA-65 signature has verified. No new trust anchor
  and no new key exchange — the ordering is the entire security argument.

  **Request and reply are the same size, and that is what `pad` is for.** The
  natural encoding is `Ping`/`Pong`'s: 46 bytes in, 65 out, a factor of 1.4.
  That is small, and small is not the same as one. A service every relay in a
  public pool operates, answering datagrams anyone able to replay one can send,
  must not amplify at all — so `Reflect` carries nineteen zero bytes reserving
  the space its own answer occupies, and the equality is a compile-time
  assertion rather than a comment.

  **The reflector answers to the source address, which is the inverse of §7.1
  and not a contradiction of it.** A `Pong` answers a question about the *peer's*
  address, where trusting the source lets an on-path attacker redirect a probe.
  A `Reflection` answers a question about the *sender's own* address, where the
  source is the entire content of the answer.

  Two defects came out of building it, both found by packet capture rather than
  by reasoning, and both more transferable than the feature.

  **A keepalive interval equal to the timeout it defends against is not a
  keepalive** (finding 22). `Reflect` first refreshed every 30 seconds, matching
  §7.5's other intervals; Linux's `nf_conntrack_udp_timeout` is also 30 seconds.
  Each refresh raced the expiry, so the mapped port alternated between the
  preserved one and a random one, the node advertised an address it was no
  longer sending from, and the pair never converged. Now 10 seconds — and §7.5
  states the rule rather than the number: *a reflexive address is only true
  while the binding that produced it is alive, and nothing tells the node how
  long that is.*

  **A masquerade rule alone is not a NAT** (finding 23). The fixture's NAT
  namespace had no filter chain, so a peer's probe to its outer address reached
  the namespace itself, drew an ICMP unreachable, and *confirmed a conntrack
  entry* that occupied the reply tuple the inside host needed — after which
  masquerade could not keep port 51820 for that peer and allocated a random one.
  A port-restricted cone behaved like a symmetric NAT, which would have been
  read as a product limitation. §6's matrix already pins the forwarded half of
  the rule; the aquifer fixture lacked the equivalent for traffic addressed to
  the NAT's own address.

  Verified end to end and **checked against the defect**: the row converges in
  ten seconds, each node holding the other's *mapped* address rather than its
  private one, and removing `[reflect]` from the relay's configuration fails
  that row **and only that row** — every other topology reaches a direct path
  without it.

  What it does **not** close is stated in §7.6: a server-reflexive address is
  the mapping toward the reflector, so this covers endpoint-independent mapping
  and not symmetric-to-symmetric, which still needs port prediction.

  One debt recorded rather than hidden: adding `ReflectOffer` was a **flag day**.
  §6 gives Ponor no forward-compatible extension point — an unrecognised frame
  type closes the connection, deliberately — and neither version byte can carry
  the signal. Acceptable exactly once, while nothing is deployed;
  `ponor-v1.md` §13.10 records that the next such change will not have that
  excuse.
- 🔶 **Full NAT test matrix in CI (§6) — ten `karstd` topologies run end to
  end, seven reach a direct path, and the instrument beneath them is now twelve
  rows.** The instrument is complete: NAT64/DNS64 landed
  2026-08-19, built from `tayga` plus an ordinary masquerade rather than an
  out-of-tree kernel module (finding 27).

  Three instrument rows added 2026-08-19:

  | Row | Establishes |
  |---|---|
  | `a_masquerading_nat_does_not_hairpin` | Linux does **not** loop a datagram addressed to its own external address back to the inside |
  | `a_nat_configured_for_hairpinning_rewrites_the_source_too` | …and when configured to, the source is the **external** address, as RFC 4787 REQ-9 requires |
  | `a_carrier_nat_admits_the_reply_it_opened_and_nothing_else` | The CGNAT row filters as well as maps — the half the double-NAT row left out |
  | `a_nat64_path_carries_ipv6_to_ipv4_and_shares_one_port_space` | An IPv6-only node reaches IPv4, and the path maps **endpoint-independently** |

  **The NAT64 result was not guaranteed and is good news.** One socket
  addressing two IPv4 hosts is seen at the same external port, so an IPv6-only
  node's reflexive address is the address every peer sees and §7.6 works on it
  unchanged. Had it come out endpoint-*dependent*, every IPv6-only node would
  have been in §7.7's hard class.

  **The hairpinning result has a direct consequence for the specification.**
  Two nodes on one home network both learn a reflexive address from the relay
  and then probe each other *at the NAT's own outer address* — which does not
  work. So `aven-v1.md` §7.2's **interface-address tier is what carries the
  same-LAN case**, and it is not a fallback there: it is the only thing that
  works. A node that advertised only reflexive addresses — the tempting
  simplification once §7.6 exists, since they work everywhere else — would relay
  two machines on the same desk through the internet.

  The carrier row closes a gap that mattered for how the exit criterion is read.
  The double-NAT row pinned the carrier's *mapping* as endpoint-dependent and
  said nothing about its *filtering*, and the two answers point opposite ways: a
  carrier filtering by address alone would make a CGNAT subscriber reachable
  from any port, and symmetric-CGNAT-to-anything would stop being the hard case.
  It filters by port too, so it does not.

  | # | Node A is behind | Node B is behind | Result |
  |---|---|---|---|
  | 1 | *(nothing)* | *(nothing)* | direct |
  | 2 | port-restricted cone | *(nothing)* | direct |
  | 3 | port-restricted cone | port-restricted cone | direct |
  | 4 | symmetric | *(nothing)* | direct |
  | 5 | symmetric | address-restricted cone | direct |
  | 6 | symmetric | symmetric | **relay** |
  | 7 | all UDP dropped | *(nothing)* | **relay**, and correctly so |
  | 8 | symmetric | port-restricted cone | **relay** — and this one is winnable |
  | 9 | symmetric **with a port mapping** | symmetric | direct — PCP/NAT-PMP |
  | 10 | the **same** NAT, one LAN | the same NAT, one LAN | direct — over private addresses |

  Each row is a whole aquifer — Go control server, relay, two daemons, real TUN
  devices — not a probe against a socket, and each ends with a TCP conversation
  under a port-scoped ACL.

  **Rows 4 and 5 are the ones that changed the picture, and both say the same
  thing: "symmetric NAT" is a property of a *pair*, not of a node.** Row 4 goes
  direct because B is publicly reachable, so A's probe crosses first and finding
  20's rule makes B adopt the address it *arrived from* — which is the mapping
  toward B, the one allocation that matters, and the one nobody could have
  predicted. Row 5 goes direct because an address-restricted cone never asks
  anyone to predict a port: it admits any port from an address it has already
  sent to. Only row 6, where both filters are port-dependent and both mappings
  are unpredictable, actually needs port prediction.

  **Row 8 was missing from the first seven and it is the one that matters
  most.** An earlier version of this section claimed row 6 was the only case
  needing port prediction. That was wrong. Row 8 — symmetric facing a
  port-restricted cone, which is a CGNAT subscriber talking to somebody on a
  home router — differs from row 5 by one word in B's filter, and it fails:
  B checks the source *port* as well as the address, and A's probe arrives from
  a port B never sent to. It is also the common real-world pairing, and unlike
  row 6 it is winnable. See the exit discussion below.

  **Row 10 is where the hairpinning result pays off.** Two nodes on one home
  network both learn a reflexive address, both advertise it, and both probe the
  NAT's own outer address — which Linux does not loop back. They go direct over
  the private segment instead, and the row asserts each holds the other's
  `10.98.1.x` address rather than the NAT's, so a hairpinning NAT could not make
  it pass for the wrong reason. Deleting the interface tier from `candidates()`
  fails it after 152 seconds of trying.

  That makes `aven-v1.md` §7.2's interface-address tier **load-bearing rather
  than decorative**. It is the only tier that works on this topology, so a node
  advertising reflexive addresses alone — the tempting simplification once §7.6
  exists, since they work on every other row — would relay two machines on the
  same desk through the internet.

  Row 5 also turned up a pleasing detail. A's reflexive address is a dead
  letter as a destination — B's probe to it is dropped — and it is nonetheless
  load-bearing, because sending to it is what puts A's outer address in B's
  filter. A candidate that never answers can still do the work. That is an
  argument for §7.2 keeping unanswered candidates that the specification did not
  previously make.

  **Rows 6 and 7 are assertions about staying put, and they are the ones worth
  reading carefully.** Neither merely waits for a timeout: each establishes on
  the relay, then holds the pair under observation for 75 seconds — several
  `Reflect` round trips, a full probe backoff, and one re-probe of every
  alternative — and fails if either node ever reports `direct`. The failure
  being guarded against is not "no direct path". It is a node advertising an
  address it is not reachable at, a peer believing it, and `karst status`
  reporting success over a black hole.

  All three new rows are checked against their own defect, which is the
  discipline finding 23 bought:

  | Row | Mutation | Result |
  |---|---|---|
  | 5 | B's NAT made port-restricted instead | fails — 212 s, never converges (this is row 8) |
  | 6 | `fully-random` removed from both NATs | fails — direct in 5 s |
  | 7 | the UDP drop removed | fails — direct in 31 s |

  Finding 23 remains the caution for every row added from here. The instrument
  is only as honest as its weakest topology, and a NAT missing a filter chain
  reports a *product* failure — the fixture said "port-restricted cone" and
  behaved like a symmetric one for two days' worth of debugging.
- Kubernetes operator + userspace mode + Docker images.
- **Exit:** **every topology in the matrix where a direct path is physically
  possible reaches one**, and the rest fall back to the relay without loss with
  both nodes reporting why; relay fallback is automatic and lossless; a peer behind symmetric CGNAT reaches a peer behind a
  different symmetric CGNAT **when at least one of the two NATs offers an
  explicit port mapping** (PCP, NAT-PMP or UPnP-IGD) — otherwise the pair falls
  back to the relay without loss, and both nodes report the reason.

  The third criterion was **restated on 2026-08-19** and the original is kept
  here so the change is legible rather than silent:

  > ~~a peer behind symmetric CGNAT reaches a peer behind a different symmetric
  > CGNAT~~

  It was restated because it was measured to be unachievable, not because it was
  inconvenient. FINDINGS.md 24 carries the measurement and the arithmetic;
  the short version is that two randomising NATs square the search space, so the
  birthday paradox's √N saving still leaves ~170,000 probes per side for a
  99.9% success rate, and 0.01% after twenty seconds of trying. Tailscale
  reaches the same conclusion and relays the same case. A criterion that no
  implementation meets is not a standard, it is a wish.

  **Two of the three hold. The third does not, and there is now a number rather
  than an expectation.**

  *Relay fallback is automatic and lossless* — row 7 above is the clean
  statement of it. Every other row lets AVEN work and watches the relay lose to
  it, which tests the upgrade rather than the fallback; row 7 drops every UDP
  datagram in both directions, so there is no discovery to lose to. The pair
  establishes, stays established for the whole observation window, and carries
  TCP under the ACL with the drop counters at zero. `Engine::via` picks the
  relay because no direct endpoint exists, and nothing above it knows the
  difference.

  *Every physically-possible topology connects directly* — **seven of the eight
  that are possible, with row 8 the one outstanding.**

  The criterion was **restated on 2026-08-19** and the original is kept so the
  change is legible:

  > ~~≥ 90% direct-connection rate across the matrix~~

  It was restated because it is **arithmetically unreachable by counting rows**,
  and not for want of engineering. Two of the ten topologies are relay by
  construction: symmetric-to-symmetric has no technique that reaches it
  (§12.4's 0.01%), and a path with all UDP dropped has no direct path to find.
  That caps any row count at 80%. The only routes to 90% would be to add easier
  rows — which games the denominator, and is the dishonesty this matrix exists
  to prevent — or to weight by real-world NAT prevalence, which needs field data
  this project does not have and cannot invent.

  The replacement is checkable, means something, and cannot be gamed by adding
  rows: an easy row that connects adds nothing to it, and a row that *should*
  connect and does not fails it. The old figure is still worth reporting and
  still is — seven of ten, 70% — but as a description rather than a target.

  *The old figure, for continuity* — **seven of ten topologies, which is 70%,
  or 78% over the nine where a direct path exists at all.** Both figures are
  below the criterion and both are reported rather than the flattering one
  alone. Two further honesties belong with them. The denominator is a set of
  topologies chosen here, not a population weighted by how common each NAT is
  in the field, so this is a capability count and not the rate the criterion
  means; producing the latter needs field data this project does not have.
  And three shapes are still unbuilt — double NAT, hairpinning, NAT64/DNS64 —
  of which double NAT is the one the third criterion names.

  *A peer behind symmetric CGNAT reaches a peer behind a different symmetric
  CGNAT when at least one NAT offers an explicit port mapping* — **yes, as of
  2026-08-19.** `bins/karstd/src/portmap.rs` asks the default gateway for a
  mapping on the datapath port, PCP first and NAT-PMP on fallback, renews
  against the granted lifetime and re-requests on an epoch restart; the mapped
  address becomes a fourth and strongest candidate tier (`aven-v1.md` §7.2).
  The row `a_symmetric_nat_with_an_explicit_mapping_reaches_another_symmetric_nat_directly`
  runs two symmetric NATs, one of them serving PCP through `miniupnpd`, and the
  pair reaches a direct path in about ten seconds. **Checked against the
  defect**: `KARST_AQUIFER_DISABLE_PORT_MAPPING=1` fails that row and the other
  eight still pass.

  The original wording remains unachievable, and the paragraph below records
  why it was restated rather than met.

  *The original: a peer behind symmetric CGNAT reaches a peer behind a different
  symmetric CGNAT, with no mapping on either side* — **no.** Row 6 is
  that case and it stays on the relay. The mechanism this plan named for it is
  port prediction, and FINDINGS.md 24 measures why that does not work: the
  symmetric NATs that matter scatter their external ports with no locality at
  all, so there is nothing to predict. Rows 4 and 5 establish that the failure
  is *narrow* — a symmetric NAT is not by itself disqualifying — and row 6
  establishes that it is *graceful*. Neither makes the criterion true.

  **The recommended restatement, which is a decision this plan should take
  rather than quietly leave open:**

  > A peer behind symmetric CGNAT reaches a peer behind a different symmetric
  > CGNAT **when at least one of the two NATs offers an explicit port mapping**
  > (PCP, NAT-PMP or UPnP-IGD); otherwise the pair falls back to the relay
  > without loss, and both nodes report the reason.

  That is achievable, verifiable against a third-party server, and honest about
  the residue. **`karstd` now does the PCP/NAT-PMP half of it end to end.** It
  finds the default gateway, asks PCP first and falls back to NAT-PMP on the
  explicit version errors RFC 6887 §9 names, advertises the mapped external
  address as a top-tier candidate, renews on the granted lifetime, and reports
  both the live mapping and the failure reason in `karst status`. The aquifer
  matrix now splits the old doubly-symmetric row in two: with one mapping-
  capable side it goes direct; with neither side mapped it stays on the relay.

  **It does not close the whole space.** Port mapping helps only where a
  gateway offers it; where neither side has one, the doubly-symmetric case is
  still the relay row and that is the correct answer. And the current daemon
  path speaks the two UDP protocols `karst-portmap` already implements — PCP
  and NAT-PMP. A gateway that offers only UPnP-IGD remains outside this build,
  which is the same crate boundary recorded when `karst-portmap` was added.

  **Row 8 is a separate and better-value target, and the literature agrees.**
  Tailscale's published analysis splits the problem exactly where our
  measurements do. For the hard/easy pairing — one symmetric NAT, one
  endpoint-independent — 256 sockets on the hard side against 256 random probes
  from the easy side reaches **64% success in under two seconds** at 100
  probes/sec. For hard/hard it collapses to **0.01% after twenty seconds**;
  99.9% would need 170,000 probes from each side, about 28 minutes. Tailscale
  relays the hard/hard case, exactly as we do.

  So the honest split is that row 6 should be conceded and **row 8 is winnable
  and is the common pairing** — a CGNAT subscriber talking to somebody on a
  home router.

  **Measured against our own NAT flavours on 2026-08-19, and it holds** —
  `docs/measurements/hard-easy-2026-08-19.md`, with the harness beside it:

  | N sockets (hard) | M probes (easy) | Packets | Measured | Trials | Predicted |
  |---|---|---|---|---|---|
  | 128 | 128 | 256 | **20%** | 40 | 22% |
  | 256 | 256 | 512 | **60%** | 20 | 64% |
  | 512 | 512 | 1024 | **95%** | 20 | 98% |

  The blast takes about a millisecond. The arithmetic predicts the measurement
  closely enough to design against, which makes one result actionable
  immediately: **one large round beats several small ones.** Reaching 95% by
  retrying 256×256 costs about 1536 datagrams; doing it once at 512×512 costs
  1024. A design that starts small and escalates spends more traffic to arrive
  at the same place, because the birthday curve is superlinear in *N·M*.

  ❌ **Not adopted, 2026-08-19.** Specified, implemented, measured, and then
  conceded to the relay — the same answer §12.4 reaches for
  symmetric-to-symmetric, on evidence rather than by assumption.

  The corrected arithmetic is what decided it. `N` is live *mappings*, not
  sockets opened, and a mapping lives about a NAT timeout. Only the hard side's
  search mappings are targets, so half its external ports are dead. And a node
  does not know which side it is — §7.6's two-reflector test would tell it and
  most nodes have one relay — so it funds both roles from one budget, halving
  *N* and *M* together. At the allowance §7.5 grants that is **64% after eight
  minutes**, for a pair already talking over the relay the whole time.

  What it costs is a **datapath change**: the collision lands on one of *N*
  sockets, so the peer's traffic must migrate to whichever socket won, against
  §4's single shared socket. A protocol change of that size for a probabilistic
  gain on one pairing, at the edge of the amplification budget, is not a good
  trade. Explicit port mapping is the better answer for the same pairing and is
  already built.

  The implementation is removed rather than left dormant: it opened 128 sockets
  per peer and spent budget for a technique now specified as not adopted.
  `aven-v1.md` §7.7 keeps the analysis, and the branch `aven-77-align` keeps the
  eight fixes for anyone who revisits it. **One thing is left unexplained and
  recorded as a caution**: a capture inside a node shows the exchange working at
  the network layer while the daemon records no arrival. An implementer who
  reads the measurements and concludes the technique is ready has the same
  surprise waiting.

- KarstDNS: stub resolver, split DNS, all platform integrations (§7).
- Bedrock: SLH-DSA roots, quorum signing, hash-chained log,
  client-side enforcement, console UI for signing requests.
- Admin console: all views in §8.1.
- User portal: §8.2.
- macOS and Windows clients, signed and notarized, with installers.
- SCIM 2.0 provisioning and group sync.
- **Exit:** a non-expert admin can install the server, connect three nodes
  across three OSes and two NATs, write an ACL, enable network lock, and
  deprovision a user — entirely from the console and installers, following
  only the published docs.

### Phase 6 — Hardening and beta (8 weeks · Dec 2026–Feb 2027)

- **External cryptographic review** of PHREATIC and its implementation
  (budget 4–6 weeks lead time; book this now, not at the start of Phase 6 —
  Phase 3 has already passed and the booking did not happen in it).
- **External penetration test** of the control plane and console.
- ⬅️ **TURN fallback**, slipped from Phase 4 on 2026-08-20 under the option that
  bullet reserved: client-side allocation, permissions, channel binding and
  credential refresh; control-server ephemeral credential minting; coturn added
  to the NAT matrix.

  It arrives here with the base case already covered — ten `karstd` topologies
  show the co-located relay path automatic and lossless — so what TURN buys is
  interoperability with third-party infrastructure (ADR-0008), not connectivity.
  Scoped accordingly: it is a compatibility feature in this phase rather than a
  traversal one.
- Subnet routers, exit nodes, advertised routes, ACL-gated SSH.
- Observability: Prometheus, OTel traces, per-node diagnostics bundle,
  `karst bugreport`.
- HA: control-server horizontal scaling, Postgres replication, backup/restore
  runbooks, documented disaster recovery with a tested RTO/RPO.
- Documentation: install guide, operations manual, protocol spec, security
  whitepaper, migration guide from WireGuard/Tailscale.
- Public beta with design partners.
- **Exit:** all high/critical audit findings remediated and re-tested;
  30 days of beta with a defined stability bar met.

### Phase 7 — GA and mobile (12 weeks · Feb–May 2027)

- iOS and Android clients via UniFFI over the Rust core.
- Performance tuning: io_uring, path MTU discovery, QUIC relay transport.
- **Shard the datapath.** Carried from Phase 2, where it was measured and
  scoped out: throughput does not rise with flow count (686 → 708 Mbps for
  1 → 4 flows) while both datapath threads sit at 70% CPU. One TUN-reader
  thread and one UDP-reader thread serialise every flow of every peer, so the
  fix is multiple queues (`IFF_MULTI_QUEUE`, `SO_REUSEPORT`) rather than
  tuning. This is the gate on the ≥ 3 Gbps target in §3.3. See §3.4.
- **Measure the absolute ≥ 1 Gbps figure**, deferred from Phase 2's exit
  criterion, on a link carrying ≥ 1.13 Gbps single-flow. The lab's 3×1G bond
  gives one flow one slave and cannot express the number.
- CNSA 2.0 profile as **suite 3** of the agility layer (ML-KEM-1024 /
  ML-DSA-87 / AES-256-GCM / SHA-384, PQ-only) — shipped *through* the
  mechanism rather than by patching, which is what proves the layer works.
  Confirmed for Phase 7 by §13 Q6: no customer mandate, no date.
- v1.0 GA.

**Total from here: ~40 weeks (~9 months) to GA**, 2026-08-10 → May 2027, being
Phases 4–7. Self-hosted Linux-to-Linux mesh with a working console is usable at
end of Phase 5 (**~20 weeks**, Dec 2026), and that is the milestone worth
optimizing for.

The original figure was ~65 weeks across all eight phases. Phases 0–3 are done
and the remainder is what is left to schedule; the 65-week number is not
restated as elapsed time, because it was never a measurement.

---

## 11. Testing strategy

| Layer | Approach |
|---|---|
| Crypto | NIST KATs, cross-implementation differential testing against PQClean, `proptest` round-trips |
| Protocol | Sans-io state-machine tests, `cargo-fuzz` + OSS-Fuzz on all parsers, deterministic simulation with a virtual clock and lossy/reordering/duplicating network |
| Formal | Verifpal (Phase 1), ProVerif (Phase 3), `kani` on the fragmentation reassembler |
| Datapath | netns integration, packet-level assertions, 24h soak with chaos (kill, flap, migrate, clock-jump) |
| NAT | Full matrix in CI (§6) — this catches the regressions that hurt most |
| Control plane | Table-driven ACL tests, Postgres-backed integration tests via testcontainers, exhaustive RBAC matrix tests |
| Frontend | Vitest units, Playwright E2E against a real server, axe-core accessibility gate |
| Security | `cargo deny` + `govulncheck` + Dependabot in CI, SBOM per release, quarterly dependency review |
| Release | Reproducible builds, signed artifacts, transparency-logged releases |

**Deterministic simulation testing deserves emphasis.** A virtual-clock,
virtual-network harness that can replay a failing seed exactly is the
difference between debugging a distributed handshake bug in an afternoon and
losing a week to it. Build it in Phase 2, before it's desperately needed.

---

## 12. Risks

| Risk | Impact | Likelihood | Mitigation |
|---|---|---|---|
| Handshake fragmentation opens a DoS vector | High | Medium | Per-fragment MACs, mandatory cookies under load, zero pre-validation state, bounded reassembly, amplification assertions, `kani` on the reassembler, external review (ADR-0004) |
| Netmap now carries PSK secrets, raising the value of a server compromise | Medium | Medium | Encrypted at rest on nodes, never logged, master in HSM/KMS, rotation every 24h; stated plainly in the security whitepaper |
| NAT traversal underperforms Tailscale | High | **High** | Full test matrix from Phase 4; 10-week budget; relay fallback always works; treat direct-connection rate as a tracked KPI |
| ML-KEM or ML-DSA cryptanalytic advance | Critical | Low | Hybrid construction means a break costs no confidentiality; agility layer allows swapping suites |
| Greenfield scope exceeds estimate | High | **High** | Phase-5 usable milestone; mobile and SaaS explicitly deferred; ruthless non-goals |
| Platform DNS integration breakage | Medium | High | Per-platform tests, conservative fallbacks, `karst doctor` diagnostics |
| Windows driver signing / macOS notarization delays | Medium | Medium | Start certificate acquisition in Phase 3, not Phase 5 |
| Crypto review finds a protocol flaw late | High | Medium | Verifpal in Phase 1 and ProVerif in Phase 3 pull discovery earlier; book reviewers early |
| No WireGuard interop limits adoption | Medium | Certain | Accepted consequence of the greenfield decision; mitigate with a migration guide and side-by-side operation support |
| Trademark collision forces a rename | Low–Medium | **High** | ADR-0007 makes trademark the only defensive lever; a collision already appears likely. Search concluded and name settled as a Phase 0 exit criterion, before repo/crate/SPDX names harden |

---

## 13. Open questions

1. ~~**Classic McEliece vs. fragmentation** (§2.3)~~ — **resolved 2026-08-08,
   [ADR-0004](docs/adr/0004-handshake-mtu-and-kem-selection.md).** Fragmentation
   with ML-KEM-768 throughout, stateless-under-load responder, per-pair PSK
   mixing for assumption diversity; McEliece retained as an optional profile.
2. ~~**Licensing**~~ — **resolved 2026-08-08,
   [ADR-0007](docs/adr/0007-licensing.md).** `MIT OR Apache-2.0` for crates,
   agent, CLI and relay; `AGPL-3.0-or-later` for the control server and web
   apps; CC-BY-4.0 for the spec; DCO everywhere, no CLA. Commercial
   dual-licensing is deliberately foreclosed. See [LICENSING.md](LICENSING.md).
3. ~~**Does the initiator's static key need encryption in msg1?**~~ —
   **resolved 2026-08-09,
   [ADR-0005](docs/adr/0005-identity-model-and-peer-presentation.md).** The
   premise was faulty: the hint travels inside the AEAD, so there is no privacy
   cost to accept — it matches WireGuard and beats it under responder-key
   compromise. Unsalted, session-independent, 32 bytes, no full-key fallback.
4. ~~**Relay funding model for self-hosters**~~ — **resolved 2026-08-09,
   [ADR-0008](docs/adr/0008-relay-infrastructure-and-funding.md).** Relay
   co-located with the coordination server by default (zero marginal cost);
   standard TURN as a pluggable fallback for regional coverage; no default
   public fleet; community pool opt-in with mandatory strict-mode admission.
   Tailscale's fleet and DERP wire compatibility are both ruled out.
5. ~~**Name collision**~~ — **resolved 2026-08-09,
   [ADR-0010](docs/adr/0010-project-name-and-component-naming.md).** The
   original name collided head-on with ThreeFold's
   [Mycelium](https://github.com/threefoldtech/mycelium): an actively developed
   encrypted overlay network, in Rust, whose daemon binary is literally
   `myceliumd`. The project is now **Karst**, with Bedrock, Ponor, PHREATIC and
   KarstDNS as component names. Formal clearance on crates.io, npm, the GitHub
   org, the domain and USPTO remains a **Phase 0 exit criterion** before any
   public commit.
6. ~~**CNSA 2.0 mandate?**~~ — **resolved 2026-08-09.** No target customers
   identified and no compliance date. The audience is **hobbyists and
   security-minded commercial organisations**, which favours defaults that are
   safe without a security team and performant on modest hardware (hence
   ChaCha20-Poly1305 and Category 3 by default, per
   [ADR-0001](docs/adr/0001-cryptographic-algorithm-selection.md)). The CNSA
   2.0 profile stays in **Phase 7** as suite 3 of the agility layer, where it
   doubles as the proof that the layer works.

**All open questions are now closed.** New ones belong here as they arise.

---

## 14. Immediate next steps

**All ten ADRs (0001–0010) are written and all six open questions closed.**
The plan is decision-complete; what remains is execution.

1. ✅ **Trademark cleared** (ADR-0010). Remaining: register the mark, and
   reserve the crates.io / npm / PyPI / GitHub org names **before the first
   public commit** so they cannot be taken during Phase 0.
2. ✅ **Threat model drafted** ([docs/THREAT-MODEL.md](docs/THREAT-MODEL.md)).
   Circulate with the ADR set for review and sign-off.
3. ✅ **Monorepo and CI scaffolded**, `SECURITY.md` with the good-faith-research
   safe harbour included. Verified: `cargo fmt --check`, `cargo clippy -D
   warnings` and `cargo test` pass across 13 crates; crate `karst-cli` produces
   the binary `karst` as intended.
5. ✅ **[`spec/phreatic-v1.md`](spec/phreatic-v1.md) drafted** (Draft 0.1).
   Nine open items in its §14; items 1–2 (Verifpal, ProVerif) are release
   gates. Next protocol work is the Verifpal model.
4. Run the **NetBird fork-evaluation spike** (ADR-0009) early in Phase 0; its
   outcome restructures Phases 3 and 5.
4. Draft `spec/phreatic-v1.md` far enough to model in Verifpal.
5. Book an external cryptographic reviewer for **Q4 2026** now — Phase 6 opens
   in December, lead times are long, and this is a hard gate on GA. The date
   moved forward by three quarters when the schedule was re-anchored; the
   booking is the item most likely to be left on the old one.
