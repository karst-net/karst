# Karst — Implementation Plan

**A post-quantum mesh VPN with self-hosted coordination, admin console, and user management.**

Status: draft v1 · Plan date: 2026-08-08 · Owner: TBD

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
| Malicious peer inside the tailnet | **Yes** | Contained by ACL enforcement at both ends |
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
small, fixed, server-class tailnets that want code-based security.

---

## 3. The Rust data plane

### 3.1 Crate layout (Cargo workspace)

```
crates/
  karst-crypto/     KEM/sig/AEAD traits, suite registry, zeroization
  karst-proto/      wire formats, fragmentation, codec, no_std-friendly
  karst-noise/      PHREATIC handshake state machine (sans-io)
  karst-transport/  UDP sockets, GSO/GRO, sendmmsg, endpoint mgmt
  karst-disco/      NAT traversal: STUN-like probing, path selection
  karst-relay-proto/ Ponor relay framing (client side)
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
| ML-DSA-65 | **`cloudflare/circl` v1.6.5** — see below |
| SLH-DSA-SHA2-192s | **`cloudflare/circl`** — no standard-library path exists |

The KEM half needed no new dependency. ML-DSA did, and the reason is worth
recording because it is temporary:

**Go 1.26 implements ML-DSA-44/65/87 — in `crypto/internal/fips140/mldsa`,
ACVP-tested — but does not export it.** There is no public `crypto/mldsa`, and
`internal/` cannot be imported from outside the standard library. The pattern
is the one ML-KEM followed: `crypto/mlkem` is a thin public wrapper over
`crypto/internal/fips140/mlkem`, shipped in 1.24 after the internal
implementation landed. ML-DSA has completed the internal half, so a public
package looks close — but it is not in the current stable and cannot be used.

`cloudflare/circl` is therefore the choice, and it is **not purely a stopgap**:
Bedrock needs SLH-DSA-SHA2-192s (ADR-0001) and the standard library has no
SLH-DSA at all, not even internally. circl is a dependency either way.

The swap is pre-planned. `channel.Signer` and `channel.Verifier` are
interfaces, and `management/internals/karst/identity` is a deliberately thin
shim, so migrating ML-DSA to the standard library when it ships is one file.

This also removed a stale `replace` directive pinning circl to a 2023 codeberg
fork that predates FIPS 204 — dead weight, since the prune had already left
circl with zero packages in the build graph.

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

### 4.5 Bedrock (tailnet-lock equivalent)

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

The design owes a clear debt to Tailscale's **DERP** — mesh presence,
home-relay selection, relay-first-then-upgrade — which is credited as prior art
here and in `spec/phreatic-v1.md`. We borrow the design and **not** the protocol or
the fleet: [ADR-0008](docs/adr/0008-relay-infrastructure-and-funding.md) rules
out both, and `karst-relay` must never gain a DERP compatibility mode.

- Transport: HTTPS/TLS 1.3 with hybrid `X25519MLKEM768`, upgrading to a binary
  frame protocol. Port 443 so it survives restrictive networks. HTTP/3 +
  QUIC datagrams as a Phase 6 alternative for better loss behavior.
- Relays are **addressed by node public key**, hold no long-term state, and
  see only PHREATIC ciphertext. A relay operator learns who talks to whom, when,
  and how much — and nothing else. Documented plainly in the security model.
- Every connection begins over a relay and **upgrades to a direct path** when
  discovery succeeds, with no packet loss during the switch (the datapath
  keeps both paths warm and cuts over on receipt of the first direct packet).
- Region map: multiple relays per region, latency-probed by clients, published
  by the control server so self-hosters can add their own.
- Mesh mode: relays in a region gossip client presence so a peer connected to
  relay A in region X can be reached via relay B.
- Abuse controls: per-key rate limits, per-connection byte accounting,
  admission only for keys present in a signed tailnet roster. Strict mode is
  **mandatory for community-pool relays** — an open relay is an abuse conduit
  and hands its operator traffic they cannot inspect and did not agree to carry.
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

## 6. NAT traversal (`karst-disco`)

The hard, unglamorous part where most mesh VPNs actually fail. Budget generously.

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

- Assigns each node `<hostname>.<tailnet>.karst.` names, resolvable only inside
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
relative to a start of **2026-09-01**; adjust the anchor, keep the durations.

---

### Phase 0 — Foundations (3 weeks · Sep 2026)

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

### Phase 1 — Crypto core and protocol spec (6 weeks · Sep–Oct 2026)

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

### Phase 2 — Node agent, first packets (8 weeks · Nov–Dec 2026)

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

### Phase 3 — Coordination server and netmap (8 weeks · Jan–Feb 2027)

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
  be used and why circl is a dependency regardless. **28 tests** now pass
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
  cost a rehandshake with every other: on a large tailnet a single enrolment
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
  else, so a peer *inside* the tailnet prefix was reachable for free and a peer
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

### Phase 4 — Relays and NAT traversal (10 weeks · Mar–May 2027)

- `karst-relay` server: framing, mesh mode, region map, rate limits, metrics;
  co-located with the control server in the default deployment artefact.
- **TURN fallback** (ADR-0008): client-side allocation, permissions, channel
  binding and credential refresh; control-server ephemeral credential minting;
  coturn added to the NAT matrix. **Designated slip candidate for this phase** —
  the co-located relay covers the base case, so TURN moves to Phase 6 if the NAT
  matrix work overruns, rather than compressing the matrix work.
- `karst-disco`: STUN, candidate gathering, hole punching, port mapping,
  path selection with hysteresis, seamless relay→direct upgrade.
- Full NAT test matrix in CI (§6).
- Kubernetes operator + userspace mode + Docker images.
- **Exit:** ≥ 90% direct-connection rate across the matrix; relay fallback is
  automatic and lossless; a peer behind symmetric CGNAT reaches a peer behind
  a different symmetric CGNAT.

### Phase 5 — KarstDNS, Bedrock, admin console (10 weeks · May–Jul 2027)

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

### Phase 6 — Hardening and beta (8 weeks · Aug–Sep 2027)

- **External cryptographic review** of PHREATIC and its implementation
  (budget 4–6 weeks lead time; book this in Phase 3, not Phase 6).
- **External penetration test** of the control plane and console.
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

### Phase 7 — GA and mobile (12 weeks · Oct–Dec 2027)

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

**Total: ~65 weeks (~15 months) to GA**, Sep 2026 → Dec 2027. Self-hosted
Linux-to-Linux mesh with a working console is usable at end of Phase 5
(**~10 months**), and that is the milestone worth optimizing for.

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
5. Book an external cryptographic reviewer for Q3 2027 now — lead times are
   long and this is a hard gate on GA.
