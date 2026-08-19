<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-0011: Control-channel authentication and confidentiality

- **Status:** Proposed
- **Date:** 2026-08-13
- **Deciders:** TBD
- **Related:** ADR-0005 (data-plane identity), ADR-0009 (fork), ADR-0001
  (algorithm selection), Spike 0001 §5.2a, PLAN.md §4.2, §2.6

---

## Context

Phase 3 replaces the forked control server's identity spine. NetBird fuses
three roles into one X25519 WireGuard key — **authentication handle, primary
index, and transport encryption key** — carried in the envelope of every RPC:

```proto
message EncryptedMessage {
  string wgPubKey = 1;   // sender identity AND decryption routing
  bytes  body     = 2;   // NaCl box, sealed to the server's WG public key
  int32  version  = 3;
}
```

Karst has no such key. Its node identity is **ML-DSA-65** (1952 B) plus a
static **ML-KEM-768** key (1184 B); the X25519 in PHREATIC is ephemeral,
per-handshake, and never a static identity. So the envelope has to change, and
the question is what replaces it.

Spike 0001 §5.2a measured the blast radius against the compiler rather than by
grep. Making the identity opaque breaks 44 sites; a one-line `String()` method
fixes 32 of them, because they only ever used it as a label. The residual 12
split into 7 signature-cascade sites and **5 that genuinely need a key** —
`encryptResponse` ×3 and `encryption.EncryptMessage` ×2, all on the NaCl-box
path, all reached through one function, `parseRequest`. That function is the
whole decision surface.

### The constraint that eliminates the simplest option

The obvious simplification is to delete the inner layer entirely: gRPC already
runs over TLS, so carry a plaintext body and authenticate the sender with a
signature. One layer instead of two.

**This is not available to us, because the netmap carries secrets.** Per-pair
PSKs (§2.6) are distributed to nodes *in the netmap*, and PLAN.md's own risk
register records the consequence: "netmap now carries PSK secrets, raising the
value of a server compromise." Under TLS-only, every PSK in the network is
readable by anything that terminates TLS — a load balancer, an ingress
controller, a service mesh sidecar, a corporate middlebox. That is a routine
deployment, not an exotic attack.

NetBird's inner box exists for the same reason and it must survive the
refactor. **The inner layer is not redundant with TLS; it is what makes a
TLS-terminating proxy safe to deploy in front of the control server.**

### What the inner layer does *not* need to do

It is worth being precise, because PHREATIC's requirements do not all transfer:

| PHREATIC needs | Control channel |
|---|---|
| Single-datagram, stateless responder under flood | No — gRPC over TCP/TLS, connection-oriented |
| Fragmentation and reassembly (§9) | No — the stream handles it |
| Endpoint roaming, NAT rebinding | No — the node dials out |
| Identity confidentiality against a passive observer | Already provided by TLS |
| Mutual authentication | **Yes** |
| Confidentiality against a TLS terminator | **Yes** |
| Replay resistance | **Yes** |

## Decision

**Retain an inner cryptographic layer; split the three roles explicitly.**

### 1. The envelope names an opaque handle, never a key

```proto
message KarstEnvelope {
  bytes  node_id   = 1;   // server-assigned, opaque; NOT key material
  bytes  body      = 2;   // AEAD ciphertext under the channel key
  uint64 seq       = 3;   // per-channel counter, monotonic
  uint32 version   = 4;
}
```

`node_id` is the authentication handle and the database index. It is not
derived from and cannot be used as a key. The forked `Peer` model already has
`ID string \`gorm:"primaryKey"\`` with the WireGuard key as a mere uniqueness
index, so **the schema already separates what the protocol fused** — the
primary-index role costs nothing to split.

### 2. Channel establishment, once per stream

The server holds a **static** ML-KEM-768 key *and* an **ML-DSA-65 identity**,
both pinned at enrolment and distributed with the auth key or setup token, and
generates an **ephemeral** ML-KEM-768 keypair per connection.

```
server → node   ChannelHello  { server_kem_pk_id, eph_kem_pk, server_random[32],
                                signature }
node   → server ChannelInit   { ct_static, ct_eph, identity_pk?, node_id?, signature }
```

- `(ss_s, ct_static) = ML-KEM-768.Encaps(server_static_kem_pk)`
- `(ss_e, ct_eph)    = ML-KEM-768.Encaps(eph_kem_pk)`
- `k = HKDF-SHA-512(ss_s ‖ ss_e,
        "karst-control-v1" ‖ server_random ‖ ct_static ‖ ct_eph)`
- `signature = ML-DSA-65.Sign(identity_sk, "karst-control-init-v1" ‖
  server_random ‖ ct_static ‖ ct_eph ‖ node_id_or_empty)`

The server decapsulates both, derives `k`, and verifies the signature — against
the stored identity key when `node_id` is present, or against the **presented**
`identity_pk` during first registration, which is then bound to the new node
record. The ephemeral private key is destroyed when the connection ends.

**Each of the two encapsulations does a distinct job, and neither is
redundant:**

| | Provides | Lost if omitted |
|---|---|---|
| `ct_static` (pinned server key) | Implicit **server authentication** — only the real server can decapsulate, so an impostor derives the wrong `k` and the channel simply fails | Server auth would have to come from a server ML-DSA signature over `eph_kem_pk`, adding a second signature scheme to the path |
| `ct_eph` (per-connection key) | **Forward secrecy** — compromising the server's static key later does not decrypt recorded sessions | A recorded session, including every PSK it carried, decrypts retroactively on server-key compromise |

**`eph_kem_pk` is signed, and the node MUST verify it before transmitting.**

An earlier revision of this ADR left it unsigned, arguing: *"an attacker who
substitutes it cannot produce `ss_s`, so `k` diverges and the channel dies on
the first AEAD failure."* That argument is sound about **authentication** and
worthless about **forward secrecy**, which is what the ephemeral exists for.
ProVerif found the trace (`spec/models/karst-control.pv`):

1. The attacker rewrites `ChannelHello` so `eph_kem_pk` is **the server's own
   static public key** — a value the attacker simply reads off the wire.
2. The node encapsulates *both* ciphertexts to that one key:
   `ct_static = Encaps(S_pub, r₁)`, `ct_eph = Encaps(S_pub, r₂)`.
3. Both shared secrets are now recoverable from the server's long-term
   decapsulation key alone. The ephemeral half contributes nothing.
4. The channel does indeed die — but only *after* the node has sent
   `ChannelInit` and its first request, which carries an auth key. "Fails
   closed" does not help a message already on the wire.
5. When the static key later leaks, every recorded session decrypts.

The attacker needs no key material of their own. So the server holds an
**ML-DSA-65 identity** and signs `H("karst-control-hello-v1" ‖ server_random ‖
eph_kem_pk)`; the node pins that verification key alongside the KEM key at
enrolment and aborts before sending anything if it does not verify.

Both ciphertexts are bound into `k` and into the node's signature, so a
man-in-the-middle cannot mix and match halves from two exchanges.

This costs one extra 1088-byte ciphertext in `ChannelInit`, a 3309-byte
signature in `ChannelHello`, and **no extra round trip** — the ephemeral public
key rides in a `ChannelHello` that had to be sent anyway.

### Verification status

`spec/models/karst-control.pv` (ProVerif 2.05) discharges four queries:
channel-content secrecy in both directions under **post-session compromise of
the server's static key**, injective agreement on `ChannelInit`, and key
agreement. `spec/models/karst-control-nofs.pv` drops `ss_eph` from the key
schedule and is **expected to fail** the two secrecy queries while still
passing both authentication queries — an executable demonstration that the
ephemeral encapsulation buys forward secrecy and nothing else.

Subsequent messages in both directions are ChaCha20-Poly1305 under `k` with
`seq` as the nonce input. **Only the init is signed.** Because the signature
covers `kem_ct`, and `k` is derived from it, possession of `k` on later
messages is already attributable to whoever signed the init. Signing every
message would cost 3309 bytes each to prove something the AEAD proves for free.

### 3. `server_random` rather than a timestamp

The stream gives a free round trip, so the server contributes freshness
directly. PHREATIC's msg1 uses a timestamp because it must be single-datagram
and stateless (spec §5); the control channel is neither, so it can have the
stronger property without paying for it. No clock-skew window, no replay cache
for init messages.

### Alternatives rejected

**TLS-only, signature-authenticated plaintext bodies.** Simplest, and one fewer
thing to get wrong — but it exposes every per-pair PSK to any TLS terminator.
Rejected on §2.6 grounds above. This is the option to revisit *only* if PSK
distribution moves out of the netmap.

**Reuse PHREATIC for the control channel.** Attractive: one protocol, one
ProVerif model, one implementation to audit. It fails on registration.
PHREATIC is `IK` — the responder identifies the initiator by looking up
`peer_id_hint` in its roster (ADR-0005). **A registering node is by definition
not yet in any roster**, so the identity must be *presented* rather than looked
up, which is a different pattern (`XX`/`IX`-shaped). Forcing PHREATIC to carry
both would complicate the protocol that guards the datapath in order to serve
the one that does not. Rejected — but the primitives, the key-schedule
discipline, and the suite registry are shared, so this is a distinct handshake,
not a distinct cryptosystem.

**Keep NaCl box, re-keyed on a static X25519 control key.** Minimal diff from
the fork; every one of the 5 crypto sites keeps working with a different key
type. Rejected because it leaves a classical-only control channel in a
post-quantum product: an adversary recording control traffic today decrypts
every PSK in the network once a CRQC exists. The datapath would be PQ and the
key distribution for it would not.

**Sign every message with ML-DSA-65.** Stateless and simple to reason about.
Rejected on size: 3309 B per message against a netmap delta that is often
smaller than the signature, on a long-poll stream, for a property the channel
key already carries.

### Implementation note: where the primitives come from

Decided while implementing, 2026-08-13. ML-KEM-768, HKDF-SHA-512 and
ChaCha20-Poly1305 are all available without a new dependency —
`crypto/mlkem` and `crypto/hkdf` are Go standard library and
`golang.org/x/crypto` was already direct.

ML-DSA-65 was not. **Go 1.26 implemented it in `crypto/internal/fips140/mldsa`
and did not export it**; there was no public `crypto/mldsa` and `internal/` is
unimportable from outside std. `cloudflare/circl` v1.6.5 filled the gap.
`Signer` and `Verifier` are interfaces precisely so this choice stayed
reversible; see PLAN.md §3.2.

**Updated 2026-08-18: reversed, as designed.** Go 1.27 shipped the public
`crypto/mldsa` and `identity.go` now wraps it; circl left the module. The
interfaces did their job — the change was one file and nothing above it moved.
circl returns for Bedrock's SLH-DSA-SHA2-192s, which the standard library still
has no implementation of.

---

## Consequences

### Positive

- The three fused roles are separated by construction, and the type system
  enforces it: `node_id` is opaque bytes with no key operations defined on it.
- Confidentiality survives a TLS-terminating proxy, so the control server can
  be deployed behind ordinary infrastructure without leaking PSKs.
- The control channel becomes post-quantum, closing a gap that would otherwise
  have made the datapath's PQ guarantees moot for anything a CRQC could harvest
  now and decrypt later.
- Registration and steady-state use one code path, differing only in whether
  the identity key is presented or looked up.

### Negative

- **A second handshake to specify, implement, model and audit.** PHREATIC has a
  spec and a ProVerif model; this has neither yet, and shipping it without both
  would be inconsistent with how the datapath was treated. That work is not
  costed in Phase 3's estimate.
- Key pinning becomes an enrolment concern: a node that accepts any server KEM
  key on first contact is trust-on-first-use, with the usual consequences. The
  pinned key must travel with the auth key or setup token, and an enrolment
  path that omits it silently downgrades server authentication to whatever TLS
  provides.
- **Forward secrecy holds only for the *channel*, not for what crosses it.**
  `ct_eph` means a recorded session cannot be decrypted later. It does not help
  if the server itself is compromised while running: the server necessarily
  sees every PSK it distributes. §2.6 already states this — "server compromise
  plus a lattice break is a full break" — and this ADR does not change it.
- The construction is Noise-shaped but is **not** Noise, and is not covered by
  PHREATIC's ProVerif model. It needs its own model, and the mixed
  static-plus-ephemeral encapsulation is exactly the kind of construction where
  informal reasoning is unreliable.

### Reconsider if

- PSK distribution moves out of the netmap — the TLS-only option becomes
  available and is materially simpler.
- Post-quantum TLS (ML-KEM hybrid key exchange plus PQ certificates) becomes
  deployable in the Go and Rust stacks *and* the deployment story rules out
  TLS termination by third parties. Both conditions are needed; the first alone
  does not help, because it is the terminator and not the network that this
  layer defends against.
