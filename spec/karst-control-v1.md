<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# KARST-CONTROL v1 — Protocol Specification

- **Status:** Draft 0.1 — Phase 3 deliverable, modeled but not externally reviewed
- **Date:** 2026-08-13
- **License:** CC-BY-4.0 with an irrevocable, royalty-free grant to implement
  in software under any license. Independent implementations are wanted.

> **Implementable.** §4–§7 are stable enough to build against and match the Go
> implementation in `server/management/internals/karst/`. §11 lists what
> remains open.
>
> All four ProVerif queries verify (§10), including content secrecy under
> post-session compromise of the server's static key. **No external
> cryptographic review has happened**, and symbolic models say nothing about
> implementation behavior.
>
> §9 records a flaw found by modeling *after* the design had been reviewed,
> written up, implemented and tested: the server's ephemeral key was
> unauthenticated, which silently cost forward secrecy against an active
> attacker holding no key material.

---

## 1. Introduction

KARST-CONTROL carries the relationship between a Karst node and its
coordination server: registration, login, network-map delivery and the
per-pair PSK schedule. It runs as a bidirectional gRPC stream, **inside TLS**,
and provides mutual authentication and confidentiality independently of it.

### 1.1 Why a second protocol

Karst already has PHREATIC (`phreatic-v1.md`) for the data plane. Reusing it
here was considered and rejected — see ADR-0011.

PHREATIC is a Noise `IK` analog: the responder identifies the initiator by
looking up `peer_id_hint` in its roster (ADR-0005). **A registering node is by
definition not yet in any roster**, so its identity must be *presented* and
verified rather than looked up. That is a different pattern, and bending
PHREATIC to cover both would complicate the protocol guarding the data plane in
order to serve the one that does not.

The two share primitives, key-schedule discipline and the suite registry
(`phreatic-v1.md` §3). They are distinct handshakes, not distinct
cryptosystems.

### 1.2 Why an inner layer at all, given TLS

Because the network map **carries per-pair PSKs** (PLAN.md §2.6). Under
TLS-only, every PSK in the network is readable by anything terminating TLS: a
load balancer, an ingress controller, a service-mesh sidecar, a corporate
middlebox. Those are routine deployments.

The inner layer is not redundant with TLS. **It is what makes a TLS-terminating
proxy safe to put in front of the control server.** If PSK distribution ever
moves out of the netmap, this decision should be revisited — it is the sole
justification for the second layer.

### 1.3 What this protocol does not do

- **It is not a transport.** Ordering, retransmission and framing are gRPC's.
- **It has no DoS machinery.** No cookies, no stateless responder, no fragment
  MACs. PHREATIC needs those because it is single-datagram UDP; a TCP stream
  behind TLS is not the same threat surface.
- **It does not authenticate the *user*.** OIDC and auth keys ride *inside* the
  channel and are checked by the business layer.
- **It does not protect against a compromised running server.** The server
  necessarily sees every PSK it distributes. §2.6 of PLAN.md already states
  this and this protocol does not change it.

---

## 2. Conventions

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted
as in RFC 2119.

`‖` denotes concatenation. `H(x)` is SHA-512. All lengths are in bytes.

Every concatenation that is hashed is **length-prefixed**: each component is
preceded by its length as a 4-byte big-endian integer. Without this,
`("ab","c")` and `("a","bc")` hash identically, and both the transcript and the
signature input are built from attacker-influenced variable-length fields.

---

## 3. Cryptographic suite

Version 1 (`KARST_CONTROL_1`) only:

| Role | Algorithm | Size |
|---|---|---|
| Key encapsulation | ML-KEM-768 (FIPS 203) | pk 1184 B, ct 1088 B, ss 32 B |
| Signature | ML-DSA-87 (FIPS 204) | pk 2592 B, sig 4627 B |
| AEAD | ChaCha20-Poly1305 | key 32 B, nonce 12 B, tag 16 B |
| Hash / KDF | SHA-512 / HKDF-SHA-512 | 64 B |

**This is the control channel's own registry, not PHREATIC's.** Earlier drafts
said "suite `0x0001` (`KARST_1`), matching `phreatic-v1.md` §3", which stopped
being true twice over: [ADR-0015](../docs/adr/0015-cnsa-2-0-as-a-mandate.md)
item 4 gave this channel its own versioned registry, and item 7 then removed
ChaCha20-Poly1305 from the data plane entirely, so PHREATIC's `0x0001` is now an
AES-256-GCM suite and this one is not.

**ChaCha20-Poly1305 here is therefore the last of it in the tree, and it is a
conformance gap.** A deployment under CNSA 2.0 or seeking FIPS 140-3 validation
cannot run it in the approved boundary. Version 2
(`KARST_CONTROL_2_MLKEM1024_MLDSA87_AES256GCM_SHA512`) is reserved and named for
exactly this, and is not yet implemented: both primitives exist, so what remains
is dispatch. Until it lands, the control channel is the one place a mandated
deployment is not conformant, and it should be read as an open item rather than
as a settled choice.

Suite negotiation is **not** in v1, and will not be in any version. The suite
is implied by the protocol version in each message, and the registry that makes
that concrete is `channel/suite.go` with its Rust mirror.

**One number gates both the envelope format and the algorithms**, which is the
point rather than a convenience: an algorithm cannot change without the version
changing. That property went missing once already — ADR-0015 moved this channel
from ML-DSA-65 to ML-DSA-87 while the version was a bare constant, and nothing
objected. Nothing was deployed, so nothing broke; the same edit against a live
fleet would have produced handshakes failing on a signature with no indication
why.

**There is no negotiation because there is nothing to discover.** The data
plane negotiates (`phreatic-v1.md` §3) because two nodes configured by
different people must agree. A control channel is one operator's node talking
to their own server, so a negotiation would be a downgrade surface bought for
nothing.

What replaces it is a **floor**. The server states its version; the node
refuses anything below its own configured minimum, even a version it
implements. That is ADR-0006's rule — a compromised server may raise the floor
and never lower it — applied to the one channel ADR-0006 did not cover.

Two consequences worth stating:

- **A known-but-unimplemented version fails differently from an unknown one.**
  "This build does not implement version 2 (the CNSA 2.0 suite)" is actionable;
  "unsupported version" is not. Version 2 is therefore *reserved* in the
  registry rather than absent from it.
- **Pin sizes come from the suite.** A node pins its server's static KEM and
  verification keys, and a key's length is its algorithm — 1 184 bytes is
  ML-KEM-768 and can be nothing else. So a deployment configured for one
  version with pins from another fails at startup naming both sizes, rather
  than at the handshake, where the symptom sends somebody looking in the wrong
  place.

| Version | Suite | State |
|---|---|---|
| 1 | ML-KEM-768, ML-DSA-87, ChaCha20-Poly1305, SHA-512 | Implemented |
| 2 | ML-KEM-1024, ML-DSA-87, AES-256-GCM, SHA-512 | Reserved — the CNSA 2.0 profile (ADR-0015) |

---

## 4. Identities and pinning

### 4.1 The server holds two keypairs

| Key | Purpose |
|---|---|
| **Static ML-KEM-768** | Long-lived. Nodes encapsulate to it; only the real server can decapsulate, which authenticates the server implicitly |
| **ML-DSA-87 identity** | Long-lived. Signs the per-connection ephemeral key, which is what makes forward secrecy real (§9) |

A node MUST be given **both** public halves out of band at enrollment,
alongside its auth key or setup token. Distributing only the KEM half silently
downgrades forward secrecy to nothing against an active attacker; an
implementation MUST refuse to proceed without a pinned verification key.

The server also generates a **per-connection ephemeral ML-KEM-768 keypair**.
Its private half MUST be destroyed when the connection ends and MUST NOT be
persisted.

### 4.2 The node holds one keypair

An **ML-DSA-87 identity**, generated locally and sealed at rest. This is the
same identity used everywhere else in Karst, so signatures MUST carry a FIPS
204 context string (§6.3) to keep the uses apart.

### 4.3 Node handles

A node is named on the wire by an opaque **handle**, never by key material:

```
handle = BASE64(SHA-256("karst-node-handle-v1" ‖ identity_pk))
```

44 characters. The label is not decorative: the data plane also hashes public
keys (ADR-0005's `peer_id_hint`, over the *KEM* key), and two unlabelled hashes
of related material is how a correlation channel gets built by accident.

The length is deliberate — it matches a base64 X25519 key, so the handle drops
into a schema that indexes WireGuard keys without a migration. That is an
implementation convenience, not a protocol requirement; other implementations
MAY use any stable, unique string.

---

## 5. Messages

All messages are protobuf; see `karst_control.proto`.

### 5.1 ChannelHello — server speaks first

| Field | Size | Notes |
|---|---|---|
| `server_kem_pk_id` | 16 B | Truncated hash of the static key, so the server can rotate without breaking nodes mid-rotation |
| `eph_kem_pk` | 1184 B | Per-connection ephemeral encapsulation key |
| `server_random` | 32 B | Freshness |
| `signature` | 4627 B | ML-DSA-87 over §6.2 |
| `version` | — | 1 |

**The server MUST speak first.** The node signs over `server_random`, which it
has not yet seen, so a captured `ChannelInit` is useless on another connection.

PHREATIC uses a timestamp instead (`phreatic-v1.md` §5) because it must be
single-datagram and stateless under flood. A stream is neither, so it can have
the stronger property at no cost: no clock-skew window, no replay cache.

### 5.2 ChannelInit — node answers

| Field | Size | Notes |
|---|---|---|
| `ct_static` | 1088 B | Encapsulation to the **pinned** static key |
| `ct_eph` | 1088 B | Encapsulation to `eph_kem_pk` |
| `identity_pk` | 2592 B | Present **only** when registering |
| `node_id` | 44 B | Empty on first registration |
| `signature` | 4627 B | ML-DSA-87 over §6.3 |
| `version` | — | 1 |

`identity_pk` MUST be absent for a node that already has a handle: a known node
presenting a *different* key is identity substitution, not re-registration, and
the server MUST reject it.

Measured field sizes, asserted in `TestHandshakeSizes` so a change shows up as
a diff rather than as drift:

| Message | Bytes |
|---|---|
| `ChannelHello` | 4541 |
| `ChannelInit`, registration (identity presented) | 7437 |
| `ChannelInit`, steady state (identity looked up) | 5485 |

Once per connection, not per message. Roughly 12 KB to open a channel, against
PHREATIC's 4614 B to open a data-plane session — the control channel can afford
it because it is amortised over a long-lived stream rather than paid per peer
per rekey.

### 5.3 KarstEnvelope — everything afterwards

| Field | Notes |
|---|---|
| `node_id` | Cleartext handle. **Not key material**; no key operation is defined on it |
| `body` | ChaCha20-Poly1305 ciphertext |
| `seq` | Monotonic per direction, and the nonce input |
| `version` | 1 |

### 5.4 Network-map delivery

`KarstNetmapRequest` asks for the caller's current map. `known_version = 0`
means that the caller holds no map; any other value is the content hash in
§5.5. A matching value produces an `unchanged` response with no replacement
content. A non-matching response is either a complete replacement or a delta;
the `delta` flag, not an empty peer list, distinguishes those cases. On a
complete replacement the node MUST discard every peer absent from `peers`; on a
delta it MUST apply `peers` and `removed_peers` to the map it already holds.

The request's `sessions` field (wire field 4) is an authenticated, advisory
report from the node that measured each peer path. Each observation names the
stable peer `node_id` from the netmap — never a DNS/display label — and carries
`direct`, `relay`, or `unreachable`, an optional endpoint, the PSK-fallback
indicator and epoch, and the suite bound into the session's handshake
parameters. The server timestamps receipt, validates bounded text and
duplicate handles, and MUST NOT deny or delay a netmap when observation
persistence fails. Observations contain no PSK, discovery key, or private
material and are rendered as last-known telemetry rather than current truth.

Each `KarstNetmapPeer` contains its routable identity material, current and
previous PHREATIC PSKs, and these additional fields:

| Field | Wire field | Meaning |
|---|---:|---|
| `disco_key` | 9 | 32-byte AVEN per-pair path-discovery key for this peer at `psk_epoch` |
| `psk_previous` | 8 | PHREATIC PSK at `psk_epoch - 1`; empty at epoch zero |

`disco_key` is derived independently of the PHREATIC PSK and travels only in
the encrypted control-plane envelope. An empty value disables discovery for
that peer; the node MUST retain or use a relay path rather than treating it as
a zero key.

`KarstNetmapResponse.relays` (wire field 13) is the ordered registry of Ponor
relays available to the node. Each `KarstRelay` has `address`, 32-byte
`relay_id`, the relay's 2592-byte ML-DSA-87 `identity_key`, optional `region`,
and `tls_server_name`. The latter is used only for TLS SNI and certificate
validation; the node MUST pin `identity_key` and check `relay_id` during the
Ponor handshake (`ponor-v1.md` §4.2). A non-unchanged response replaces the
registry wholesale, including with an empty registry.

### 5.5 Network-map version

`version` is the leading eight bytes, interpreted big-endian, of SHA-256 over
the map's canonical content. Zero is remapped to one because zero means "I
hold no netmap" in a request. Let `LP(x)` be a four-byte big-endian length of
`x` followed by `x`. The hash input is, in order:

```
"karst-netmap-version-v1" || BE32(psk_epoch) ||
LP(node_id) || LP(dns_name) || LP(addresses[0]) || ... ||
each peer's LP(node_id, kem_public_key, dh_public_key, dns_name, endpoint,
               allowed_ips[0], ...) ||
each ingress filter rule's LP(sources..., BE32(first) || BE32(last), ...) ||
LP("karst-egress-filter") ||
each egress filter rule's LP(destinations..., BE32(first) || BE32(last), ...) ||
LP("karst-relays") ||
each relay's LP(address, tls_server_name, relay_id, identity_key, region) ||
LP("karst-dns") ||
LP(dns_config.zone) || BE32(dns_config.magic_dns ? 1 : 0) ||
LP(dns_config.nameservers[0]) || ... ||
LP(dns_config.search_domains[0]) || ... ||
each route's LP(match_domain, resolvers[0], ...) ||
LP("karst-bedrock") ||
LP(bedrock_head.hash) || LP(BE64(bedrock_head.seq))
```

Repeated values are encoded in their transmitted order; that order is therefore
part of the map content. The PSK, previous PSK, and `disco_key` bytes are
deliberately excluded: each is secret material determined by a pair and epoch,
and `psk_epoch` already makes an epoch rotation move the version. Relay fields
are included so that a node holding an old relay registry cannot be told that
its map is unchanged. The `"karst-relays"` separator is load-bearing: it makes
an empty relay registry part of the construction and prevents a future relay
encoding from being ambiguous with the preceding egress-filter sequence.

**Compatibility note (2026-08-18).** The relay separator and relay entries
were added to this construction after the original vectors. Consequently all
pre-change `netmap_version` values are intentionally incompatible; the
regenerated vectors record the new construction.

**Compatibility note (2026-08-22).** The `"karst-dns"` separator and DNS
configuration were added after the relay construction. An absent proto message
is encoded as its all-zero default (empty strings/lists and `BE32(0)`), so all
maps use one unambiguous construction; pre-change version values are
intentionally incompatible.

**Compatibility note (2026-08-25).** The `"karst-bedrock"` separator and log
head were added after the DNS construction. An absent head encodes as its
all-zero default (empty hash, `BE64(0)`), which is unambiguous because Bedrock
sequence numbering starts at one. Pre-change version values are intentionally
incompatible.

Both the head hash **and** its sequence are hashed. Hashing only the hash would
let a server rewind its log and re-serve an earlier tip without the version
moving, which would leave a node enforcing against coverage it believes is
current (`bedrock-v1.md` §5).

---

## 6. Key schedule

### 6.1 Derivation

```
(ss_s, ct_static) = ML-KEM-768.Encaps(server_static_kem_pk)
(ss_e, ct_eph)    = ML-KEM-768.Encaps(eph_kem_pk)

salt   = H("karst-control-v1" ‖ server_random ‖ ct_static ‖ ct_eph)
k_c2s  = HKDF-SHA-512(ss_s ‖ ss_e, salt, "karst-control-v1 node-to-server", 32)
k_s2c  = HKDF-SHA-512(ss_s ‖ ss_e, salt, "karst-control-v1 server-to-node", 32)
```

**Both encapsulations are load-bearing and neither is redundant:**

| | Provides | Lost if omitted |
|---|---|---|
| `ct_static` | Implicit **server authentication** — an impostor derives a different key and the channel fails closed | Server authentication would rest on the signature alone |
| `ct_eph` | **Forward secrecy** — later compromise of the static key does not decrypt recorded sessions | Every recorded session, and every PSK in it, decrypts retroactively |

`spec/models/karst-control-nofs.pv` drops `ss_e` and fails the secrecy queries
while still passing both authentication queries. It is kept as an executable
demonstration that this table is true rather than asserted.

**Separate keys per direction**, so a plain counter can be the nonce with no
risk of the two ends colliding on one.

### 6.2 The server's hello signature

```
sig_hello = ML-DSA-87.Sign(server_identity_sk,
                H("karst-control-hello-v1" ‖ server_random ‖ eph_kem_pk))
```

The node MUST verify this **before deriving keys and before transmitting
anything**. §9 explains what happens otherwise.

### 6.3 The node's init signature

```
sig_init = ML-DSA-87.Sign(node_identity_sk,
               H("karst-control-init-v1" ‖ server_random ‖ ct_static
                                         ‖ ct_eph ‖ node_id))
ctx      = "karst-control-v1"          (FIPS 204 context string)
```

Both ciphertexts are bound into the signature *and* into `salt`, so a
man-in-the-middle cannot mix halves from two exchanges.

**Only the init is signed.** Because the signature covers both ciphertexts and
the keys derive from them, possession of a channel key on later messages is
already attributable to whoever signed the init. Signing every message would
cost 4627 bytes to prove what the AEAD proves for free.

Signing SHOULD be **hedged** (randomized). FIPS 204 permits either; the
randomized form does not hand a fault-injection attacker a repeatable target.

---

## 7. Record layer

- Nonce is `seq` big-endian in the low 8 bytes of a 12-byte nonce, zero-padded.
- Associated data is `node_id ‖ seq`, binding the cleartext envelope fields so
  a proxy cannot relabel one node's traffic as another's.
- `seq` starts at 1 and MUST strictly increase per direction. A receiver MUST
  reject any `seq` it has already accepted or passed.
- `seq` MUST be checked **before** the AEAD, so a replay costs a comparison
  rather than a decryption.
- `recv_seq` MUST advance **only on successful decryption**, so a forged
  envelope cannot burn sequence numbers the real peer still intends to use.
- A decryption failure MUST end the stream. The transport is ordered and
  authenticated, so a failure means tampering or a bug; there is no recovery
  that does not weaken the channel.

No replay *window* is needed, unlike `phreatic-v1.md` §8, because the transport
is an ordered stream rather than UDP.

---

## 8. Error handling

Handshake rejections MUST be **uniform**. Distinguishing "no such node" from
"bad signature" gives an unauthenticated caller a node-handle oracle. One
`Unauthenticated` status, no detail.

An envelope arriving before `ChannelInit`, or a second `ChannelInit` on an
established channel, MUST end the stream. The latter would reset sequence
counters under a key the peer has already used.

---

## 9. The flaw modeling found

Recorded because the reasoning was plausible, survived review, and was wrong.

The first revision left `eph_kem_pk` **unsigned**, arguing: *an attacker who
substitutes it cannot produce `ss_s`, so the key diverges and the channel dies
on the first AEAD failure.* That is correct about **authentication**. It is
worthless about **forward secrecy**, which is the only thing the ephemeral key
exists to provide.

ProVerif's trace:

1. The attacker rewrites `ChannelHello` so that `eph_kem_pk` is **the server's
   own static public key** — a value read off the wire, requiring no key
   material of the attacker's own.
2. The node encapsulates both ciphertexts to that single key:
   `ct_static = Encaps(S_pub, r₁)` and `ct_eph = Encaps(S_pub, r₂)`.
3. Both shared secrets are now recoverable from the server's long-term
   decapsulation key alone. The ephemeral half contributes nothing.
4. The channel does die — but only *after* the node has sent `ChannelInit` and
   its first request, which carries an auth key. **"Fails closed" does not help
   a message already on the wire.**
5. When the static key later leaks, every recorded session decrypts.

The fix is §6.2: the server signs its ephemeral key, and the node verifies
before transmitting.

Two things are worth taking from this beyond the fix. **No test would have
caught it** — every test agreed with the same wrong reasoning that produced the
code, and 51 of them passed. And the flawed argument was *locally* valid: it
answered a question about authentication correctly and was then applied to a
different property.

---

## 10. Formal verification

`spec/models/karst-control.pv`, ProVerif 2.05:

| Query | Result |
|---|---|
| Netmap secrecy (server→node), with static-key compromise in phase 1 | ✅ |
| Request secrecy (node→server), same | ✅ |
| Injective agreement on `ChannelInit` | ✅ |
| Channel-key agreement | ✅ |

`karst-control-nofs.pv` drops `ss_e`: both secrecy queries **fail**, both
authentication queries still pass. That is the intended result and a run in
which it passes means the model has stopped testing anything.

Not modeled: the record layer's sequence numbers, gRPC framing, and TLS. TLS
is deliberately excluded — the point of this layer is to hold up when a TLS
terminator is hostile, so modeling it would assume away the threat.

Two red results during development were **modeling artifacts**, recorded so
future readers do not mistake them for findings: an unscoped agreement query
(the attacker may legitimately register as itself) and an event-ordering
mistake (the node emitted completion after its send, though the implementation
derives keys first).

---

## 11. Open items — this draft is incomplete

1. **No external cryptographic review.** As with PHREATIC, this is the largest
   gap.
2. **Key rotation is specified only in outline.** `server_kem_pk_id` exists so
   the server can rotate, but the rotation procedure, overlap window and node
   behavior on an unrecognized id are unwritten.
3. **Enrollment is out of scope here** and is where pinning actually happens. A
   node that accepts any server key on first contact is trust-on-first-use,
   with the usual consequences. This needs its own specification.
4. **No downgrade protection**, because there is nothing to downgrade to yet.
   When a second suite exists, the version field alone will not be enough.
5. **Post-compromise security is absent.** A node whose identity key leaks is
   impersonable until it is revoked out of band; there is no ratchet.
6. **The record layer has no rekeying.** `seq` is 64 bits, which will not
   exhaust, but a long-lived channel keeps one key indefinitely.
7. **Padding is not specified.** Message lengths leak which request is being
   made, inside TLS, to an observer who is already past TLS.
