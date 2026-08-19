<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# PONOR v1 — Relay Protocol Specification

- **Status:** Draft 0.2 — Phase 4 deliverable, modelled but not externally reviewed
- **Date:** 2026-08-14
- **Licence:** CC-BY-4.0 with an irrevocable, royalty-free grant to implement
  in software under any licence. Independent implementations are wanted.

> **Implementable.** §4–§9 are stable enough to build against and match the
> Rust implementation in `crates/karst-relay-proto/`. §13 lists what remains
> open, and the list is longer than the other two specs' because this is an
> early draft rather than a third.
>
> All four ProVerif queries verify (§12), against an attacker who **operates a
> relay the honest client legitimately connects to** — the configuration
> ADR-0008 §6 offers as a community pool.
>
> Two things the model changed, recorded because both were wrong in draft 0.1.
> §12.2 states the design decision this specification got right for a reason it
> had not identified: the load-bearing field is `relay_id`, not `role`. And
> §13.3 states what the model *cannot* show, which is that Ponor's
> authentication does not extend past the handshake.

---

## 1. Introduction

Ponor is the protocol between a Karst node and a **relay** (`karst-relay`), and
between relays in a meshed region. A relay forwards opaque PHREATIC datagrams
between nodes that cannot reach each other directly, and reports which nodes are
currently reachable through it.

Relays are **untrusted infrastructure**. They carry ciphertext they cannot read
and are assumed to be curious about everything they *can* see. The protocol's
job is therefore narrow: get frames to the right place, let nobody but the
roster's members use the relay at all, and add nothing to what a relay operator
learns beyond what forwarding inherently reveals.

The design owes an explicit debt to Tailscale's **DERP** — mesh presence,
home-relay selection, relay-first-then-upgrade. ADR-0008 rules out both wire
compatibility and use of their fleet, for reasons that are ethical first and
technical second. The prior art is credited; the protocol is ours.

### 1.1 What Ponor does

| | |
|---|---|
| **Forwarding** | Node → relay → node, addressed by node ID, payload opaque |
| **Mutual authentication** | Post-quantum, both directions, before any frame is forwarded |
| **Admission control** | Structural rather than optional — §5.3 |
| **Presence** | Which nodes are reachable here, gossiped across a meshed region |
| **Liveness** | Keepalive and RTT measurement, which is also home-relay selection input |

### 1.2 What Ponor does not do

- **It does not encrypt the payload.** The payload is already a PHREATIC
  datagram, encrypted end to end between the two nodes. TLS covers the
  node↔relay hop against the network. Adding a third layer would protect
  metadata from a TLS terminator but not from the relay itself, which is the
  party the metadata is being disclosed to. That trade is not worth a second
  record layer, and the asymmetry with `karst-control-v1.md` §1.2 is deliberate:
  there, the inner layer hid **PSKs** from a TLS terminator that the *server*
  was also trusted with. There is no equivalent secret here.

  This argument is about **confidentiality** and does not carry over to
  **integrity**: with no inner layer there is also no session key, so nothing
  but TLS protects the frame headers. §13.3 states what that costs and why it
  is accepted rather than fixed.
- **It does not inspect the payload.** A relay MUST treat a forwarded payload as
  opaque octets (§7.1). It is not a PHREATIC parser and a relay compromise
  therefore cannot be a PHREATIC parsing bug.
- **It does not authorise.** Whether two nodes may exchange traffic is an ACL
  question, decided by the packet filter at both endpoints
  (PLAN.md §4.3). Ponor enforces only that both ends are admitted members of the
  same tailnet (§5.4) — an abuse control, not an access-control decision.
- **It is not a transport.** Ordering, retransmission and congestion control are
  TCP's. §13.5 records what that costs.
- **It provides no forward secrecy of its own.** It performs no key agreement.
  TLS 1.3 with `X25519MLKEM768` provides it for the hop; the payload's forward
  secrecy is PHREATIC's.

---

## 2. Conventions

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted
as in RFC 2119.

`‖` denotes concatenation. `H(x)` is SHA-512. Integers on the wire are
**big-endian**. All lengths are in bytes.

Every concatenation that is hashed is **length-prefixed**: each component is
preceded by its length as a 4-byte big-endian integer. This matches
`karst-control-v1.md` §2 and is not optional even where every field here is
fixed-width — a future field that is not fixed-width would otherwise inherit an
ambiguity nobody re-derived.

---

## 3. Cryptographic suite

Suite `0x0001` (`KARST_1`), the same registry entry as `phreatic-v1.md` §3.
Ponor uses only the signature and hash halves:

| Role | Algorithm | Size |
|---|---|---|
| Signature | ML-DSA-65 (FIPS 204) | pk 1952 B, sig 3309 B |
| Hash | SHA-512 | 64 B |
| Identifier hash | SHA-256 | 32 B |

No KEM and no AEAD: Ponor derives no keys. Suite negotiation is not in v1; the
suite is implied by the version byte in each handshake frame.

---

## 4. Transport

### 4.1 TLS and the HTTP upgrade

A Ponor connection is a TCP connection carrying TLS 1.3, on which the client
performs an HTTP/1.1 upgrade:

```
GET /ponor HTTP/1.1
Host: relay.example.com
Connection: Upgrade
Upgrade: ponor
Ponor-Version: 1

HTTP/1.1 101 Switching Protocols
Connection: Upgrade
Upgrade: ponor
```

Everything after the 101 is Ponor frames (§6) in both directions.

Three requirements, each load-bearing:

- The TLS key exchange MUST offer and SHOULD negotiate **`X25519MLKEM768`**.
  Relays are where the whole network's metadata converges; recording that hop
  for later decryption is the cheapest possible harvest-now-decrypt-later
  target. A client MUST refuse a connection that negotiates a classical-only
  group unless explicitly configured otherwise, and an implementation that
  offers such a configuration MUST surface it as a downgrade.
- The default port is **443**, and the framing is an HTTP upgrade rather than a
  bare TLS stream, so a relay survives networks that permit only HTTPS and so
  that it can **share a port and a certificate with the coordination server**.
  That sharing is what makes ADR-0008's co-location default free: one host, one
  cert, one listener, distinguished by path.
- TLS provides confidentiality for the hop. It does **not** provide the relay's
  identity (§5.2).

### 4.2 The relay is not authenticated by its certificate

A client MUST NOT treat successful TLS certificate validation as
authentication of the relay. Relay identity is established by §5.2's signature
over an ML-DSA-65 key published in the relay registry.

The certificate is still required and still validated — it is what makes the
connection look like and behave like HTTPS — but three things make it
insufficient on its own:

1. **WebPKI is classical.** RSA and ECDSA certificate signatures are forgeable
   by a CRQC. PLAN.md §1.1 declares real-time MITM by a CRQC out of scope for
   v1, so this alone would not force the issue — but it means relay identity
   would be the one hop in Karst with no post-quantum authentication at all,
   which is not a defensible thing to ship in a product whose claim is that it
   has none of those.
2. **Self-hosting.** The realistic deployment is a self-hoster with an internal
   CA, a self-signed certificate, or a certificate for a hostname that is not
   the relay's own. Pinning an ML-DSA key distributed through the netmap works
   in all of those; pinning a certificate chain works in none of them
   uniformly.
3. **Termination.** A relay behind a shared load balancer or CDN has a valid
   certificate for the hostname and is not thereby the relay. This is the same
   reasoning as `karst-control-v1.md` §1.2, applied to identity rather than
   confidentiality.

### 4.3 `derp://` is rejected

Per ADR-0008 §2, a relay registry entry whose scheme is `derp://` MUST be
rejected at parse time, and `karst-relay` MUST NOT implement a DERP
compatibility mode. This is a standing constraint recorded so that a future
contributor does not add it as a helpful-looking feature: wire compatibility
would produce a client whose default behaviour consumes strangers' bandwidth.

---

## 5. Identities and admission

### 5.1 Node identity

A node is named on the wire by its 32-byte **node ID**:

```
node_id = SHA-256("karst-node-handle-v1" ‖ identity_pk)
```

This is the same value as the KARST-CONTROL **handle** (`karst-control-v1.md`
§4.3), which is its base64 presentation. The raw digest is used here because
the ID appears on every forwarded frame and 32 bytes of overhead is preferable
to 44 for the same information. Implementations MUST treat the two as the same
identifier and MUST NOT derive a third.

`identity_pk` is the node's ML-DSA-65 identity key — the same key that
authenticates the control channel. Ponor signatures therefore MUST carry the
FIPS 204 context string `"ponor-v1"` (§5.5) so that no signature produced for
one protocol is verifiable in the other.

### 5.2 Relay identity

A relay holds its **own** ML-DSA-65 keypair, distinct from any node identity.
An implementation MUST NOT allow a relay key and a node key to be the same key,
even when the relay is co-located with a node or with the coordination server.

```
relay_id = SHA-256("karst-relay-id-v1" ‖ relay_identity_pk)
```

The coordination server publishes `(relay_id, relay_identity_pk, endpoint,
tls_server_name, region)` in the relay registry and ships it in the netmap.
`tls_server_name` is the DNS name used for TLS SNI and certificate validation;
it is deliberately separate from `endpoint`, which may be an IP address or a
load-balancer target. A client MUST have
the relay's public key before connecting and MUST refuse to proceed without
one. A relay it cannot verify is a relay it does not use.

### 5.3 Admission control is structural

The relay verifies a client's signature against the public key it holds for
that `node_id` in its **roster** — the set of admitted nodes, signed by the
coordination server and distributed to the relay out of band of any client.

The client does **not** present its public key on the wire. This is the single
most important design decision in the protocol, and the reason is that it makes
the open-relay configuration unreachable rather than merely discouraged:

> A relay with no roster entry for a `node_id` **cannot verify that node's
> signature at all**. There is no code path in which an unknown node is
> admitted, because admitting it would require a key the relay does not have.

ADR-0008 §6 requires signed-roster admission for community-pool relays and
PLAN.md §5 had left it as a mode. Carrying the key on the wire would have made
"verify the presented key's signature and let it in" a two-line change that
looks like a convenience feature. It is now not expressible.

The same reasoning appears throughout Karst and is worth naming: **an absent
value must never read as permissive.** An empty roster admits nobody. An
unrecognised `relay_id` is rejected, not trusted. A missing relay public key
stops the connection rather than falling back to the certificate.

Cost, stated plainly: roster distribution becomes a hard operational
dependency. A relay whose roster is stale rejects nodes that were legitimately
added since. §13.2 lists the freshness and revocation semantics as open.

### 5.4 Tailnet scoping

A roster entry names the tailnet the node belongs to. A relay MUST refuse to
forward a frame unless the source and destination are in the **same** tailnet.

Without this rule a multi-tenant relay is a general-purpose message bus between
any two keys it has ever been told about, which is both an abuse conduit and a
cross-customer channel that no operator agreed to carry.

### 5.5 Signature inputs

```
ctx = "ponor-v1"                                    (FIPS 204 context string)

sig_client = ML-DSA-65.Sign(identity_sk, ctx,
                 H("ponor-client-auth-v1" ‖ relay_id ‖ relay_random
                                          ‖ client_random ‖ peer_id ‖ role))

sig_relay  = ML-DSA-65.Sign(relay_identity_sk, ctx,
                 H("ponor-relay-auth-v1"  ‖ relay_id ‖ relay_random
                                          ‖ client_random ‖ peer_id ‖ role))
```

`peer_id` is the connecting party's ID — a `node_id` when `role = CLIENT`, a
`relay_id` when `role = MESH`. Signing SHOULD be hedged (randomized); FIPS 204
permits either form and the randomized one does not hand a fault-injection
attacker a repeatable target.

Four bindings, each closing something specific:

| Bound field | Prevents |
|---|---|
| `relay_id` | **A rogue relay replaying the client's authentication to the real relay.** A client that reaches an impostor produces a signature naming the impostor, which the real relay will not accept. |
| `relay_random` | Replay of a recorded `ClientAuth` onto a new connection |
| `client_random` | Replay of a recorded `RelayAuth`; the relay's signature is fresh with respect to the client |
| `role` | Cross-role confusion — a client's authentication being accepted as a mesh peer's, which would grant it §8's forwarding privileges |

The two labels are distinct so that neither party's signature is ever a valid
value for the other's, even though the signed field lists are otherwise
identical.

---

## 6. Framing

Every message after the 101 is a frame:

```
 0        1        2        3        4
 +--------+--------+--------+--------+
 |  type  |      length (24 bits)    |
 +--------+--------+--------+--------+
 |  payload (length bytes)           |
 +-----------------------------------+
```

- `type` — one byte, §6.1.
- `length` — 24-bit big-endian payload length.

A reader MUST reject, and close the connection on, a frame whose `length`
exceeds **4096** — before allocating anything. The 24-bit field can express
16 MB; the cap is what makes a frame header safe to act on. 4096 is chosen as
the smallest power of two above the largest legal frame (`ClientAuth`, 3375 B)
with room for a future field, and it is checked in addition to the exact
per-type lengths below, not instead of them.

A reader MUST reject a frame whose `length` does not match the exact length its
`type` requires, and MUST reject an unknown `type`. Ponor v1 has **no
forward-compatible extension point**: a frame nobody recognises is an error, not
something to skip. Silently ignoring unknown frames is how a downgrade is
mounted against a protocol that has no other negotiation to attack.

### 6.1 Frame types

| Type | Name | Direction | Payload | Length |
|---|---|---|---|---|
| `0x01` | `RelayHello` | relay → peer | `version ‖ relay_id ‖ relay_random` | 65 |
| `0x02` | `ClientAuth` | peer → relay | `version ‖ role ‖ peer_id ‖ client_random ‖ sig_client` | 3375 |
| `0x03` | `RelayAuth` | relay → peer | `version ‖ sig_relay` | 3310 |
| `0x04` | `SendPacket` | client → relay | `dst_id ‖ payload` | 33..1368 |
| `0x05` | `RecvPacket` | relay → client | `src_id ‖ payload` | 33..1368 |
| `0x06` | `PeerGone` | relay → peer | `peer_id ‖ reason` | 33 |
| `0x07` | `Ping` | either | `token` | 8 |
| `0x08` | `Pong` | either | `token` | 8 |
| `0x09` | `Restarting` | relay → peer | `reconnect_in_ms ‖ try_for_ms` | 8 |
| `0x0a` | `Close` | either | `reason` | 1 |
| `0x0b` | `PeerPresent` | mesh → mesh | `node_id` | 32 |
| `0x0c` | `Forward` | mesh → mesh | `src_id ‖ dst_id ‖ payload` | 65..1400 |
| `0x0d` | `ReflectOffer` | relay → client | `reflect_key ‖ endpoint` | 51 |

`version` is `0x01`. `role` is `0x01` (`CLIENT`) or `0x02` (`MESH`); any other
value MUST be rejected.

`payload` in `SendPacket`, `RecvPacket` and `Forward` is between 1 and **1336**
bytes — the largest datagram PHREATIC emits (`phreatic-v1.md` §13.6,
`TRANSPORT_DATAGRAM_MAX`). A zero-length payload MUST be rejected: it costs a
frame header and delivers nothing, which makes it a pure amplification unit.

### 6.2 Reason codes

`PeerGone.reason` and `Close.reason`:

| Code | Meaning |
|---|---|
| `0x00` | `NOT_HERE` — the destination is not connected to this relay or its mesh |
| `0x01` | `DISCONNECTED` — the destination was here and has gone |
| `0x02` | `NOT_ADMITTED` — the destination is not in the roster, or not in this tailnet |
| `0x03` | `REPLACED` — a newer connection for this ID has been accepted |
| `0x04` | `RATE_LIMITED` — sustained excess; see §7.4 |
| `0x05` | `SHUTTING_DOWN` |
| `0x06` | `PROTOCOL_ERROR` |

`NOT_HERE` and `NOT_ADMITTED` are distinguishable, and that is a deliberate
disclosure: it tells a *roster member* whether a peer it was given by the netmap
is unknown to this relay. Both parties are already admitted members of the same
tailnet, so the information does not cross a trust boundary — and without it, a
stale netmap and a stale roster are indistinguishable from a routing failure,
which is exactly the class of bug that goes undiagnosed for weeks.

A rejection during the handshake carries no reason at all (§9).

---

## 7. The client connection

### 7.1 Establishment

```
Client                                                Relay
  |                    TLS 1.3 + HTTP upgrade            |
  |<-- RelayHello   (relay_id, relay_random) ------------|
  |--- ClientAuth   (role=CLIENT, node_id, ------------->|
  |                  client_random, sig_client)          |
  |<-- RelayAuth    (sig_relay) -------------------------|
  |--- SendPacket / Ping / ... ------------------------->|
  |<-- RecvPacket / PeerGone / ... ----------------------|
```

**The relay speaks first**, for the same reason the server does in
`karst-control-v1.md` §5.1: the client signs over a value it has not yet seen,
so a captured `ClientAuth` is useless on any other connection. There is no
timestamp, no clock-skew window and no replay cache, because a stream can
afford the stronger property. PHREATIC cannot, and pays for it with §5's
timestamp.

The client MUST verify `sig_relay` **before sending any frame other than
`ClientAuth`**. KARST-CONTROL §9 is the reason this is stated as an ordering
requirement rather than left to the implementation: "the connection will fail
closed" is no comfort for a message already on the wire.

`ClientAuth` is sent before the relay is authenticated, and that is accepted
rather than overlooked. What an impostor relay learns from it is that a node
with this ID attempted to connect — metadata the real relay learns anyway, and
which reaching an impostor already implies. What it cannot do is use it: the
signature names `relay_id`, so it does not verify at the real relay (§5.5).

A relay MUST close a connection on which `ClientAuth` has not arrived within
**10 seconds** of `RelayHello`. Connection slots are the scarce resource on a
relay, and a half-open handshake consumes one for free.

### 7.2 Forwarding

On `SendPacket(dst_id, payload)` the relay:

1. Checks the source's rate budget (§7.4). Over budget → drop the frame.
2. Looks up `dst_id` in the roster. Absent, or a different tailnet → emit
   `PeerGone(dst_id, NOT_ADMITTED)`, drop.
3. Rejects `dst_id == src_id`. A node cannot relay to itself; the frame is
   dropped and the connection MAY be closed with `PROTOCOL_ERROR`.
4. Finds the destination's connection: locally, else via mesh presence (§8).
   Absent → emit `PeerGone(dst_id, NOT_HERE)`, drop.
5. Enqueues `RecvPacket(src_id, payload)` on the destination.

`src_id` MUST be the authenticated `node_id` of the connection the frame
arrived on. It is never taken from the wire — no client-supplied source field
exists in `SendPacket`, precisely so that there is nothing to spoof.

The relay MUST NOT parse, validate, transform or log `payload`. Its length and
timing are already visible to the operator (§11); its bytes are not the relay's
business and treating them as opaque is what keeps a relay compromise from
being a datapath compromise.

### 7.3 Queueing

Each destination connection has a **bounded** write queue. The relay MUST drop
frames on overflow and MUST NOT block, backpressure, or stall the reading of
the source connection.

This is a correctness requirement, not a tuning parameter. A relay that lets
one slow destination apply backpressure to a source's read loop has made every
*other* peer of that source hostage to the slowest one — a single stalled
mobile client degrading a node's entire relayed traffic. Dropping is also the
honest behaviour: the payload is a datagram from a protocol that already
tolerates loss.

Recommended default queue depth is **32 frames** per destination, and on
overflow the **oldest** frame is dropped. Dropping the head rather than the
tail keeps the queue's contents fresh, which matters because everything in it
is either a handshake retransmission or a datagram whose usefulness decays.

### 7.4 Rate limiting and accounting

A relay MUST apply a per-`node_id` token bucket over both **bytes** and
**frames**, and MUST maintain per-connection byte accounting for the operator.

Frames as well as bytes: a flood of 33-byte `SendPacket`s is cheap in
bandwidth and expensive in per-frame work, so a bytes-only limit is one an
attacker simply sizes around.

Over budget, the relay drops frames. It MUST NOT close the connection for a
burst — bursts are what a relayed handshake looks like. Sustained excess,
defined by the operator, MAY end the connection with `RATE_LIMITED`.

Recommended defaults, which are **policy rather than protocol** and which an
operator is expected to tune: 25 Mbit/s sustained per node with an 8 MB burst,
and 5000 frames/s with a 20000-frame burst. Enough for interactive use and a
relayed bulk transfer that finishes; not enough to make a volunteer's relay a
free CDN.

### 7.5 Liveness

Either side MAY send `Ping` at any time. A receiver MUST reply `Pong` with the
identical token, ahead of queued `RecvPacket` frames.

- A client SHOULD send `Ping` every **30 seconds** on an otherwise idle
  connection.
- A relay MUST close a connection from which no frame has been received for
  **90 seconds** — three missed keepalives.

`Ping`/`Pong` RTT is also the client's measurement for home-relay selection.
It is measured on the established Ponor connection rather than by a separate
probe, so what is measured is the path that will actually be used, including
TLS record processing and the relay's own scheduling delay.

### 7.6 Duplicate IDs and restarts

A second authenticated connection presenting an ID that is already connected
**replaces** the first, which is closed with `REPLACED`. The alternative —
refusing the new connection — black-holes a node whose old TCP connection is a
half-open zombie the relay has not yet timed out, which is the common case
after a laptop suspends or a mobile network hands over.

Replacement is safe because it requires the node's identity key. It is not a
denial-of-service vector available to anyone else.

For a planned restart, a relay SHOULD send `Restarting(reconnect_in_ms,
try_for_ms)` before closing, and clients SHOULD wait `reconnect_in_ms` plus
jitter before reconnecting and keep retrying for `try_for_ms`. Without the
jitter a restart produces a synchronised reconnect storm, which is the failure
mode where a relay that was merely restarting becomes a relay that is down.

### 7.7 `ReflectOffer` — the UDP reflector

A relay MAY run an AVEN reflector (`aven-v1.md` §7.6): a UDP service that tells
a node the source address it is seen from, which is the piece a pair of
NAT-bound nodes needs before either can be probed at all.

A relay that runs one MUST send `ReflectOffer` **after `RelayAuth` and before
any `RecvPacket`**, on a `role = CLIENT` connection only. The payload is a
32-byte `reflect_key` drawn from a CSPRNG per connection, and the reflector's
UDP endpoint in `aven-v1.md` §6.2's encoding.

**The key travels inside TLS, after the client has verified `sig_relay`.** That
ordering is the whole security argument: §7.1 already requires the client to
authenticate the relay before sending anything but `ClientAuth`, so a key
arriving after that point comes from the ML-DSA-65 identity the netmap pinned.
No new trust anchor, no new key exchange, and nothing an impostor relay reaches.

A relay MUST mint a distinct key per connection and MUST forget it when the
connection closes. A key that outlived its connection would be a credential with
no revocation and no expiry, held by a node the relay has stopped tracking.

The endpoint is carried rather than inferred because **the reflector is a
different socket from the Ponor listener** — a different port, and possibly a
different address behind a load balancer that terminates TCP and not UDP. A
client that assumed the Ponor address would reach the wrong host in exactly the
deployment §4.2 was written for.

A client MUST tolerate never receiving `ReflectOffer`: a relay without a
reflector is conformant, and discovery degrades to §7.2 with the pair staying on
the relay when that is not enough.

**This is a flag day, and pretending otherwise would be worse than saying so.**
§6 gives Ponor no forward-compatible extension point — an unrecognised frame
type closes the connection, deliberately, because silently ignoring unknown
frames is how a downgrade is mounted on a protocol with no other negotiation to
attack. So a relay sending `0x0d` to an older client disconnects it, and there
is no version field that could have prevented that: `RelayHello.version` is read
by the client before it could signal anything, and `ClientAuth.version` is
rejected by an older relay if a newer client bumps it. The change is made as a
flag day because there is no deployed population to break. §13.10 records that
the next such change will not have that excuse.

---

## 8. Mesh

Relays in a region MAY be meshed so that a client connected to one is reachable
through any of them. A mesh connection is an ordinary Ponor connection with
`role = MESH`, authenticated by the relays' own identity keys (§5.2) against a
configured list of mesh peers.

- On establishment each side sends `PeerPresent(node_id)` for every client
  currently connected to it, then incrementally as clients arrive.
- On a client's departure each side sends `PeerGone(node_id, DISCONNECTED)`.
- To deliver to a client held by a mesh peer, a relay sends
  `Forward(src_id, dst_id, payload)`. The receiving relay delivers it locally
  as `RecvPacket(src_id, payload)`.

**A relay MUST NOT forward a `Forward` frame onward.** One hop, enforced by
frame type rather than by a TTL, so a mesh loop is not expressible rather than
merely bounded. A `Forward` naming a `dst_id` not connected locally is dropped,
and the receiving relay SHOULD emit `PeerGone(dst_id, DISCONNECTED)` back to
its mesh peer so the stale presence entry is corrected.

Presence is **advisory**. A relay MUST tolerate a `Forward` for a client that
has just left and MUST NOT treat presence disagreement as an error; the
distributed state is eventually consistent by construction and a design that
required otherwise would fail on every client roam.

Mesh peers are not clients: a relay MUST NOT accept `SendPacket` on a `MESH`
connection, nor `Forward` on a `CLIENT` one. This is what the `role` binding in
§5.5 protects.

Mesh is **within a region**. A client reaches a peer in another region by
opening its own connection to that peer's home relay (§9.1), not by relays
forwarding across regions — cross-region relay-to-relay forwarding would make
every relay's bandwidth spendable by every other region's operator.

---

## 9. Relay selection

### 9.1 Home relay

Each node selects a **home relay** by measuring `Ping`/`Pong` RTT across the
registry's endpoints, and publishes the choice to the coordination server,
which distributes it in the netmap. A node MUST maintain a connection to its
home relay whenever it is running, so that peers have somewhere to reach it
before any direct path exists.

To reach a peer, a client uses, in order:

1. Its own relay, if the peer is present there or on its mesh.
2. An on-demand connection to the peer's published home relay.

On-demand connections SHOULD be closed after a period with no traffic; the
home connection is never closed while the node runs.

### 9.2 Selection stability

Home-relay selection MUST use hysteresis. A node SHOULD change home relay only
when an alternative is faster by a margin (recommended: 20 ms or 20%,
whichever is larger) sustained across several measurements.

RTT to a relay is noisy, the netmap must be updated on every change, and every
peer must learn the new home before it is useful. Selection that tracks the
instantaneous minimum produces flapping whose cost is paid by the whole tailnet,
not by the flapping node.

---

## 10. Error handling

Handshake rejections MUST be **uniform**: the relay closes the connection
without a `Close` frame and without distinguishing an unknown `node_id` from a
bad signature from a wrong tailnet. Distinguishing them hands an unauthenticated
caller a roster-membership oracle, which is the same reasoning as
`karst-control-v1.md` §8 and as PHREATIC's silent dropping of `peer_id_hint`
misses (`phreatic-v1.md` §4).

The distinction drawn in §6.2 between `NOT_HERE` and `NOT_ADMITTED` is not in
tension with this: those are sent to an **already-authenticated** member of the
tailnet the query is about.

### 10.1 Uniform in timing, not only in content

A relay MUST verify the signature in `ClientAuth` **even when the roster lookup
missed**, against a decoy key, and reject afterwards.

This was found while implementing §5.3 rather than while writing it, and it is
the more interesting half of the requirement. Uniform *responses* are not
enough: the natural implementation returns on a failed map lookup and pays for
a full ML-DSA-65 verification only when the lookup hits. That difference is
measurable from off the machine, and it is exactly the roster-membership oracle
the uniform response was meant to deny — available to any unauthenticated
caller, for the cost of one connection per guess.

The decoy is any syntactically valid ML-DSA-65 public key with no corresponding
private key in existence — a keypair generated at relay start and discarded is
the intended implementation. It is never transmitted and verifies nothing.

This closes the lookup asymmetry, not every asymmetry: the roster is a hash map
and a relay under load has a cache. The claim is bounded accordingly — the
oracle no longer costs an attacker a single request to read, which is the
difference between an enumeration attack and a research problem.

After the handshake, a protocol error — a bad length, an unknown type, a frame
illegal for the role — MUST end the connection. The transport is ordered and
authenticated, so a malformed frame means tampering or a bug, and there is no
recovery that does not weaken the connection.

---

## 11. What the relay operator learns

Stated here rather than in documentation because ADR-0008 §6 requires it to be
disclosed at the point of configuration, and because a security product that is
vague about this is not one.

**Visible to the relay:**

- Which node IDs are connected, and when — a presence log for the tailnet.
- Which node IDs exchange traffic with which, at what times, in what volumes,
  with what packet-size distribution and what timing.
- The source IP address and port of every connected node.

**Not visible to the relay:**

- The content of any packet. Payloads are PHREATIC ciphertext.
- The per-pair PSK, the netmap, or any control-plane secret. None of these
  traverse a relay.
- Which *user* a node belongs to, or the tailnet's ACL structure — except as
  can be inferred from the traffic graph above, which for a small tailnet is a
  weak qualifier.

**No padding is applied**, so packet sizes are exact. PLAN.md §1.3 declares
metadata privacy beyond fixed-size padding buckets a non-goal for v1, and
Ponor does not implement even the buckets. The traffic graph above is therefore
the honest description, not a worst case.

This is the whole argument for ADR-0008's co-location default: when the relay
and the coordination server are the same host run by the same operator, this
disclosure is to a party who already holds strictly more. It is also why
community-pool relays are opt-in with the cost stated at the point of
configuration, rather than a default.

---

## 12. Formal verification

`spec/models/ponor.pv`, ProVerif 2.05, seconds:

| Query | Result |
|---|---|
| The relay authenticates a client, **injectively** | ✅ |
| A client authenticates the relay, **injectively** | ✅ |
| The relay authenticates a mesh peer, **injectively** | ✅ |
| A mesh peer authenticates the relay, **injectively** | ✅ |

The attacker model is the one that makes this worth running: it **operates a
relay of its own that honest clients legitimately connect to**, with that
relay's signing key. ADR-0008 §6 supports a community relay pool, so "a relay
you use is hostile" is a configuration this product offers rather than a
contrived one.

TLS is deliberately not modelled, as in `karst-control-v1.md` §10. The
authentication established here must not depend on it.

### 12.1 What is not modelled

The frames after the handshake — and that is not an omission for tidiness. See
§13.3; it is a real property of the design that a symbolic model cannot show,
because an absent property produces no failing query.

Also absent: §10.1's timing defence (ProVerif reasons about what an attacker can
derive, not about how long a rejection takes), rate limits, presence, and
queueing.

### 12.2 `relay_id` is the load-bearing binding, and `role` is not

Draft 0.1 proposed a broken variant with `role` unbound, on the reasoning that
role confusion was the obvious attack on §5.5. Building it showed the
reasoning was wrong, and the correction is worth keeping.

**Role confusion is not reachable.** `node_id` and `relay_id` are hashes under
*different domain labels*, so the client directory and the mesh directory have
disjoint key spaces. A client's `ClientAuth` replayed with `role = MESH` names
an id the mesh directory cannot contain, and is rejected on the lookup before
the signature is examined. Binding `role` is correct and costs one byte, but it
is defence against a misconfiguration, not against an attack.

**`relay_id` is a different matter**, and `spec/models/ponor-norelayid.pv`
demonstrates it: dropping `relay_id` from the client's signing input makes
queries 1 and 3 **false**. ProVerif's trace:

1. The rogue relay opens a connection to the honest relay and reads its
   `RelayHello`, learning `relay_random`.
2. It sends its **own** `relay_id` with **that** `relay_random` to a client
   which has the rogue's key pinned. The client's §4.2 identity check passes:
   this is the relay it meant to reach.
3. The client signs `(relay_random ‖ client_random ‖ node_id ‖ role)`. Without
   `relay_id`, that is byte-identical to what the honest relay is expecting.
4. The rogue forwards the `ClientAuth` to the honest relay, which admits the
   honest node. **The rogue has impersonated its own client elsewhere.**

Queries 2 and 4 still pass, because only the client's signing input is
weakened. That asymmetry is the point: the variant isolates one field.

The lesson generalises past this protocol. **The client checks the relay's
identity in both versions** — §4.2's pinning is untouched. What the variant
removes is the *binding* of that identity into what the client signs. Checking
who you are talking to and binding it into your signature are different
properties, and only the second survives your signature being carried
somewhere else.

---

## 13. Open items — this draft is incomplete

1. **No external review.** As with the other two specs, the largest gap. A
   symbolic model says nothing about implementation behaviour.
2. **Roster freshness and revocation are unspecified.** §5.3 makes the roster
   load-bearing and then says nothing about how stale it may be, how a
   revocation propagates, or what a relay does when it cannot reach the
   coordination server. A relay that fails open on a stale roster undoes §5.3
   entirely; one that fails closed is a coordination-server outage that becomes
   a data-plane outage. This is the most consequential thing left open.
3. **The handshake's authentication does not extend to the frames after it.**
   Ponor derives no session key, so once §7.1 completes there is nothing
   protecting the frame stream but TLS. An attacker past TLS — a hostile
   terminator, or a forged certificate — can inject `SendPacket` frames
   attributed to an authenticated client, redirect them by rewriting `dst_id`,
   and drop or reorder at will.

   The damage is bounded, and the bound is what makes this an accepted cost
   rather than a defect: payloads are PHREATIC ciphertext, so an injected frame
   is discarded by the receiving *node*, not acted on. What an attacker gets is
   denial of service, misattribution against the source's rate budget, and
   metadata manipulation. No confidentiality is lost and no impersonation
   survives the connection.

   It is nonetheless a **hard dependency on TLS that Karst's other two
   protocols do not have** — KARST-CONTROL derives keys precisely so that a
   hostile TLS terminator cannot do this. §1.2 argued that no inner layer was
   needed here because the payload is already encrypted end to end; that
   argument is about *confidentiality* and it is correct, but it was silently
   applied to *integrity*, which it does not cover. Recorded here rather than
   fixed, because fixing it means a session key and a record layer, and the
   case for that should be made deliberately rather than as a footnote.

   A symbolic model cannot surface this: an absent property produces no failing
   query. It is stated in `ponor.pv`'s header for the same reason.
4. **Relay key rotation.** `relay_id` is a hash of a key with no rotation
   procedure, overlap window, or defined client behaviour on an unrecognised
   `relay_id` — the same gap as `karst-control-v1.md` §11.2.
5. **TCP head-of-line blocking is unaddressed.** All of a client's relayed
   peers share one TCP connection, so a lost segment stalls every one of them,
   and a relayed PHREATIC session runs TCP inside TCP. PLAN.md §5 schedules
   HTTP/3 + QUIC datagrams for Phase 6; until then this is a real cost, and it
   is worst for exactly the loss-prone paths that need a relay.
6. **No congestion signal to the client.** §7.3 drops silently. A client cannot
   distinguish relay-side drop from path loss, so it cannot back off usefully,
   and a `Dropped` frame would itself be a channel a hostile relay could use to
   shape a peer's behaviour. Unresolved.
7. **No downgrade protection.** The version byte is the only negotiation, and
   with one version there is nothing to downgrade to. When a second version
   exists, the byte alone will not be enough — §6's rejection of unknown frame
   types is what currently substitutes.
8. **Mesh presence has no reconciliation.** §8's incremental gossip has no
   periodic full resync, so a missed `PeerGone` leaves a stale entry until the
   mesh connection is re-established. Bounded in impact (a dropped `Forward`)
   but unbounded in duration.
9. **Multi-tailnet relays are specified but not sized.** §5.4 scopes forwarding
   per tailnet; nothing says how a relay's capacity is divided between them, so
   one tailnet can consume a shared relay's entire budget within its per-node
   limits.
10. **Ponor has no capability negotiation, and §7.7 spent the one free pass.**
    Adding `ReflectOffer` was a flag day: relay and node must be upgraded
    together, because §6 makes an unknown frame type fatal and neither version
    byte can carry the signal (the client reads `RelayHello.version` before it
    could act on one, and an older relay rejects a bumped `ClientAuth.version`).
    That was acceptable exactly once, while nothing is deployed. Before 1.0 the
    handshake needs a capability field — signed, so §13.7's downgrade gap does
    not simply reappear one layer up — or every future optional frame is another
    coordinated restart of every relay and every node at the same moment.
