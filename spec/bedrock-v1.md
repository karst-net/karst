# BEDROCK v1

Bedrock is Karst's network lock. Node identity keys are countersigned by a
quorum of authority keys whose lineage traces to offline roots, and **nodes
verify the chain themselves and refuse to peer outside it, regardless of what
the netmap says** (PLAN.md §4.5).

The coordination server distributes this log. It does not author it and cannot
forge it: every entry is signed by keys the server never holds.

## 1. What this does not do

Stated first, because a security mechanism that is believed to do more than it
does is worse than none.

- It does not stop a compromised server **denying** service. The server can
  drop a node from the netmap, refuse enrollment, or serve a stale log. Bedrock
  makes lying detectable, not impossible.
- It does not protect a node whose own key is stolen. That is revocation, and
  revocation propagates at the speed of the log.
- It does not make the audit log complete. An `anchor` entry fixes tail
  truncation of `karst_audit_log`; it says nothing about entries that were
  never written (`audit.go`).
- It does not rotate roots. There is no root-rotation operation in v1 — see
  §9.

## 2. Key hierarchy

| Tier | Algorithm | pk | sig | Signs |
|---|---|---|---|---|
| Root | ML-DSA-87 | 2 592 B | 4 627 B | The authority list, and nothing else |
| Authority | ML-DSA-87 | 2 592 B | 4 627 B | Node countersignatures, revocations, quorum changes, anchors |
| Node | ML-DSA-87 | 2 592 B | — | Nothing. It is the subject, not a signer |

Root keys live on offline media or hardware tokens, `k`-of-`n`. Authority keys
live on admin devices.

**The root was SLH-DSA-SHA2-192s and is not any more.** ADR-0001 chose a
hash-based root so that a break of lattice cryptography — which takes ML-KEM and
ML-DSA together — would leave the ability to re-key the network intact, and
ADR-0014 built this hierarchy on that property. CNSA 2.0 excludes SLH-DSA
outright, so ADR-0015 took ML-DSA-87 over the stateful LMS alternative and
recorded the cost: **there is no assumption-diversity hedge above the authority
tier.** A lattice break now takes the whole hierarchy, recovery path included.

The tiers are therefore separated only by their context strings and by which key
list they index into, which is why §2's rule about those strings stopped being a
formality the day the algorithms converged.

Node identity moved to ML-DSA-87 in the same transition (ADR-0015 item 5). That
changed every node handle in the project, since a handle is a hash of the
identity key — affordable exactly once, before anything shipped, and this was
that once.

Signatures are made under a per-tier context string:

```
root      "karst-bedrock-v1 root"
authority "karst-bedrock-v1 authority"
```

A root signature MUST NOT be a valid authority signature or vice versa. The
algorithms differ today, so this holds trivially; it is specified because
ADR-0014 makes the authority tier rotatable and the algorithms will not always
differ.

Signing is **deterministic** in both tiers, departing from the hedged signing
`identity.go` uses on the control channel. A Bedrock key signs rarely, during a
deliberate ceremony, on a machine with no network interface — so a fault
attack requires physical possession, at which point the key itself is
available. Determinism buys reproducibility instead: a second admin can re-run
a ceremony and compare bytes.

## 3. The log

Everything Bedrock does is an entry in one hash-chained, append-only log that
every node replicates and verifies in full. The log *is* the state; the
server's copy is a cache of it.

### 3.1 Entry types

| Op | Signed by | Body |
|---|---|---|
| `genesis` | `k`-of-`n` roots | Zone, root keys, `n`, `k`, initial authority list, `q` |
| `authority-list` | `k`-of-`n` roots | Replacement authority set and `q` |
| `node-sign` | `q` authorities | Handle, ML-DSA-87 identity key, ML-KEM-768 static key, X25519 static key, not-before, expiry |
| `node-revoke` | `q` authorities | Handle, reason, effective time |
| `quorum-change` | `q` authorities under the **old** threshold | New `q` |
| `anchor` | ≥1 authority | Audit-log head hash and sequence |
| `disable` | `k`-of-`n` **roots** | Reason |

`disable` is root-signed, not authority-signed, on purpose: an attacker holding
`q` admin devices should be able to add rogue nodes — bad, and permanently
visible in the log — but not silently switch the mechanism off, which is bad
and visible only to someone watching a mode field.

### 3.2 Chaining

Let `LP(x)` be a four-byte big-endian length of `x` followed by `x`, the same
construction as `karst-control-v1.md` §5.5. Let `BE64` and `BE32` be unsigned
big-endian integers.

```
entry_hash_n = SHA-512("karst-bedrock-v1"
                       || LP(entry_hash_{n-1})
                       || LP(BE64(seq))
                       || LP(BE64(time))
                       || LP(op)
                       || LP(body))
```

`entry_hash_0` is the empty string. `time` is Unix **seconds**, not nanoseconds:
these are human-scale policy times and an admin reasons about them in seconds.

SHA-512, not the audit log's SHA-256, per ADR-0001's hash choice. The audit log
predates that convention and is a Go-internal artifact; Bedrock is on the wire
and verified by two implementations.

**Every field is length-prefixed, including `op`.** PLAN.md's sketch of this
construction left `op` bare. That would have been a canonicalization hazard of
exactly the kind §3.3 exists to avoid — a bare variable-length field followed
by a length prefix admits ambiguity — so the prefix was added. The shape now
matches `audit.go`'s `chainHash` exactly: a bare constant label, then every
field length-prefixed.

### 3.3 Bodies are opaque

Two implementations must produce byte-identical bodies or every signature
fails. The design removes the opportunity to disagree rather than specifying a
canonical form and hoping:

**The signer emits body bytes; the log stores those bytes; every verifier
hashes what it was given and parses it separately for display.** There is no
parse-then-reserialize round trip anywhere in the verification path, because
that round trip is where canonicalization bugs live.

The cost is that a malformed body is detected *after* signature verification
rather than before, which is the correct order anyway: an unauthenticated body
should never have been parsed.

Bodies are nonetheless written in one documented layout, so that an offline
signer in either language produces the same bytes for the same intent.

### 3.4 Body layouts

```
genesis         LP(zone) || BE32(n) || n × LP(root_pk)
                         || BE32(k)
                         || BE32(a) || a × LP(authority_pk)
                         || BE32(q)

authority-list  BE32(a) || a × LP(authority_pk) || BE32(q)

node-sign       LP(handle) || LP(ml_dsa_public_key)
                           || LP(kem_public_key) || LP(dh_public_key)
                           || BE64(not_before) || BE64(expiry)

node-revoke     LP(handle) || LP(reason) || BE64(effective)

quorum-change   BE32(q)

anchor          LP(audit_head_hash) || BE64(audit_seq)

disable         LP(reason)
```

`expiry` of zero means no expiry. `not_before` of zero means immediately
effective.

### 3.5 Signatures

Signatures cover `entry_hash_n` and are **not** themselves hashed into it.
Each is carried with the index of the key that produced it, into the active
root list (root ops) or the active authority list (authority ops):

```
BE32(sig_count) || sig_count × ( BE32(signer_index) || LP(signature) )
```

An index rather than a public key, because the log already defines the list and
a 4-byte index costs 2 588 bytes less than repeating an ML-DSA-87 key. For
`genesis` the indices refer to the root list carried in `genesis`'s own body.

**Duplicate signer indices MUST be rejected.** Without that rule a single
compromised authority reaches any quorum by repeating its own signature, which
would reduce `q` to 1 for every operation in the log.

### 3.6 Entry and log encoding

One encoding serves storage, the offline signer's bundles, the node's cache and
the wire:

```
entry = LP(BE64(seq)) || LP(BE64(time)) || LP(op) || LP(body)
              || BE32(sig_count) || sig_count × ( BE32(signer_index) || LP(sig) )

log   = BE32(entry_count) || entry_count × LP(entry)
```

**Hashes are not carried.** Neither `entry_hash` nor `prev_hash` appears in the
encoding; both are recomputed during verification. Carrying them would create a
second source of truth and the question of which one to believe, and the answer
would always be "the computed one" — so the carried one is only a way to be
wrong.

On the control plane an entry travels as an opaque `bytes` field
(`KarstBedrockResponse.entries`), never as a modeled protobuf message.
Protobuf is not canonical, and every signature is over a hash of exactly these
bytes; modeling an entry as a message would require two implementations to
agree on a protobuf serializer's internal field ordering, which neither can
promise. Putting the entry inside a `bytes` field removes the question.

## 4. Verification

A verifier walks the log from `genesis` forward, carrying state: the root list
with `n` and `k`, the current authority list with `q`, the covered-node set, and
whether enforcement has been disabled.

For every entry, in this order:

1. `seq` equals the expected sequence. The log starts at 1 and is contiguous; a
   gap means an entry was removed.
2. `prev_hash` equals the previous entry's hash — empty for `genesis`.
3. `time` is greater than or equal to the previous entry's time.
4. The recomputed `entry_hash` matches the one carried.
5. `op` is one of the seven in §3.1. An unknown op is a hard failure, not a
   skip: a verifier that ignores what it does not understand can be fed a log
   whose meaning it does not share with its peers.
6. Signer indices are in range for the active list of the op's tier, and
   contain no duplicates.
7. Every signature verifies over `entry_hash` under the tier's context string.
8. The signature count meets the threshold for the op: `k` for root ops, `q` for
   authority ops, 1 for `anchor`. For `quorum-change`, the **old** `q`.
9. Only then is the body parsed and applied to the state.

The first entry MUST be `genesis` and `genesis` MUST NOT appear again.

A node that cannot reach a head it has been told about keeps its last verified
state and enforces on that. **It does not fail open.**

## 5. Distribution and equivocation

A hash chain proves the server did not *edit* history. It does not prove the
server told everyone the *same* history — a server can maintain two valid
chains and hand a different one to each node. That is equivocation, and it is
the attack Bedrock exists to stop.

Three layers, in increasing cost:

1. **Head in the netmap.** `KarstNetmapResponse` carries `bedrock_head` (hash
   and sequence), folded into the netmap version hash under a
   `LP("karst-bedrock")` separator — the same pattern as the relays and DNS
   blocks in `karst-control-v1.md` §5.5.
2. **Log fetch.** `KarstBedrockRequest{ since_seq }` →
   `KarstBedrockResponse{ entries[] }`, riding the existing encrypted control
   envelope. Nodes fetch from their last verified sequence and verify forward.
3. **Peer-to-peer head comparison.** Two nodes establishing a PHREATIC session
   exchange head hash and sequence in the first control frame after the
   handshake. Divergence at a common sequence is proof of equivocation.

   It must ride the PHREATIC session and nothing else. The coordination server
   knows each pair's PSK (PLAN.md §2.6) but not the ephemeral ML-KEM and X25519
   secrets, so a PHREATIC session is the only channel between two nodes that is
   confidential from the party being audited. A comparison over the netmap, the
   relay, or AVEN would be one the server could forge into agreement.

   The claim is a **Karst inner control frame**, carried in the plaintext of an
   ordinary transport message:

   ```
   0x00 || 0x01 || BE64(seq) || BE32(len) || hash
   ```

   `0x00` is the control marker and `0x01` selects the head claim. The marker is
   zero because zero is not a legal IP version, so a control frame can never be
   confused with a tunnelled packet and vice versa.

   **It is inside the AEAD, and that is not a stylistic choice.** PHREATIC's
   outer message-type byte (`phreatic-v1.md` §8) is written before the
   ciphertext with an empty AAD, so it is unauthenticated. Discriminating on a
   new outer type would let anyone who can flip one bit in flight redirect a
   tunnelled packet into the control handler, or a control frame into the host.
   The length prefix is needed for the same layer's reason: §8 pads the
   plaintext and carries no length of its own.

   Comparison happens at the **lower** of the two sequences, the only point
   both nodes have an opinion about. Comparing heads directly would report
   divergence whenever one node had polled more recently than the other, and an
   alarm that fires constantly is one nobody reads. A peer that is further along
   is not evidence of anything.

On detecting divergence a node logs loudly, surfaces it in `karst status` and
the console, and **does not tear the session down**. Both nodes verified their
peer against a valid chain; the correct response is an alarm to a human, not a
self-inflicted outage on the network that human needs in order to investigate.

Layer 3 is what makes the property real. Without it Bedrock detects a server
that rewrites history but not one that keeps two of them — and a server capable
of the first is capable of the second.

## 6. Enforcement

Three modes:

| Mode | Behavior |
|---|---|
| `off` | No verification. The default until an operator turns it on |
| `advisory` | Verify, report, do not drop |
| `enforcing` | Drop uncovered peers |

A node is **covered** at time `t` when the log contains a `node-sign` for its
handle binding **all three** of the keys the netmap presents for it — the
ML-DSA-87 identity key, the ML-KEM-768 static key `S_pk`, and the X25519 static
key `D_pk` — with `not_before <= t` and (`expiry == 0` or `t < expiry`), and no
later `node-revoke` for that handle with `effective <= t`.

Coverage binds the handle **and the keys together**. A `node-sign` for a handle
does not cover different keys later presented under that handle, which is what
makes a compromised server unable to substitute keys it controls.

### 6.1 Why the datapath keys are covered and not just the identity key

This is the part that decides whether Bedrock does anything at all, so it is
stated at length.

A Karst node has three keypairs (ADR-0005). The ML-DSA-87 **identity** key
authenticates the control channel and is what the node handle is derived from.
The ML-KEM-768 and X25519 **static** keys are what a PHREATIC session actually
authenticates against — and `phreatic-v1.md` §4 is explicit that the identity
key "is **not used by PHREATIC**".

So a `node-sign` covering only the identity key would authorize *that a node may
exist* while saying nothing about *which session keys are its*. The netmap would
still be the only source of `S_pk` and `D_pk`, backed by nothing but the
server's word — and a compromised server could hand node A an entry for handle
B carrying keys the attacker controls. A's handshake would succeed, against the
attacker, with the network lock switched on and reporting healthy.

That is precisely the attack §1 says Bedrock exists to stop, so the
countersignature covers the keys the handshake uses. The identity key stays in
the body for two reasons: it is what the control channel authenticates, and it
makes the handle self-certifying — a verifier checks
`handle == BASE64(SHA-256("karst-node-handle-v1" ‖ ml_dsa_public_key))` rather
than trusting an opaque label the log asserts.

**Consequence: rotating a node's datapath keys requires a new `node-sign`.**
Static keys are long-lived by design, so this is rare, but it is a real
operational cost and it is the reason a deployment cannot rotate `S_pk` without
an authority quorum.

Under `enforcing`, uncovered peers are dropped from the netmap projection
before any session may be established with them. A node's own key must be
covered too; if it is not, the daemon refuses to bring the interface up and
says why.

The control API MUST refuse to move an aquifer to `enforcing` while any node is
uncovered, unless the request carries the explicit list of handles that will be
cut off. **Turning on network lock is the single most effective way to lock
yourself out of your own network.**

### 6.2 The server declines to disclose a netmap to an uncovered node

Under `enforcing`, the coordination server SHOULD refuse a netmap to a node the
log does not cover.

This is **not** where the security property lives — the node-side filter is,
and it must keep working against a server that ignores this entirely. What it
addresses is *disclosure*: a netmap carries every peer's handle, static keys,
addresses and endpoints, plus a per-pair PSK for each. Serving one to an
uncovered node hands the shape of the whole network, and those PSKs, to whoever
presented a setup key — even though every peer would refuse that node.

Only under `enforcing`. Under `advisory` the point is that an operator sees
what enforcement *would* do before anyone is cut off, and a server that refused
netmaps in advisory mode would do the thing advisory exists to avoid.

A refused node is not stuck: it keeps polling, and the next poll after an
authority countersigns it succeeds. That is the ordinary enroll-then-countersign
order and it costs a poll interval, not a re-enrollment.

**A countersignature is not yet an enrollment credential.** `channel.go`'s
enrollment comment lists "auth key, OIDC, Bedrock countersignature" as the three
ways to admit a node, and the third is not implemented. It would be *stronger*
than the other two — a setup key authorizes whoever holds it, while a
countersignature authorizes one specific key that the node proves possession of
during the handshake — but it needs the account to be resolvable before the
node is known, and the forked account manager exposes only `LoginPeer`, which
requires a setup key or a user. Widening that interface is a fork-coupling
decision (see `PeerLoginer`'s comment on why it is narrow) and is deliberately
not taken here.

## 7. Recovery

- **Quorum of authorities lost.** The roots sign a new `authority-list`.
  Recoverable, offline, no server involvement.
- **`k` roots lost.** The network lock cannot be disabled and no new node can
  be added. **There is no recovery path and there must not be one, because a
  recovery path is a bypass.** The mitigation is procedural: `n >= 3`, `k = 2`,
  keys generated on separate offline machines, at least one paper backup,
  stored in separate physical locations.
- **Server lost, log surviving on nodes.** A rebuilt server can be re-seeded
  from any node's replicated copy, and the chain proves it is the same history.

## 8. Interoperability

Both implementations are checked against `spec/vectors/bedrock-v1.json`, which
pins entry hashes and exact signature bytes. Pinning signature bytes rather
than merely asserting mutual verification is possible because §2 makes signing
deterministic, and it is worth doing: a vector that only says "both verify"
passes even when one side signs the wrong message under the right key.

## 9. Deliberately not in v1

- **Root rotation.** There is no operation that replaces the root list. Adding
  one would be safe in itself — it would require `k` roots to authorize — but
  §7's "no recovery path" property is easier to reason about when the root set
  is fixed at `genesis`, and no deployment has yet needed it. Revisit when one
  does.
- **Threshold signatures.** `k`-of-`n` is `k` separate signatures, not a
  threshold scheme. Simpler to verify, simpler to audit, and larger.
- **Automatic anchoring policy.** `anchor` entries exist; when to write one is
  an operator decision, not a protocol rule.
- **Capability-scoped authorities.** Every key in the authority list may sign
  every authority operation. That is why anchoring cannot be automated: an
  authority key that could sign `anchor` on a timer could also countersign
  nodes, so nothing a compromised server holds may be one. An authority
  restricted to `anchor` would fix that and is a change to the `authority-list`
  body — see FINDINGS 56.
