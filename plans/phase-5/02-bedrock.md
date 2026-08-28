# Bedrock — the network lock

**PLAN.md §4.5 · W1–W8 · Crypto lead, with Rust 1 pairing from W5 and Go 1 on
the server side from W6.**

## 1. What it is for, stated precisely

> **Re-baselined 2026-08-27.** The signer, signed-log model, chain verification,
> status/mode APIs, console read views, node-side enforcement primitives, and
> the full offline ceremony now exist: a root quorum can create and combine a
> genesis log, the console imports it, and an authority can countersign an
> enrolled node through exported/imported bundles. A privileged aquifer test
> now proves that a Go control server distributes Rust-produced ceremony bytes
> to a real `karstd`, which admits the covered node and excludes an uncovered
> netmap peer while enforcing. Audit anchoring is manual until authority
> capabilities can limit an online or scheduled signer to `anchor` operations.

Karst's control server is a distributor of policy, not an enforcement point: it
cannot read traffic. But it *does* tell every node which public keys belong to
which peers, and a compromised server can therefore hand node A a key it
controls and claim it is node B. Every cryptographic property below the control
plane holds perfectly while A talks to the attacker.

Bedrock closes that. Node identity keys must be countersigned by a quorum of
authority keys whose lineage traces to offline roots, and **nodes verify the
chain themselves and refuse to peer outside it, regardless of what the netmap
says.**

What it does not do, and the docs must say so:

- It does not stop a compromised server **denying** service. It can drop a
  node from the netmap, refuse enrolment, or hand out a stale map. Bedrock
  makes lying detectable, not impossible.
- It does not protect a node whose own key is stolen. That is revocation's
  job, and revocation is a Bedrock operation with the propagation delay of the
  log.
- It does not make the audit log complete. `audit.go` already says a hash
  chain cannot detect entries that were never written; Bedrock signs the head,
  which fixes truncation and not omission.

## 2. Historical implementation inventory (superseded)

Three comments and no code.

| Location | Says |
|---|---|
| `karst/identity/identity.go:16` | circl "**will come back for Bedrock**, which needs SLH-DSA-SHA2-192s (ADR-0001) and which the standard library has no implementation of" |
| `karst/audit/audit.go:24` | "Bedrock's quorum signing is the intended home for" the external anchor that makes tail truncation detectable |
| `karst/channel/channel.go:317` | enrolment decides "whether to accept it (auth key, OIDC, **Bedrock countersignature**)" |

ADR-0001 has already made the algorithm decision and corrected it once:
**SLH-DSA-SHA2-192s** for the offline root (pk 48 B, sig 16 224 B), Category 3,
chosen because it is hash-based and so survives a lattice break that would take
ML-KEM and ML-DSA with it. `identity.go`'s `ControlContext` already exists
specifically to keep control-channel signatures from being valid Bedrock
countersignatures.

## 3. Key hierarchy

Three tiers, two algorithms. The split is deliberate: roots sign a handful of
times ever, authorities sign once per node.

| Tier | Algorithm | Where the key lives | Signs |
|---|---|---|---|
| **Root** | SLH-DSA-SHA2-192s | Offline media or hardware token, `k`-of-`n` | The authority list, and nothing else |
| **Authority** | ML-DSA-65 | Admin devices; a subset offline | Node countersignatures, revocations, quorum changes, log heads |
| **Node** | ML-DSA-65 | The node, in its keystore | Nothing in Bedrock — it is the subject, not a signer |

**Why authorities are ML-DSA and not SLH-DSA.** An authority signature is
produced every time a node enrols and travels in the log to every node. At
16 224 bytes an SLH-DSA countersignature with a quorum of three costs 48 KB per
node; a thousand-node network's log becomes 48 MB that every node replicates
and verifies. ML-DSA-65's 3 309 bytes makes the same thing 10 MB, and the
authority tier is *rotatable* — if lattices fall, the roots (which are not
lattice-based) sign a new authority list under whatever replaces ML-DSA. The
hash-based anchor is exactly where it needs to be and nowhere it is expensive.

Record this reasoning in an ADR — **ADR-0014, "Bedrock trust hierarchy"** —
because ADR-0001 specifies the root algorithm and is silent on the tier beneath
it, and the next reader will otherwise assume the omission means SLH-DSA
throughout.

## 4. Open dependency question, resolve in W1

`identity.go` says the standard library has no SLH-DSA. **Verify that against
Go 1.27 as shipped** — the module is already pinned to a 1.27 RC for
`crypto/mldsa`, and if `crypto/slhdsa` landed alongside it, the plan gets
simpler and circl stays out of the module.

| If | Then |
|---|---|
| `crypto/slhdsa` exists in Go 1.27 | Use it. Mirror `identity.go`'s FIPS-mode error handling |
| It does not | `cloudflare/circl` returns, BSD-3-Clause, already allowed by `deny.toml`'s Go equivalent — check the Go licence gate too. Wrap it as thinly as `identity.go` originally wrapped circl for ML-DSA, with the same "written to be deleted" comment |

Rust side: **`slh-dsa` from RustCrypto**, `MIT OR Apache-2.0`, consistent with
the `ml-dsa = "0.1"` already in `karstd`. Verify it exposes SHA2-192s
specifically and that its FIPS 205 test vectors pass before committing to it —
and add a cross-implementation test that the Go and Rust sides verify each
other's signatures over the same message, in the same shape as
`TestSeedIsStable`. **A signature format disagreement between the signer and
the verifier of a fail-closed path is the worst bug available in this
workstream**, and it is exactly the failure `identity.go`'s byte-compatibility
check was written to prevent for ML-DSA.

## 5. The log

Everything Bedrock does is an entry in one hash-chained, append-only log that
every node replicates and verifies in full. Not a database with a signature
column — the log *is* the state, and the server's copy is a cache of it.

### 5.1 Entry types

| Op | Signed by | Contents |
|---|---|---|
| `genesis` | `k`-of-`n` roots | Root public keys, `n`, `k`, the initial authority list, the quorum threshold `q`, the zone |
| `authority-list` | `k`-of-`n` roots | Replacement authority set and `q` |
| `node-sign` | `q` authorities | Node handle, ML-DSA-65 public key, not-before, expiry |
| `node-revoke` | `q` authorities | Node handle, reason, effective time |
| `quorum-change` | `q` authorities under the *old* threshold | New `q` |
| `anchor` | ≥1 authority | Audit-log head hash and sequence (`audit.Log.Head`) |
| `disable` | `k`-of-`n` **roots** | Turns enforcement off. Roots, not authorities — see §9 |

### 5.2 Encoding and chaining

Reuse the audit log's shape so there is one construction to review, not two:

```
entry_hash_n = SHA-512("karst-bedrock-v1" ‖ entry_hash_{n-1} ‖ BE64(seq)
                       ‖ BE64(time) ‖ op ‖ LP(canonical_body))
```

SHA-512, not the audit log's SHA-256, per ADR-0001's hash choice — the audit
log predates that convention and is a Go-internal artefact; Bedrock is on the
wire and verified by two implementations. `LP` is the same four-byte
length-prefix construction as `karst-control-v1.md` §5.5, so a reviewer who has
read that spec has read this one.

Signatures cover `entry_hash_n`, with a context string per tier —
`"karst-bedrock-v1 root"`, `"karst-bedrock-v1 authority"` — following
`identity.ControlContext`'s precedent. **A root signature must never be a valid
authority signature and vice versa**, even though the algorithms differ today,
because the algorithms will not always differ.

### 5.3 Canonical encoding is the subtle part

Two implementations must produce byte-identical bodies or every signature
fails. Protobuf is not canonical. Either define the body as an explicit
length-prefixed field sequence, exactly as §5.5 of the control spec does for
the version hash, or serialise once on the signer and treat the bytes as
opaque everywhere else.

**Take the second.** The signer emits bytes; the log stores those bytes; every
verifier hashes what it was given and parses it separately for display. A
parse-then-reserialise round trip is where canonicalisation bugs live, and this
design has no round trip in it. The cost is that the log is slightly larger and
that a malformed body is detected after signature verification rather than
before, which is the correct order anyway.

## 6. Distribution and the equivocation problem

A hash chain proves the server did not *edit* history. It does not prove the
server told everyone the *same* history — the server can maintain two valid
chains and hand a different one to each node. That is equivocation, and it is
the attack Bedrock exists to stop, so the design has to address it explicitly.

**Three layers, in increasing cost:**

1. **Head in the netmap.** `KarstNetmapResponse` carries `bedrock_head`
   (hash + seq), folded into the version hash under a `LP("karst-bedrock")`
   separator — the same pattern as the relays block and the DNS block from
   [01](01-karstdns.md) §4.2. Coordinate all three hash changes into one commit
   in W3; three separate breaking changes to the same construction is three
   times the vector regeneration.
2. **Log fetch.** A new control message pair, `KarstBedrockRequest{ since_seq }`
   → `KarstBedrockResponse{ entries[] }`, riding the existing encrypted
   envelope in `channel.go`'s dispatch. Nodes fetch from their last verified
   sequence and verify forward. A node that cannot reach a head it has been
   told about **keeps its last verified state and enforces on that** — it does
   not fail open.
3. **Peer-to-peer head comparison.** Two nodes that establish a PHREATIC
   session exchange their head hash and sequence in the first control frame
   after the handshake. Divergence at a common sequence is proof of
   equivocation: log it loudly, surface it in `karst status` and the console,
   and — this is a judgement call — **do not tear the session down.** Both
   nodes verified their peer against a valid chain; the right response is a
   screaming alarm to a human, not a self-inflicted outage on the network the
   human needs to investigate it.

Layer 3 is what makes the property real, and it is the layer most likely to be
cut for time. **Do not cut it.** Without it, Bedrock detects a server that
rewrites history and not one that keeps two of them — and a compromised server
capable of the first is capable of the second.

## 7. Node-side enforcement

In `karstd`, this is a filter between "the netmap said this peer exists" and
"a session may be established with it".

- `crates/karst-bedrock/` — new crate: log parsing, chain verification, quorum
  evaluation, the coverage query. No I/O, no async, `#![forbid(unsafe_code)]`,
  and testable against the same vectors the Go side uses.
- `bins/karstd/src/netmap.rs` — after a netmap is decrypted and projected,
  every peer's `ml_dsa_public_key` is checked against the log. Uncovered peers
  are dropped from the projection with a counted, rate-limited log line naming
  the handle.
- The node's **own** key must be covered too. If it is not, and enforcement is
  on, the daemon refuses to bring the interface up and says why. A node that
  cannot be verified by its peers should not be quietly running.
- Persist the verified log alongside the encrypted netmap cache
  (`crates/karst-control-client/src/cache.rs`). A node that boots offline must
  enforce the policy it last verified, not no policy at all.

**Three modes, and the middle one is what makes this deployable:**

| Mode | Behaviour |
|---|---|
| `off` | No verification. The default until an operator turns it on |
| `advisory` | Verify, report, do not drop. Console shows exactly which nodes would be excluded |
| `enforcing` | Drop uncovered peers |

The console must refuse to move an aquifer to `enforcing` while any node is
uncovered, unless the admin confirms a list of the nodes that will be cut off,
by name. **Turning on network lock is the single most effective way to lock
yourself out of your own network**, and every product that has shipped this
feature has learned that from a support ticket.

## 8. Signing, off the server

Authority keys must be usable from a machine that never touches the coordination
server, or the offline story is theatre.

**New binary: `bins/karst-bedrock/`.** No network, no dependencies beyond the
signing crate and the log crate.

```
karst-bedrock init          # generate a root or authority key, print the pk
karst-bedrock inspect FILE  # decode and print a request or log bundle
karst-bedrock sign FILE     # verify, prompt with a human-readable summary, sign
karst-bedrock verify FILE   # verify a chain offline
```

The flow is file-based on purpose: the console exports a signing-request bundle
(a JSON file with the pending entries and their context), the admin moves it to
the offline machine on removable media, `sign` produces a response bundle, and
the console imports it. No QR codes, no Bluetooth, no clever transport. A
bundle is small — a node-sign request is a handle, a 1 952-byte key and some
metadata.

**`sign` must print what it is about to sign in words a human can check**:
"Countersign node `laptop-alice` (handle `a3f1…`), key fingerprint `SHA-256:…`,
expires 2027-03-01" — and require a typed confirmation. An admin who signs a
bundle without reading it has reduced Bedrock to a slower version of trusting
the server, and the tool should make reading it the path of least resistance.

## 9. Recovery, and the way this feature ruins someone's month

Be explicit about the failure that has no cryptographic answer.

- **Quorum of authorities lost** (`q` of them unavailable): the roots sign a
  new authority list. Recoverable, offline, no server involvement.
- **`k` roots lost**: **the network lock cannot be disabled and no new node can
  ever be added.** There is no recovery path and there must not be one, because
  a recovery path is a bypass. The mitigation is entirely procedural: `n ≥ 3`,
  `k = 2`, keys generated on separate offline machines, at least one printed as
  a paper backup, stored in separate physical locations. **The setup wizard in
  the console must walk this and must not let an admin proceed with `n = 1`.**
- **The server is lost but the log survives on nodes**: a rebuilt server can be
  re-seeded from any node's replicated copy, and the chain proves it is the
  same history. Write this down as a documented procedure and test it; it is
  the strongest argument for the whole design and it costs a page of docs.

`disable` is signed by **roots**, not authorities, for the same reason: an
attacker who compromises `q` admin devices should be able to add rogue nodes
(bad, detectable in the log) but not silently switch the mechanism off (bad,
and detectable only if someone is watching the mode field).

## 10. Work breakdown

> **Status, 2026-08-25.** 10.1–10.12 and 10.14 are done. 10.13's API half is
> done and its views are blocked on `karst-console` not existing (see
> [04](04-admin-console.md)). Five of the six exit criteria in §12 are met and
> tested; the sixth needs a console.
>
> **Four things in this plan turned out to be wrong, and are worth reading
> before trusting the rest of it.**
>
> 1. **§7's "check every peer's `ml_dsa_public_key` against the log" would have
>    shipped a placebo.** That field does not exist on `KarstNetmapPeer`, and
>    adding it would not have helped: `phreatic-v1.md` §4 says the identity key
>    "is **not** used by PHREATIC". Sessions authenticate on the static ML-KEM
>    and X25519 keys, so covering only the identity key authorises a node to
>    exist without constraining which session keys are its. `node-sign` now
>    covers all three — spec §6.1.
> 2. **§5.2's chain-hash sketch left `op` unprefixed** while length-prefixing
>    everything else, which is the canonicalisation hazard §5.3 exists to
>    remove. Fixed, and recorded in spec §3.2.
> 3. **Nothing here mentions duplicate signer indices.** Without that rule one
>    compromised authority reaches any quorum by signing twice, reducing `q` to
>    1 for every operation in the log.
> 4. **§6's coordination window had already closed.** The netmap version hash
>    ended up taking three separate breaking changes rather than one, because
>    the DNS block landed first.
>
> Two items were narrower than written. **10.11**'s "Bedrock countersignature"
> as an enrolment credential needs a fork-surface decision the plan does not
> anticipate; what was built is the disclosure gate (spec §6.2), which is the
> half with security value. **10.14**'s "on a schedule" cannot mean automatic:
> an anchor needs an authority signature, and anything holding an authority key
> can also countersign nodes (FINDINGS 56).

| # | Item | Weeks | Depends on |
|---|---|---|---|
| 10.1 | Resolve the SLH-DSA library question, both languages; cross-verify test | W1 | — |
| 10.2 | ADR-0014, trust hierarchy | W1 | 10.1 |
| 10.3 | `spec/bedrock-v1.md` — entry types, encoding, chain, verification rules | W2 | 10.2 |
| 10.4 | `crates/karst-bedrock`: types, chain verification, quorum | W3–W4 | 10.3 |
| 10.5 | Go mirror in `karst/bedrock/`, plus storage | W3–W5 | 10.3 |
| 10.6 | Shared test vectors, `spec/vectors/bedrock-v1.json` | W4 | 10.4, 10.5 |
| 10.7 | Netmap `bedrock_head` + version hash (with [01](01-karstdns.md) §4.2) | W3 | — |
| 10.8 | `KarstBedrockRequest`/`Response`, both ends | W5 | 10.5 |
| 10.9 | `bins/karst-bedrock` offline signer | W5 | 10.4 |
| 10.10 | Node enforcement, three modes, cache persistence | W5–W6 | 10.4, 10.8 |
| 10.11 | Enrolment hook at `channel.go:317` | W6 | 10.5 |
| 10.12 | Peer-to-peer head comparison | W6–W7 | 10.10 |
| 10.13 | Console: inventory, pending requests, log viewer, mode switch, setup wizard | W7–W8 | [03](03-control-api.md), [04](04-admin-console.md) |
| — | *API half done; views blocked on `karst-console` not existing* | — | — |
| 10.14 | Audit anchor entries on a schedule | W8 | 10.5 |

## 11. Tests

- **Vectors.** A fixed genesis, a fixed authority list, a fixed node-sign, with
  known-good hashes and signatures, verified by both implementations. This is
  the artefact that keeps Go and Rust honest, and it goes in `spec/vectors/`
  next to the two that are already there.
- **Negative chain tests**, one per way to lie: reordered entries, a dropped
  entry, an entry signed by `q-1` authorities, an authority signature on a
  root-only op, a valid signature over a different entry's hash, a fork at
  sequence `n`, a replayed revocation, an expired node-sign.
- **Enforcement, in an aquifer topology.** Extend `bins/karstd/tests/aquifer.rs`
  with a row where three nodes are covered and a fourth is not: the fourth
  reaches the relay, is admitted structurally, appears in nobody's projected
  netmap, and no session is established. Then countersign it and watch it join
  without a restart.
- **Equivocation.** A test server that serves two chains; assert both nodes
  detect it on head exchange and that the console surfaces it.
- **Lockout guard.** Assert the API refuses `enforcing` with uncovered nodes
  unless the request carries the explicit list of handles to be cut off.
- **Offline round trip.** Export a request bundle, sign it with
  `karst-bedrock` in a subprocess with no network namespace at all, import it,
  and watch the node become covered.

## 12. Exit criteria

1. A node with no Bedrock coverage cannot establish a session with a covered
   node when the aquifer is `enforcing`, and the reason is legible in
   `karst status` on both ends.
2. A rogue key injected into the netmap by a modified test server is refused by
   the node, and the test asserts the refusal rather than the absence of
   traffic.
3. Two divergent chains are detected by peer head exchange and reported.
4. An admin countersigns a node from an offline machine with no network access,
   and the node joins.
5. The chain verifies identically in Go and Rust against shared vectors.
6. A rebuilt server re-seeded from a node's replicated log produces the same
   head hash, following the documented procedure.
