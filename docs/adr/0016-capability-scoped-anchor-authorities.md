<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-0016: A capability-scoped anchor tier

- **Status:** Accepted and fully implemented — the wire format, §4 verification
  rules, both languages, the `karst-bedrock` CLI, the anchor scheduler, and
  `VerifyAnchored`'s console wiring are all in the tree (see "Implementation"
  below for the item-by-item account). GitHub issue [#61](https://github.com/karst-net/karst/issues/61) tracks this ADR.
- **Date:** 2026-08-29
- **Deciders:** TBD
- **Related:** Extends ADR-0014 (Bedrock trust hierarchy); inherits ADR-0015 (CNSA 2.0); changes `spec/bedrock-v1.md` §2, §3.4, §3.5, §4, §7, §9; closes FINDINGS 56; unblocks PLAN.md Phase 5's deferred "automated anchoring"

---

## Context

An `anchor` entry commits an audit-log head — a sequence and its hash — into the
Bedrock chain. It is the only thing that makes tail truncation of
`karst_audit_log` detectable: `audit.go` says plainly that a hash chain "does
not detect truncation of the tail — delete the last k entries and the remaining
chain still verifies perfectly", and `audit.Log.VerifyFrom` has always been able
to check against a fixed point it had no trustworthy way to obtain.

**Plan item 10.14 asked for anchors "on a schedule", and only half of it could
be built.** `PrepareAnchor` computes what should be anchored
(`bedrock/anchor.go:78`); an authority signs it offline with the same
`karst-bedrock sign` ceremony a node-sign uses; the console exports the request
and imports the response (`web/console/src/views/bedrock.tsx:41`). The cadence
is how often an administrator runs a ceremony.

It cannot be automated today because **the authority list is flat**. Spec §9
states the constraint: "Every key in the authority list may sign every authority
operation." A key that could sign `anchor` on a timer could also sign
`node-sign` — countersign a rogue node — which is the single capability Bedrock
exists to deny a server that may be compromised (§1). There is no arrangement in
which a server both anchors automatically and cannot admit rogue nodes.

### What the deferral actually costs

Anchoring that depends on a human ceremony is anchoring that stops happening,
and it degrades **silently**: the old anchor keeps verifying, nothing fails, and
the window of undetectable truncation grows without a symptom. The console
renders `entries_since_anchor` and `last_anchored_at`
(`api/nodes.go:1758`), so the number is visible to anyone who looks at the audit
screen — but nothing acts on it. `AnchorDue`, written to make the "anchor now?"
decision consistent, has no production caller. Neither does `VerifyAnchored`,
which is the function that would report a log contradicting its own anchor.
The mechanism is complete, tested, and never invoked.

### The constraint the design has to satisfy

The Bedrock log is append-only and hash-chained, replicated to every node and
verified in full on every fetch and every boot. A `genesis` entry signed last
month cannot be re-encoded. So any change to a body layout must be one that a
new verifier can apply to logs that already exist, and any change to the op set
is a flag day across the whole fleet.

---

## Decision

**A third signing tier, carried in the existing authority-list body, permitted
to sign `anchor` and nothing else.**

| Tier | Algorithm | Context string | Where the key lives | Signs |
|---|---|---|---|---|
| Root | ML-DSA-87 | `karst-bedrock-v1 root` | Offline media, `k`-of-`n` | The authority list, `genesis`, `disable` |
| Authority | ML-DSA-87 | `karst-bedrock-v1 authority` | Admin devices | `node-sign`, `node-revoke`, `quorum-change`, `anchor` |
| **Anchor** | **ML-DSA-87** | **`karst-bedrock-v1 anchor`** | **A monitoring host, or the coordination server** | **`anchor`, and nothing else** |

**The separation is cryptographic, not procedural.** An anchor key signs under
its own context string, so a signature it produces is not a valid authority
signature over the same entry hash — not because a verifier checks a permission
bit, but because ML-DSA verification under `karst-bedrock-v1 authority` fails on
it. A verifier that never heard of this ADR cannot be tricked into accepting an
anchor key's `node-sign`; it can only fail closed. That is the same reasoning
ADR-0014 used to specify per-tier domain separation before the algorithms
converged, and the same reasoning §3.3 used to make bodies opaque: remove the
opportunity to disagree rather than specify a rule and hope every implementation
applies it.

### Wire format

The anchor keys ride in the two bodies that already carry the authority list, as
an optional trailing block:

```
genesis         LP(zone) || BE32(n) || n × LP(root_pk)
                         || BE32(k)
                         || BE32(a) || a × LP(authority_pk)
                         || BE32(q)
                         [ || BE32(s) || s × LP(anchor_pk) ]

authority-list  BE32(a) || a × LP(authority_pk) || BE32(q)
                         [ || BE32(s) || s × LP(anchor_pk) ]
```

**A body that ends after `q` means `s = 0`, and `s = 0` MUST be encoded as
absence.** Emitting `BE32(0)` is a decode failure. Without that rule there are
two byte strings for one meaning, which is precisely the canonicalization hazard
§3.3 exists to remove — and it is what lets a deployment that never enables
anchor keys keep producing bodies byte-identical to today's.

**No threshold field.** §4 rule 8 already fixes the `anchor` threshold at 1, and
a configurable `s`-of-`s` would defeat the purpose: automation needs one key
able to act alone.

**Signer indices are one concatenated space.** §3.5 carries `BE32(signer_index)`
into the active list of the op's tier. For `anchor`, `signer_index < a` selects
the authority list under the authority context; `signer_index >= a` selects the
anchor list at `signer_index - a` under the anchor context. One arithmetic rule,
no wire change to §3.5, and no "try both lists and see which verifies" — that
pattern is how confused-deputy bugs are written. For every other op the active
list is the authority list of length `a`, so an index of `a` or above is out of
range and rejected by rule 6 unchanged. **A full authority may still anchor**,
which is what keeps the existing offline ceremony working and keeps a `s = 0`
deployment able to anchor at all.

### Verification rules

Amendments to §4:

- **Rule 6** — index range is against the concatenated space for `anchor`, and
  against the authority list alone for every other authority op.
- **Rule 7** — a third context string, selected by the same boundary at `a`.
- **Rule 8** — the `anchor` threshold stays 1 regardless of which list the
  signer came from.
- **New rule: an `anchor` entry's `audit_seq` MUST be strictly greater than the
  previous anchor's.** The verifier does not have this today (`verify.go:287`
  assigns `st.Anchor` unconditionally; the check lives only in `PrepareAnchor`,
  which a compromised server bypasses by not calling it). It is harmless while
  the server holds no key. **It becomes load-bearing the moment it holds one**:
  without monotonicity, a server that truncates its audit log can simply anchor
  the truncated head and every node accepts the rewind. This rule is what makes
  the rest of the decision safe and must land with it, not after it.
- **New rule: an anchor key MUST NOT also appear in the root or authority list
  of the same body.** A key in both lists gets both context strings, and copying
  an authority key into the anchor slot is the exact footgun this ADR exists to
  prevent. Rejecting it at verification turns an operational mistake into a
  failed ceremony.
- `s <= 64` and `a + s <= 64`, matching `maxSigners`; each key exactly 2 592
  bytes.

§7's recovery story is unchanged and that is the point of putting the keys in
this body: **"the roots sign a new `authority-list`" replaces the anchor keys
atomically with the authorities.** A separate list would mean authority-compromise
recovery took two ceremonies, one of which can be forgotten.

### Why this is safe to automate

An anchor key's only power is to *fix* history at a point. It cannot un-fix one:
monotonicity forbids rewinding the anchor, and the audit chain's own hash
forbids anchoring a head that does not follow from the anchored one. What a
compromised server holding an anchor key gains is the ability to anchor a
history it fabricated *after* the last anchor — and it has that already, because
a human ceremony signs what the server shows them. §1 says so directly: an
anchor "says nothing about entries that were never written". The property
Bedrock offers here was never "the server told the truth"; it is "the server
cannot rewrite what it already told us", and that property survives.

What remains is **staleness**, which is now the failure mode worth monitoring —
and it is monitorable without trusting the server, because the anchor entries'
`time` fields are in the log every node replicates.

### Implementation

All eight items below are done. Roughly in this order:

1. ✅ **Monotonicity and the disjointness check**, in both verifiers, with
   rejected vectors. Shipped first; it is correct independently of the rest.
2. ✅ `spec/bedrock-v1.md` — §2 tier table and context strings, §3.1 (`anchor`
   signed by "≥1 authority or anchor key"), §3.4 layouts, §3.5 index space, §4
   rules, §7, §9 (the "Capability-scoped authorities" bullet now describes what
   exists rather than what is missing), and the preamble's "every entry is
   signed by keys the server never holds", amended to name this tier as the one
   narrow exception.
3. ✅ **Go** — `AnchorContext`, `AnchorKey`/`VerifyAnchorKey` in `bedrock/sign.go`;
   the optional trailing block in `bedrock/log.go`'s four builders and parsers;
   `State.AnchorKeys` and the concatenated-signer-space lookup in
   `bedrock/verify.go`. (No `TierAnchor` — `Tier` stays root/authority only;
   the concatenated space is threaded through `verifySignatures` as a separate
   `anchorKeys` argument, non-nil only for `OpAnchor`, which is what keeps §4
   rule 6 unchanged for every other op without a third `Tier` value to check.)
4. ✅ **Rust** — the mirror in `crates/karst-bedrock/src/{log,verify}.rs`,
   `crates/karst-bedrock/src/codec.rs` (`Cursor::optional_keys`), and
   `karst-crypto/src/sign.rs`.
5. ✅ **`karst-bedrock`** — `init root|authority|anchor`, an anchor-key path
   through `sign` (recognized by which list it is in, via a CLI-local `KeyTier`
   — see item 3's note on why `Tier` itself did not grow a third value), anchor
   keys rendered in `inspect`'s genesis and authority-list summaries, and an
   optional third `-- ANCHOR.pub...` group on `genesis-request`.
6. ✅ **Vectors** — regenerated. New body cases for both shapes, a log case
   whose `anchor` is signed by an anchor key, and rejected cases for: `BE32(0)`
   written long-form, an anchor key duplicated in the authority list, an
   `anchor` that does not advance `audit_seq`, and an anchor-list index used to
   sign a `node-sign`.
7. ✅ **The scheduler** (`bedrock.Scheduler`, `bedrock/scheduler.go`) — calls
   `AnchorDue`, then `PrepareAnchor`, signs with the local `AnchorKey`, and
   imports directly via `Log.Import`. **Not** the pending-request/offline-response
   round trip that §8's flow and the console's ceremony use: that indirection
   exists specifically for keys the server does not hold, and threading an
   in-process key through it would gain nothing but latency. Wired up in
   `cmd/karst-control/main.go` behind `KARST_BEDROCK_ANCHOR_KEY_FILE` (reads the
   same raw-seed format `karst-bedrock init anchor` writes), with
   `KARST_BEDROCK_ANCHOR_MAX_AGE` and `KARST_BEDROCK_ANCHOR_MIN_ENTRIES` for
   `AnchorDue`'s two thresholds. Unset means exactly what it always meant: no
   automation, only the offline ceremony.
8. ✅ **`VerifyAnchored` on the audit status endpoint** — `AuditAnchor` gained
   `contradicts_anchor` (OpenAPI, Go, and the hand-maintained TS client — see a
   note on that below), and the console's audit view now renders a danger
   banner when it is true, rather than only counting entries since the anchor.

One implementation note the list above doesn't carry: `web/packages/api-client/src/generated/types.gen.ts`
was hand-edited to match what `openapi-ts` would produce, because the
environment this shipped from had no Node.js toolchain to run
`npm run generate`. Run it (or `npm run check-drift`) once Node is available
to confirm the hand edit matches byte-for-byte; if it does not, the generator
output is authoritative.

### Migration

**Upgrade every node first, confirm, then sign.** A node that cannot parse an
entry can never get past it, and under `enforcing` a node that cannot verify the
chain refuses every peer including itself. Because `s = 0` is encoded as
absence, a deployment that does not enable anchor keys is unaffected forever;
the flag day is the first `authority-list` entry that carries one.

### Alternatives rejected

**A per-key capability bitmask in the existing list, one context string.** The
obvious design, and it enforces scoping by *rule*: an anchor key's `node-sign`
signature would verify cryptographically and be rejected only because a verifier
remembered to check a mask. Two implementations today and any third one later
all have to remember. A separate context string costs one constant and makes the
mistake impossible to make.

**A separate root-signed `anchor-authority-list` op.** Adds an op, which §4 rule
5 makes a hard failure for every verifier that has not been upgraded — a
strictly wider flag day than a body change. It also splits recovery: §7's "the
roots sign a new `authority-list`" would no longer replace the anchor keys, so
recovering from authority compromise would take two ceremonies and could
silently skip one.

**A general capability mechanism — an op bitmask per key.** Every authority op
that is not `anchor` is either a policy change that must stay quorum-gated
(`node-sign`, `quorum-change`) or a denial capability a compromised server must
not have (`node-revoke`). Designing for capabilities nobody wants buys a mask to
parse and a rule to get wrong.

**Give the server a full authority key, mitigated procedurally — HSM, audit
logging, restricted access.** A key's capability is not reduced by where it is
kept. This is the option FINDINGS 56 exists to reject.

**Keep the human ceremony; fix the visibility instead.** Alarm on
`entries_since_anchor` and `last_anchored_at` crossing a threshold, and wire
`VerifyAnchored` in. Strictly cheaper, and it is the right fallback if this ADR
is not accepted — but it converts a silent failure into a noisy one without
removing it. Steps 1 and 8 above are worth doing on their own merits either way.

---

## Consequences

### Positive

- Anchoring becomes a background task, so the undetectable-truncation window
  stops being a function of administrator diligence.
- Scoping fails closed by construction. An anchor key cannot produce a signature
  valid on any other op, even against a verifier that does not implement this
  ADR.
- The monotonicity rule closes a gap the verifier has today, and would want
  regardless of whether the rest of this is taken.
- Recovery stays one ceremony: replacing the authority list replaces the anchor
  keys with it.
- A deployment that does not enable anchor keys produces byte-identical bodies
  to today, so the change is genuinely opt-in.
- `AnchorDue` and `VerifyAnchored` acquire the callers they were written for.

### Negative

- **"The coordination server holds no signing key" stops being true.** That
  sentence is in the spec's preamble, the README, and the mental model of anyone
  who has read them. What replaces it — "the server holds no key that can change
  policy" — is a weaker claim that takes a paragraph to explain, and a weaker
  claim that needs explaining is one that gets misremembered as the stronger one.
- **The first authority-list entry carrying anchor keys permanently excludes
  every node that has not upgraded.** This is the sentence a future reader most
  needs: the entry cannot be removed from the log, a node that cannot parse it
  can never verify past it, and a later entry setting `s = 0` does not help — the
  unparseable entry is still in the chain. An early rollout is not recoverable
  by another signature; it is recoverable only by upgrading every affected node.
- **A third context string and a third key kind, in two languages.** Six
  implementations of tier separation that must agree, up from four. The shared
  vectors are the mitigation and they only work if the rejected cases are written
  as carefully as the valid ones.
- **A compromised server holding an anchor key can grief the log.** Anchors are
  ~4.7 KB of signature each and every node replicates and verifies the log in
  full; monotonicity bounds spam to one anchor per audit entry, which the
  attacker also controls. This is denial of service, which §1 already concedes
  the server can do — but it is a new and cheaper way to do it.
- **Rotating an anchor key needs a root ceremony**, because the list lives in a
  root-signed body. That is the same weight as changing the authority list, on a
  key that is far more exposed than an authority key and therefore more likely to
  need rotating.

### Reconsider if

- A second capability is genuinely wanted — automated revocation driven by a
  SIEM is the plausible one — at which point choose between a fourth tier and a
  general mask with this ADR's reasoning as the input, rather than adding tiers
  by reflex.
- Hardware tokens make a `q`-of-`a` authority ceremony cheap enough to run on a
  timer, at which point automation no longer costs a weakened headline claim.
- A deployment wants anchoring automated but will not put a key on any host it
  operates continuously, in which case the fallback above — staleness alarms over
  a human ceremony — is the whole answer and this tier should not be built.
