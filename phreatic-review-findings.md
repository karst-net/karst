<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# PHREATIC internal cryptographic review — first pass

Phase 6 workstream 3 ([`plans/phase-6/00-overview.md`](plans/phase-6/00-overview.md)
§2), started 2026-09-02 now that its two prerequisites — the capability-scoped
anchor tier (GitHub issue [#61](https://github.com/karst-net/karst/issues/61))
and the netmap-cache suite mechanism (GitHub issue
[#58](https://github.com/karst-net/karst/issues/58)) — have both landed.

**This is a self-review, not the external cryptographic review.** Per
`docs/THREAT-MODEL.md` R1 and PLAN.md §12, an external review is required
before GA and remains Phase 8 work; nothing here substitutes for it, and this
document must not be read or cited as though it does. It checks
[`spec/phreatic-v1.md`](spec/phreatic-v1.md) against `crates/karst-noise`,
`crates/karst-proto` and their call sites in `bins/karstd`, and against the
Verifpal/ProVerif models in `spec/models/`.

**Scope of this pass:** the handshake and key schedule (§6–7), the transport
phase (§8), and the denial-of-service machinery (§9) — read against their
implementations and against the open items the spec itself already tracks in
§14. Not yet covered: `karst-crypto`'s primitive implementations for
side-channel behavior, the rekey/simultaneous-open transition table (§14 item
9), and a line-by-line reread of §13.8's adversarial-reading request (§14 item
10). Those are next.

**Method:** reading, not running an attack. `cargo test -p karst-noise -p
karst-proto` passes and the existing unit-test discipline in both crates is
good — every finding below is a gap between what the spec requires and what
the daemon does, found by tracing a call path, not a failing test.

---

## High — a spec `MUST` unenforced in the running daemon

### 1. §9.1's cookie mechanism is fully implemented and never called

`spec/phreatic-v1.md` §9 opens: "This section is where PHREATIC differs most
from WireGuard and is the highest-risk part of the protocol
(`docs/THREAT-MODEL.md` R1)." §9.1 is a `MUST`:

> A responder MUST NOT allocate reassembly state for an address-unvalidated
> source while above `LOAD_THRESHOLD` outstanding handshakes. In that
> condition it MUST discard the fragment and MAY emit a `CookieReply`.

`crates/karst-proto/src/dos.rs` implements this completely: `CookieSecret`
with rotation and a one-period grace (`rotate`, `validate`, tested at
`dos.rs:355-365`), `mac2_key` keyed by the cookie, and
`crates/karst-proto/src/reassembly.rs`'s `push` already gates on
`addr_validated` correctly (`reassembly.rs:234`, tested at
`under_load_unvalidated_sources_allocate_nothing`,
`reassembly.rs:389-421`). None of it is wired up.

`bins/karstd/src/engine.rs:1125` and `:1245` — the only two call sites of
`Reassembler::push` in the daemon — both pass a literal `true`:

```rust
// engine.rs:1115
// Address validation is `true` here because Phase 2 has a static roster
// reachable only from configured endpoints. §9.1's under-load path,
// where an unvalidated source must allocate nothing, arrives with
// cookies in Phase 3.
```

That comment is stale by four phases. There is no `CookieSecret` field on
`Engine`, no construction of one, no `CookieReply` ever built or sent (`grep
-rn "CookieReply\|enc_cookie" bins/karstd/src` returns nothing outside
`karst-proto`'s own type definitions), and `mac2_key` has zero call sites
outside `dos.rs`'s tests. `karst_proto::MessageType::CookieReply` exists as a
wire value (`crates/karst-proto/src/lib.rs:192`) that no code path in the
daemon ever emits.

**Consequence.** `LOAD_THRESHOLD`'s under-load branch —
`!addr_validated && occupied >= load_threshold` at `reassembly.rs:234` — is
dead code in production: `addr_validated` is always `true`, so a spoofed-source
flood is treated exactly like genuine traffic up to `max_entries`/
`max_per_source`, and never gets the 0.06-amplification `CookieReply`
challenge §9.1 exists to provide. The reassembler's other protections
(bounded memory, per-source budget) still hold, so this is not the "unbounded
allocation" failure mode — but the specific mitigation the spec calls the
protocol's highest-risk section, and that an adversary spoofing source
addresses is specifically what defeats, is absent from the running daemon.
`docs/THREAT-MODEL.md`'s R1 row reads "Mitigated" — that should read
"Partially mitigated" until this is closed.

**Not a Phase 6 surprise in shape — the "Phase 3" comment shows it was known
and deferred, then never picked back up.** It belongs in this workstream
because closing it needs a keyed `Engine` field, a rotation timer, and a
`CookieReply` send path — protocol-adjacent work exactly like the anchor tier
and netmap-cache items that opened this phase, not a one-line fix.

---

## High — a spec `MUST` silently narrowed to "accept whatever the local epoch is"

### 2. §7.3's PSK epoch grace period is not implemented; the storage to implement it does not exist

§7.3:

> `psk_epoch` selects the per-pair PSK. Responders MUST accept epoch *n* and
> *n−1* and MUST reject any other.

`karst_noise::handshake::respond`'s `lookup` callback signature was
deliberately built to carry this: `F: FnOnce(&[u8; HINT_LEN], u32) ->
Option<PeerPublic>` (`crates/karst-noise/src/handshake.rs:619`), with the doc
comment on `respond` spelling out why —

> `lookup` resolves a `peer_id_hint` *and a PSK epoch* to that peer's netmap
> entry. […] Epoch acceptance is the caller's policy: §7.3 requires accepting
> epoch *n* and *n−1* and rejecting anything else, which this signature
> expresses by letting the resolver refuse.

Both callers discard the parameter:

```rust
// engine.rs:1329 and :1409, identically
|hint, _epoch| {
    let index = *by_hint.get(hint)?;
    let peer = peers.get(index)?;
    matched = Some(index);
    Some((*peer.public).clone())
}
```

`_epoch` is never compared against anything — any `psk_epoch` value in an
inbound `HandshakeInit`, including one that is neither *n* nor *n−1*, resolves
to the same peer. The "reject any other" half of the `MUST` is absent, not
merely weakened.

The "accept *n−1*" half is not just unimplemented — it is **unimplementable
against the current data model**. `PeerSection` (`bins/karstd/src/config.rs:
509`) holds one PSK: `pub psk: Option<String>`. `Peer.public`
(`karst_noise::PeerPublic`) likewise carries a single `psk: [u8; 32]`
(`handshake.rs:177`). There is no field anywhere in the daemon that can hold
both the current and the immediately-prior epoch's PSK at once, so even a
caller that did compare `_epoch` would have nothing but the current PSK to
offer for either answer.

**Consequence.** `engine.rs:592`'s `previous.config.psk_epoch !=
config.psk_epoch` triggers an immediate `rearm` to the new epoch's PSK the
moment *this* node's netmap push lands — with no window in which the old PSK
is still honored. Netmap propagation across a fleet is not instantaneous
(that asymmetry is exactly what `f870fab`/GitHub issue #75 was about, for a
different message). A responder that has rotated and an initiator that has
not yet received the same push will each derive the current-epoch transcript
on one side and the previous-epoch one on the other; `mix_key_and_hash` at
step 12 makes those diverge unrecoverably, and the handshake fails closed with
no diagnosable error (§11 — silent discard). §7.3's own rationale for
existing at all is worth requoting: "A downgrade-to-zero-PSK attack is the
most obvious avenue against this design" — the grace period is what lets a
fleet rotate PSKs on a schedule (`PSK_EPOCH_DURATION` = 86400 s, §10) without
that rotation itself being a recurring, self-inflicted connectivity fault.
Today, every epoch rotation is a fleet-wide race against netmap propagation
latency, and the losing side of that race gets a handshake failure that
`karst status` cannot explain, since nothing distinguishes it from any other
silent-discard cause.

Whether this has been *masked* in practice by short netmap propagation times
in the current deployment scale is untested — worth a targeted integration
test (rotate the epoch, hold one node's netmap push back by longer than a
handshake round trip, assert the pair still connects) before this is closed,
since that test would also be the first thing to catch a regression.

---

## Medium — blocks this workstream's own exit criterion — **closed 2026-09-02**

### 3. The formal models do not cover suite `0x0002` at all

**Closed.** [`spec/models/phreatic-nodh.vp`](spec/models/phreatic-nodh.vp)
models suite `0x0002`'s key schedule (steps 6, 10 and 11 absent, no `e_dh_pk`)
and verifies 6/6 under Verifpal 0.80.1, same as `phreatic.vp`. Wired into
`just verify` and CI's `formal` job alongside the existing three models.
`spec/models/README.md` and `spec/phreatic-v1.md` §13.3/§14 updated. GitHub
issue [#78](https://github.com/karst-net/karst/issues/78) closed.

**Not closed by this:** a ProVerif equivalent (`phreatic-nodh.pv`). §14's
resolution note is explicit that both tools had this gap; only the Verifpal
half is done. Left open, tracked in `spec/phreatic-v1.md` §14's item 2 note
rather than a new issue, since it's the same open item ProVerif's `phreatic.pv`
already carries.

`spec/phreatic-v1.md` §14, under item 7's resolution note:

> Item 7 is resolved by ADR-0015 item 1, which made the CNSA suite a running
> one rather than a reserved row — **the models in items 1 and 2 now have a
> second key schedule to cover**, and the no-DH variant is the one where a
> missing contribution would be hardest to notice by reading.

`grep -n "KARST_2\|0x0002\|CNSA" spec/models/phreatic.pv spec/models/phreatic.vp
spec/models/phreatic-dh-broken.pv spec/models/phreatic-kem-broken.pv` returns
nothing. All four models still encode only the three-DH, three-KEM key
schedule; none models a run with steps 6/10/11 absent. The spec is explicit
about why this particular gap is dangerous to leave to inspection alone —
it's the one "a missing contribution would be hardest to notice by reading."

This was already an open item, not a new discovery, but it is worth
restating here because it is now this workstream's own material:
`plans/phase-6/00-overview.md` §3 sequences "internal crypto review" directly
after the anchor tier and netmap-cache landed, and a review of PHREATIC that
does not model the suite roughly half of `spec/phreatic-v1.md` §7.1 describes
("under a suite with no classical half — steps 6, 10 and 11 do not exist")
is reviewing half the protocol. Recommend this precede, or run alongside,
the rest of this workstream's review passes: a second Verifpal model
(`phreatic-nodh.vp`, cloning `phreatic.vp` with the three DH actions and
`e_dh_pk` removed) is a bounded, mechanical piece of work and would close the
highest-value gap in the model suite's coverage before anyone reads
`handshake.rs`'s no-DH branches and calls that reading a review.

---

## Low / already tracked — re-confirmed, not re-opened

- **§14 item 3, test vectors for the full key schedule, is still absent.**
  `find . -iname "*vector*" -iname "*phreatic*"` finds nothing; `spec/vectors/`
  holds Bedrock, control-API and relay-roster vectors only. Blocks
  interoperability testing, not security, per the spec's own table. Left open
  here rather than re-filed.
- **§14 item 10 — §13.8's payload-MAC removal — still needs the adversarial
  reading the spec itself asks for**, and this pass did not do that reading;
  it's next.
- **§14 item 9 — the rekey/simultaneous-open transition table, including the
  tie-break §14 asks for — is still prose in the spec, not a table**, and
  `crates/karst-node/src/session.rs` still runs two coexisting sessions per
  the "costs a second AEAD attempt per inbound datagram" note rather than
  converging. Confirmed still true (`session.rs:635`, `:801`); not re-examined
  in depth this pass.
- GitHub issue [#59](https://github.com/karst-net/karst/issues/59) (transport
  type byte outside the AEAD) is an accepted, recorded constraint, re-checked
  and unchanged — Bedrock's head exchange correctly multiplexed inside the
  plaintext on the `0x00` marker rather than adding a second outer type
  (`fdb81ab`), so the constraint was respected rather than tripped.

---

## What the implementation gets right

Worth recording, since a findings list alone reads more damning than the
tree deserves:

- Every normative reordering in spec §13 (header-prefix binding before secret
  material, PSK mixed last, full-header binding including reserved bytes,
  the two-tier datagram budget) is implemented exactly as specified, checked
  line-by-line against `handshake.rs`'s `initiate`/`respond`/`finish`.
- "Authenticate before touching the replay window" (§8) is implemented and
  explicitly commented at the one place it matters
  (`transport.rs:300`), with a direct test
  (`a_forged_message_does_not_burn_a_window_slot`).
- The reassembler's three structural DoS properties (§9.1: bounded memory,
  no panic path, sans-io) all hold and are well tested, including an
  adversarial-input smoke test feeding the fuzz corpus's shape by hand.
- Continuous fuzzing (§12.3's `REQUIRED`) is real: `fragment_header`,
  `reassembly` and `handshake_respond` all run in CI (`.github/workflows/
  ci.yml:816-818`), seeded from genuine protocol messages via
  `karst-noise/examples/dump_corpus.rs` rather than starting from nothing.
- Suite dispatch is done right: both the AEAD and the hash come from the
  suite (`SymmetricState::for_suite`), the suite id is mixed before any
  secret material so a disagreement cannot silently produce
  mislabeled traffic, and `the_two_suites_derive_different_keys_from_
  identical_inputs` / `a_message_sealed_for_one_suite_does_not_open_
  under_the_other` both assert the separation directly rather than trusting
  it by construction.
- Key material zeroization (`SymmetricState`, `TransportKeys`) and redacted
  `Debug` impls are present everywhere a secret could otherwise leak into a
  log line or diagnostics bundle — checked against
  `docs/THREAT-MODEL.md` R5 and each has a test asserting the redaction.

---

## Suggested order

1. **Finding 1 (cookies, GitHub issue [#76](https://github.com/karst-net/karst/issues/76))**
   and **Finding 2 (PSK epoch, GitHub issue [#77](https://github.com/karst-net/karst/issues/77))**
   are both `MUST`-level gaps in the running daemon, not model or spec gaps —
   filed as issues and belong in this workstream's actual crypto-adjacent
   implementation work, alongside the anchor tier and netmap-cache items
   already closed this phase.
2. **Finding 3 (CNSA model coverage, GitHub issue [#78](https://github.com/karst-net/karst/issues/78))
   — closed 2026-09-02.** Landed first, ahead of further reading-based review
   passes, so the rest of this workstream's reading over the no-DH branches
   rests on a model rather than inspection alone.
3. Continue the review: `karst-crypto` primitive-level reading (constant-time
   behavior, KEM/DH/AEAD call sites), §14 item 10's adversarial reading of
   §13.8, and item 9's transition table are the next passes.
