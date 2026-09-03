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
phase (§8), the denial-of-service machinery (§9) — read against their
implementations and against the open items the spec itself already tracks in
§14 — and, in later reading passes, `karst-crypto`'s primitive-level wrapping
of `ml-kem`, `ml-dsa`, `x25519-dalek` and `aes-gcm` (Finding 4), a line-by-line
reread of §13.8's adversarial-reading request (§14 item 10, Finding 6),
constant-time behavior and branching at the KEM/DH/AEAD call sites (Finding
7), and the rekey/simultaneous-open transition table §14 item 9 asked for
(Finding 8). This pass is complete.

**Method:** reading, not running an attack. `cargo test -p karst-noise -p
karst-proto` passes and the existing unit-test discipline in both crates is
good — every finding below is a gap between what the spec requires and what
the daemon does, found by tracing a call path, not a failing test.

---

## High — a spec `MUST` unenforced in the running daemon — **closed 2026-09-02**

### 1. §9.1's cookie mechanism is fully implemented and never called

**Closed.** Wired end to end: `Engine` holds a `CookieSecret` (seeded and
rotated from `poll`, §9.3's 120 s period), `Engine::inbound`'s mac check now
tries `mac2` (keyed by a self-computed cookie, checking both the current and
previous secret for the rotation grace) whenever `mac1` fails, and the
`Reassembler::push` result's `Reject::CookieRequired` branch builds and sends
a real `CookieReply` via `Engine::issue_cookie_reply`. The initiator side —
`Session::handle_cookie_reply`, dispatched from `Engine::inbound` rather than
the ordinary per-session path because its `frag_mac` is keyed differently
(§13.10, a spec gap this closure also filled) — decrypts the cookie and
retries the outstanding `HandshakeInit` once, immediately, under `mac2`.

`docs/THREAT-MODEL.md` R1's "Mitigated" now holds without qualification.
Covered by `crates/karst-proto`'s unit tests (the AEAD construction),
`crates/karst-node/tests/cookie_reply.rs` (the initiator's five outcomes),
and `bins/karstd/tests/cookie.rs` (two real `Engine`s end to end: a flood to
`load_threshold`, a genuine peer challenged and then let through on its
mac2-signed retry, and the amplification bound checked against a live
reply). GitHub issue [#76](https://github.com/karst-net/karst/issues/76)
closed.

**What §76's original text below still describes accurately: why this was
missing and what it cost while it was.**

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

## High — a spec `MUST` silently narrowed to "accept whatever the local epoch is" — **closed 2026-09-02**

### 2. §7.3's PSK epoch grace period is not implemented; the storage to implement it does not exist

**Closed — and the title's second clause turned out to be wrong.** Re-tracing
the data from the wire inward (rather than from `engine.rs` outward, which is
how this was originally found) turned up that the control-plane proto already
has a `psk_previous` field, the Go server already computes and sends it
(`server/management/internals/karst/control/netmap.go:356-362`, citing §7.3
by name), and `bins/karstd/src/netmap.rs`'s `Peer` already parses and carries
both PSKs end to end. **The storage existed one layer below where this
finding looked.** What was actually missing was narrower: `config.rs`'s two
`PeerPublic` constructors dropped `psk_previous` at the netmap→roster
boundary, and `engine.rs`'s `lookup` closures discarded `_epoch` on top of
that.

Fixed by threading `psk_previous: Option<[u8; 32]>` through
`config.rs::Peer` (from both the netmap path and a new optional TOML field,
for the static-roster case) and giving `engine.rs`'s two `lookup` closures a
shared `peer_public_at_epoch` helper: exact match uses the peer's current
`PeerPublic` unchanged, `current_epoch - 1` (checked, not wrapping) builds a
clone with `psk_previous` substituted in, anything else returns `None` — the
`MUST reject any other` this finding found absent. `Session::rearm` and
`Session::respond_to` needed no changes: `rearm` only affects a session's own
*outbound* handshakes, which always dial at the current epoch, and
`respond_to` turned out to be exercised only by the test harness, never by
the real daemon's dispatch path.

New coverage in `bins/karstd/tests/datapath.rs`: the existing
`a_psk_epoch_rotation_does_not_interrupt_a_live_session` only ever covered an
*already-established* session surviving a rearm. Added
`a_fresh_handshake_survives_the_responder_being_one_epoch_ahead` (the actual
scenario this issue was filed over — two real `Engine`s, genuinely
disagreeing `psk_epoch`s, a fresh handshake that must still complete) and
`a_handshake_two_epochs_behind_is_still_rejected` (confirming the `MUST
reject any other` half, not just the acceptance half).

**What #77's original text below still describes accurately: the symptom, and
why it mattered.**

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

**The ProVerif half is closed too, as of the same day.**
[`spec/models/phreatic-nodh.pv`](spec/models/phreatic-nodh.pv) mirrors
`phreatic-nodh.vp`'s no-DH key schedule and verifies **4/4** under ProVerif
2.05 (installed locally via `opam`, matching CI's toolchain exactly, and
cross-checked against `phreatic.pv`'s documented 4/4 result on the same
binary before trusting the new model's) — in 0.03 s, faster than the base
model, since dropping three of the seven chaining-key mixes shortens rather
than lengthens the nesting `phreatic-kem-broken.pv` diverges on. Wired into
`just verify` and CI's `formal` job. `spec/models/README.md` and
`spec/phreatic-v1.md` §13.3/§14 updated again to record both halves closed.

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

## High — secret material never zeroized on drop — **closed 2026-09-02**

### 4. `ml-kem`, `ml-dsa`, `x25519-dalek` and `aes` each gate their own zeroization behind a Cargo feature nothing turned on

Found in the second reading pass this document's scope note above added:
`karst-crypto`'s primitive-level wrapping of its four upstream crates.

**Every long-term and ephemeral secret key `karst-crypto` and `karst-noise`
hold was being freed unzeroized**, for as long as this crate has existed —
not because the code never tried (the opposite: `SymmetricState`,
`TransportKeys`, `Psk`, `CookieSecret` and more all hand-roll careful
`Drop`+`zeroize` impls elsewhere in this codebase), but because the four
RustCrypto crates these two crates wrap each gate their *own* internal
`Drop`-based zeroization behind an opt-in Cargo feature named `zeroize`, and
none of those four features was ever turned on. Depending on the `zeroize`
*crate* — which this codebase does, extensively — is a different thing from
enabling *another* crate's own `zeroize` Cargo *feature*, and the former does
not cascade into the latter.

Verified precisely via `Cargo.lock`: the `zeroize` package is a dependency of
`aws-lc-rs`, `chacha20poly1305`, `karst-control-client`, `karst-crypto`,
`karst-disco`, `karst-noise`, `karstd`, `rustls` and a few others — never of
`ml-kem`, `ml-dsa`, `x25519-dalek`, or `aes`.

**Scope, confirmed by reading each upstream crate's source directly:**

| Crate | Type | What it protects |
|---|---|---|
| `ml-kem` | `DecapsulationKey768`/`1024` | Every static *and* ephemeral ML-KEM secret key (`KemSecretKey`), both suites |
| `ml-dsa` | `ExpandedSigningKey` | Bedrock's `RootKey`/`AuthorityKey`/`AnchorKey` — the seed was already `Zeroizing`-wrapped; the larger expanded key actually used for every `sign()` was not |
| `x25519-dalek` | `StaticSecret` | Every static and ephemeral X25519 secret (`karst_noise::handshake::StaticKeys`/`Initiator`) |
| `aes` | round-key schedule inside `Aes256Gcm` | Every live `TransportSession`'s actual send/receive traffic keys |

A real gap against `docs/THREAT-MODEL.md` R5 (secret-material leakage),
though a different vector from the log/diagnostics-bundle leakage R5's
existing continuous scan covers — this is heap memory retained after a key
is no longer needed, recoverable via a core dump, a swap file, or an adjacent
memory-disclosure bug.

**Fixed — `Cargo.toml` only, no change to the cryptography itself:**
`ml-kem`/`ml-dsa` gained `features = ["zeroize"]` in
`crates/karst-crypto/Cargo.toml`; `x25519-dalek` gained it in
`crates/karst-noise/Cargo.toml`. `aes-gcm` exposes no feature reaching past
itself into `aes`'s own gate, so `karst-crypto/Cargo.toml` also gained a
direct, otherwise-unused dependency on `aes` with `features = ["zeroize"]` —
Cargo unifies features per resolved package rather than per dependent, so
this flips the bit for the *same* `aes` instance `aes-gcm` links against.

**Compile-time regression guards**, since every crate touched here
`#![forbid(unsafe_code)]` and so cannot do the raw-memory-inspection test the
upstream crates themselves use: `kem.rs`, `sign.rs` and `aead.rs` each gained
a `const _: () = { const fn assert_zeroizes_on_drop<T:
zeroize::ZeroizeOnDrop>() {} … };`, and `handshake.rs` a `needs_drop`-based
equivalent for `x25519-dalek` specifically — its `zeroize(drop)` attribute
predates the crate's `ZeroizeOnDrop` marker trait and does not implement it.
If any of these four features is ever removed, or a future dependency bump
drops the upstream impl, the build fails at the assertion rather than the
regression shipping silently.

GitHub issue [#79](https://github.com/karst-net/karst/issues/79) closed.
`cargo build`/`clippy -D warnings`/`fmt`/`test` all clean; 1184 tests pass.

---

## High — `reassembly_id` is a predictable counter, not the CSPRNG draw §5 requires — **closed 2026-09-02**

### 5. `Session` seeds `reassembly_id` at 0 and increments by 1 — every peer pair's first fragmented message carries the same value

**Closed.** `Session::emit` (`crates/karst-node/src/session.rs`) now takes a
caller-supplied `seed: [u8; 32]` and derives `reassembly_id` from it via
`derive_reassembly_id` — `HASH("Karst reassembly-id v1" ‖ seed)`, truncated
to 4 bytes — instead of `wrapping_add(1)`. Every call site that used to leave
`emit` to invent its own increment now threads a fresh seed through: the
initiator paths (`start_handshake`, both retry branches in `poll`, the rekey
path) already had one; `adopt_responder`, `repeat_response` and
`handle_cookie_reply` gained a `seed` parameter, sourced at the two daemon
call sites (`bins/karstd/engine.rs`'s `accept_handshake` and
`accept_relayed_handshake`) from a new `Engine::seed_from(rand)` helper that
hashes the already-fresh-per-datagram `ResponderRandomness` under its own
domain-separation label — the same pattern `cookie_reply_nonce` already used
for the same `rand`, just a different label so the two derivations stay
independent. `Session::respond_to` (the test harness's entry point) does the
same locally via `seed_from_responder_randomness`.

**`TransportData`'s `reassembly_id` in `Session::send` was deliberately left
as a counter, not converted.** Traced and confirmed: `fragment()`
(`crates/karst-proto/src/lib.rs:308-323`) only ever emits `TransportData` as
a single, unfragmented datagram (`count == 1`) — it returns `None` rather
than splitting one that would need more than that — so it never reaches
`Reassembler::push`'s multi-fragment, `(source, reassembly_id)`-keyed
matching at all; `push` returns via `complete_unfragmented` before reading
`reassembly_id` (`reassembly.rs:211-213`). §5's CSPRNG requirement exists to
prevent exactly the collision this finding describes, and there is nothing
for a predictable value to collide with on that path — converting it would
have cost a hash per packet on the hot data-path send call for no property,
the same reasoning §13.8 already applied to the fragment MAC's payload
coverage on the same path. Documented in place
(`session.rs`'s `send`) so a future reader does not mistake the omission for
one this pass missed.

New coverage: `crates/karst-node/tests/reassembly_id.rs` — two freshly
dialled sessions given different seeds do not pick the same first id (and
neither picks the old fixed value, `1`), and a handshake retry's id is not
the previous one plus one. `cookie_reply.rs`'s five tests updated for
`handle_cookie_reply`'s new parameter. GitHub issue
[#80](https://github.com/karst-net/karst/issues/80) closed.

**What #80's original text below still describes accurately: why this was
missing and what it cost while it was.**

Found while tracing exactly how exploitable Finding 6's mac2 regression is in
practice — the answer turned out to depend on this, and this bug is worse on
its own than the thing it was found while checking.

§5 is explicit:

> `reassembly_id` — sender-chosen, **MUST be drawn from a CSPRNG**.

`Session::new` sets `reassembly_id: 0` (`crates/karst-node/src/session.rs:324`).
Every path that fragments an outbound message — `emit()` (`:334-336`),
the retry path in `poll()` (`:700`), and the mac2 retry
`handle_cookie_reply` sends after a `CookieReply` (`:962`) — advances it with
`self.reassembly_id.wrapping_add(1)` and nothing else. No call site draws from
`seed`, the CSPRNG closure that is in fact already threaded through
`Engine::connect_all`/`Engine::poll` for exactly this kind of need
(`bins/karstd/engine.rs:837`, `:858`, already used to seed `CookieSecret`
rotation). `reassembly_id` never uses it.

**Consequence: this is not merely guessable, it is often identical across the
whole fleet.** Every `Session` is a fresh counter starting at 0, so the first
fragmented message any node ever sends to any peer — the first
`HandshakeInit` of a first connection attempt — carries `reassembly_id = 1`.
Every retry after that is 2, 3, 4… — still a five-term arithmetic sequence
from a known start, not a 32-bit random draw.

**Why that defeats a documented design property rather than a theoretical
one.** §9.1 gives the reason entries are keyed by `(source, reassembly_id)`
rather than `reassembly_id` alone: "two peers may independently choose the
same identifier, and merging their fragments would corrupt both messages."
That sentence assumes accidental collision between two unrelated peers is the
risk CSPRNG draws make negligible. With a sequential counter starting at a
fixed value, collision is not a tail risk to hedge against — it is the modal
outcome, and it's now attacker-controllable rather than accidental: §9.2
already documents, of `mac1`, "Anyone who knows the responder's static key
can compute valid `mac1` values. It is … not an authenticator, and it
provides **no reassembly integrity**." Combine the two facts and an attacker
needs **no observation of any traffic at all** to inject forged fragments
into the exact `(source, reassembly_id)` slot a targeted pair's next
handshake attempt will use: the responder's public static key is public by
design, and the `reassembly_id` that attempt will carry is predictable from
knowing only that it's someone's Nth attempt at that pair. Spoofing the
initiator's source address (off-path UDP spoofing, or an on-path position)
is the only capability this adds to what `mac1`'s own documentation already
concedes an attacker has. The attack costs the responder one wasted
reassembly slot and, if the forged fragment lands before the genuine one,
poisons that specific attempt's completion (discarded at the AEAD stage,
§11) — a reliable, spoofing-only denial of a specific pair's handshake, not
a compromise, but exactly the kind of gap a CSPRNG draw exists to close and
presently does not.

This also means Finding 6's mac2-stage regression is not the cheapest way to
land a forged fragment in the common case — the mac1 path via this bug is
free of any observation requirement at all, whereas replaying a captured
mac2 header needs the attacker to have seen one first. Finding 6 remains
worth its own writeup because it is a distinct, `§13.8`-specific capability
shift; this finding is the more directly actionable bug.

**Fixed as described above** — `reassembly_id` is now drawn via
`derive_reassembly_id` from a fresh per-call seed everywhere `emit()` is
reached, including `handle_cookie_reply`, threaded from `Engine::inbound`'s
dispatch (`bins/karstd/engine.rs:1247`) the same way `Engine::poll` already
threads one into `Session::poll`. The property test this called for —
asserting that repeated `emit()`-triggering calls do not produce a short
deterministic sequence — is `reassembly_id.rs`'s two new tests.

GitHub issue [#80](https://github.com/karst-net/karst/issues/80) closed.

---

## Medium — the review §14 item 10 asked for

### 6. §13.8's argument mostly holds, but its own "narrow regression" paragraph undersold what an eavesdropper gains against `mac2` — **fixed 2026-09-02**

**Closed, with a code change.** This is the adversarial reading
`spec/phreatic-v1.md` §14 flags as "the one to read most sceptically" — a
security construction changed on performance grounds, never externally
checked. Option 2 below was chosen: `HandshakeInit`/`HandshakeResponse`
fragments cover the payload again; `CookieReply`/`TransportData` do not,
keeping §13.8's actual justified win where it was actually measured.
`spec/phreatic-v1.md` gained §13.11 recording the correction, and §9.2's
normative construction and "what the fragment MAC is, and is not" note were
updated to match.

`FragMacKey::compute`/`verify` and the `frag_mac`/`verify_frag_mac` free
functions (`crates/karst-proto/src/dos.rs`) now take the fragment payload and
a new `covers_payload(msg_type)` decides whether to fold it into the HMAC
input — `true` only for `HandshakeInit`/`HandshakeResponse`. Every verifier
(`Session::handle`, `Session::handle_cookie_reply`, and `Engine`'s `mac1`/
`mac2` candidate loops, consolidated into one `Engine::check_frag_mac` helper
to keep `Engine::inbound` under the workspace's line-count lint) now passes
the received payload through. New/updated coverage:
`crates/karst-proto/src/dos.rs`'s `handshake_type_fragments_cover_the_payload`
and `transport_and_cookie_reply_fragments_do_not_cover_the_payload`, and
`crates/karst-noise/tests/fragmented.rs`'s
`a_tampered_handshake_fragment_is_caught_by_its_own_mac` (replacing a test
that asserted the pre-fix behavior). GitHub issue
[#81](https://github.com/karst-net/karst/issues/81) closed.

**What #81's original text below still describes accurately: the reading
that found the gap.**

**What holds.** §13.8's core argument is correct and this pass could not
break it: `mac1`'s key, `HASH("Karst mac1 v1" ‖ S_r_pk)`
(`crates/karst-proto/src/dos.rs:53`), derives from the recipient's *public*
static key, so an adversary who holds that key could already forge a valid
`mac1` over **any** payload before this change — hashing the payload never
protected anything against that adversary, and the removal is a straight
cost win against them (confirmed at `dos.rs:107-127`: the MAC input really is
just `type ‖ reassembly_id ‖ idx ‖ cnt`, 7 bytes, nothing else). The
"amortized against a cost that is not there" argument for the transport data
path is also sound on its own terms: transport fragments run through no
`accept_handshake`-style expensive step, so a forged transport fragment that
reaches the AEAD costs the responder one AEAD failure — genuinely the narrow
cost §13.8 describes.

**What the "narrow regression" paragraph undersells.** §13.8 writes:

> An adversary who can *observe* traffic … can now capture a valid `(header,
> mac)` pair and replay it with a substituted payload, forcing an AEAD open.

That is accurate for `mac1` (no regression — the same adversary could forge
a fresh header from nothing) and for transport data (genuinely just an AEAD
open). It is **not the sharpest statement of what changes for `mac2`
specifically**, the one case where the pre-`§13.8` MAC *did* protect
something: `mac2`'s key is the secret, per-source cookie
(`mac2_key`, `dos.rs:59`), known only to the responder and to whichever
address received the matching `CookieReply` — that's what makes `mac2`
"authenticate … that the sender can receive at the claimed address" (§9.2).
Under the old, payload-covered MAC, an eavesdropper without the cookie could
only **replay** a captured `mac2`'d fragment verbatim — the reassembler
already rejects an exact repeat as `Reject::Duplicate`
(`reassembly.rs:274-276`), so a plain replay against the same entry does
nothing, and the header's own `reassembly_id` binding stops it from being
redirected anywhere else useful. Under the new MAC, the same capture lets
that eavesdropper keep the header and `mac2` bytes verbatim and substitute
**any payload it likes**, producing a fragment that still verifies as
address-validated but was never actually sent by, or derivable by, the
address it claims to come from.

Traced through to `bins/karstd/src/engine.rs:1218-1298` and
`crates/karst-noise/src/handshake.rs:628-689`, that substituted payload is
not bounded to "forces an AEAD open" if the captured fragment is index 0 (or
if the eavesdropper has captured a full set) of a `HandshakeInit`: a
`Complete` reassembly is handed to `accept_handshake`, which calls
`karst_noise::handshake::respond`, which unconditionally performs
`keys.kem_sk.decapsulate(ct_s)` (`handshake.rs:669-672`) **before** it
resolves `peer_id_hint` or checks whether the message means anything at all.
That is exactly the 20–50 µs ML-KEM decapsulation §9.2 says the whole
`mac1`/`mac2`/cookie apparatus exists to gate above `LOAD_THRESHOLD`. So the
regression, precisely stated: **above the load threshold, an eavesdropper
who has observed one legitimate `mac2`'d fragment (or set) gains the ability
to force the exact expensive operation the cookie mechanism exists to gate,
without ever learning the cookie itself** — a materially larger claim than
"forces an AEAD open," though still bounded (it costs one observation per
forgeable `reassembly_id`, requires source-address spoofing to match the
entry key, and is not a free-standing amplification primitive).

**Assessment, and the choice actually made.** Not a reason to reverse §13.8
— the transport-path win it was written for is real and untouched. Between
the two options this pass laid out — document only, or reintroduce payload
coverage for handshake-type fragments only — the second was chosen: it
closes the actual gap rather than accepting it, and the handshake path's
bounded volume (2-3 fragments per attempt, §6.4/§6.5) means the 23.4%-CPU
measurement that motivated §13.8 never applied there in the first place.
Implementation above; spec correction at §13.11.

---

## Medium — a missing standard check, honestly scoped — **fixed 2026-09-03**

### 7. Every X25519 DH output should be checked for contributory behavior, and none was

The constant-time-behavior pass this document's scope note deferred:
`karst-crypto`'s KEM/DH/AEAD call sites, read for branching and comparisons
on secret data beyond what Finding 4's zeroization pass already turned up.

**What the reading found isn't a timing side channel** — `karst-crypto`'s
`aead.rs` and `kem.rs` are thin wrappers that delegate every comparison
(AEAD tag verification, HMAC-adjacent equality) straight to `aes-gcm` and
`ml-kem`, both of which already do this in constant time, and neither module
adds a branch or comparison of its own on secret material. `dos.rs`'s
`frag_mac`/cookie comparisons (outside `karst-crypto`, but the same class of
check) already use `ct_eq`. What it found instead, in `karst-noise`'s DH call
sites specifically: `x25519_dalek::SharedSecret::was_contributory()` — the
crate's own constant-time check for RFC 7748's recommended defense against a
small-subgroup public key forcing a DH output to a fixed, publicly computable
value (the identity point, canonically, itself a valid-looking 32-byte
encoding) — existed in the dependency already in use and was never called at
any of the six `diffie_hellman()` sites in `crates/karst-noise/src/handshake.rs`.

**Why this is a Medium, not a High, once traced through — and why it's
being written up carefully rather than as a headline break.** The first pass
at this treated it as a live break of ADR-0002's "secure if either family
holds" claim, reasoning that an active MITM could substitute a wire-carried
ephemeral key for the identity point and force the classical contribution to
a known value, undetected — the classic attack this check exists for. Tracing
it through this spec's actual construction found that doesn't hold: every
DH leg here mixes a public key that was *already* bound into the transcript
hash via `mix_hash` before that same hash becomes the associated data for
the handshake's own confirmatory AEAD tag (`enc_ident` or `enc_empty`,
`crates/karst-noise/src/symmetric.rs`'s `encrypt_and_hash`/`decrypt_and_hash`).
Substituting a wire-carried ephemeral key therefore already fails that tag,
for a reason unrelated to the DH check —
`crates/karst-node/tests/handshake.rs`'s existing
`every_byte_of_handshake_init_is_authenticated` already pinned this,
including a probe at the ephemeral key's own byte offset, before this fix
existed. A MITM cannot run a "double substitution" to make both ends agree
on a forced value either: completing that requires the confirmatory tags on
*both* messages, which requires the initiator's and responder's real KEM
secrets — the attacker does not have them, and forging a self-consistent
handshake from scratch (§12.5 already establishes this is always possible,
low-order key or not) gains nothing beyond what an attacker already has by
constructing the whole exchange itself.

**What the check does close.** `initiate`'s "es" DH step uses
`peer.dh_pk` — sourced from the local netmap, not the wire — and nothing
binds *that* value into a transcript a network attacker could fail to
reproduce; a corrupted or malicious netmap entry carrying a low-order static
key would otherwise complete a handshake with a predictable, publicly
computable classical contribution, silently. That is the one leg where this
was a real, if narrow, gap — a supply-chain/netmap-compromise concern, not a
network-MITM one. The other five legs are hardening: cheap, standard, and a
backstop against a future change to the transcript-binding design
reintroducing the gap the binding currently closes as a side effect.

**Fixed.** A `mix_dh` helper (`handshake.rs`) computes each DH, checks
`was_contributory()`, and fails the handshake closed
(`HandshakeError::Malformed`, matching the existing style for other
early structural failures) before mixing a non-contributory result in —
applied uniformly to all six call sites rather than only the wire-sourced
ones, so the rule stays simple rather than depending on which binding
property covers which field today. `spec/phreatic-v1.md` §12 gained item 7
recording the requirement and its honestly-scoped rationale. New coverage:
`crates/karst-noise/tests/handshake.rs`'s
`initiate_fails_closed_against_a_low_order_peer_static_key` (the genuinely
non-redundant case). GitHub issue
[#82](https://github.com/karst-net/karst/issues/82) closed.

---

## Medium — the last open item in this workstream — **fixed 2026-09-03**

### 8. §14 item 9: the simultaneous-open pair never converged on one session

`crates/karst-node/src/session.rs` already kept both handshakes a
simultaneous open produces — the fix for GitHub issue #39, landed before
this review started — but never converged them: each end sealed with its
own initiator-role keys and read the peer's only through the responder-role
slot, a second AEAD attempt on every inbound datagram for the life of the
session, confirmed still true at the point this pass re-checked it
(`session.rs:635`, `:801`, per the "Low / already tracked" section this
finding replaces below). §14 itself named the missing piece: "converging on
one session needs a tie-break both ends can evaluate without another round
trip... and that is a normative rule, so it belongs in this document."

**Fixed.** Spec §8.1 (new) gives the state machine and the tie-break — the
higher static KEM public key's initiator role is the handshake the pair
keeps; §13.12 narrates why. `Session::handle_response`
(`crates/karst-node/src/session.rs`) now recognizes the collision precisely
(`rekey: Some(_)` alongside `initiated: false` has exactly one cause — an
outstanding dial carried into the rekey slot when the peer's own dial
answered first) and applies `wins_simultaneous_open_tiebreak`, a pure
comparison of the two already-known static keys: the winner proceeds as
before; the loser discards its own just-completed handshake and keeps the
live responder-derived session unchanged.

**One property found while writing the test, not assumed going in:
convergence is not always immediate, and MUST NOT be made to be.** Whichever
side's own handshake happens to complete first — before it has any way to
know a collision exists — legitimately becomes the live session at that
moment. If that side turns out to be the tie-break's loser once the
collision becomes visible (the peer's competing `HandshakeInit` arriving
after this end's own handshake already completed, which several of the six
message interleavings produce), correcting it immediately, on the strength
of that bare, unauthenticated second `HandshakeInit`, would violate §12.6's
existing rule against trusting an unconfirmed handshake message to override
a session already in use. The loser corrects itself on the peer's first
authenticated transport message instead — `Session::promote`, the same
mechanism §12.6 already uses for ordinary responder-session confirmation —
which the spec states as an explicit, deliberate part of the rule (§8.1,
§13.12) rather than a residual gap. The pair is fully usable in both
directions throughout; only the bookkeeping lags, for at most one message in
the losing direction.

New coverage in `crates/karst-node/tests/simultaneous.rs`:
`a_simultaneous_open_converges_on_the_higher_static_key` asserts, across all
six message interleavings, that exactly one side ends up `initiated()` and
that it is the side the tie-break names — checked after one round of
traffic each way, matching the eventual-convergence property above.
`only_the_simultaneous_opens_winner_rekeys` replaces
`a_simultaneous_rekey_carries_traffic`, whose premise ("after a simultaneous
open both ends are initiators, so both rekey") this fix makes false by
design — only the converged initiator ever rekeys now, the ordinary rule,
restored rather than worked around. GitHub issue
[#83](https://github.com/karst-net/karst/issues/83) closed.

---

## Low / already tracked — re-confirmed, not re-opened

- **§14 item 3, test vectors for the full key schedule, is still absent.**
  `find . -iname "*vector*" -iname "*phreatic*"` finds nothing; `spec/vectors/`
  holds Bedrock, control-API and relay-roster vectors only. Blocks
  interoperability testing, not security, per the spec's own table. Left open
  here rather than re-filed.
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

**Findings 1-4 from this pass are closed as of 2026-09-02, both tools'
halves of Finding 3 included:**
Finding 1 (cookies, GitHub issue [#76](https://github.com/karst-net/karst/issues/76)),
Finding 2 (PSK epoch grace period, GitHub issue [#77](https://github.com/karst-net/karst/issues/77)),
Finding 3 (CNSA model coverage, GitHub issue [#78](https://github.com/karst-net/karst/issues/78) —
`phreatic-nodh.vp` then `phreatic-nodh.pv`),
and Finding 4 (secret material never zeroized, GitHub issue [#79](https://github.com/karst-net/karst/issues/79)).

**Finding 5 (`reassembly_id` is a predictable counter, not a CSPRNG draw) is
closed** — GitHub issue [#80](https://github.com/karst-net/karst/issues/80).

**Finding 6 (§14 item 10's adversarial reading of §13.8) is closed** — GitHub
issue [#81](https://github.com/karst-net/karst/issues/81). Handshake-type
fragments now cover the payload in the MAC (spec §13.11); `CookieReply`/
`TransportData` keep §13.8's original construction.

**Finding 7 (the constant-time/DH-call-site reading) is closed** — GitHub
issue [#82](https://github.com/karst-net/karst/issues/82). Every
`diffie_hellman()` call site now checks `was_contributory()` and fails
closed; honestly scoped as defense in depth for five of the six legs and a
real fix for the sixth (a netmap-sourced peer static key).

**Finding 8 (§14 item 9, the rekey/simultaneous-open transition table) is
closed** — GitHub issue [#83](https://github.com/karst-net/karst/issues/83).
Spec §8.1 gives the state machine and the static-key tie-break that
converges a simultaneous open onto one session; §13.12 narrates it.

**All eight findings from this workstream's first pass are closed, and so
are every one of §14's items that this pass could resolve on paper — 5, 7
and 10 by earlier passes, 9 by this one.** What remains open in §14 is
exactly what the spec itself says needs something this workstream cannot
provide: item 1/2's ProVerif lattice-break gap (needs Tamarin or a
restructured model), item 3 (test vectors — an interoperability task, not a
security one), item 4 (`LOAD_THRESHOLD` — needs a real flood, not a
reading), item 6 (padding buckets — a metadata-posture design choice), and
item 8 (the out-of-band-KEM profile — not yet built). This workstream's
first pass is complete.
