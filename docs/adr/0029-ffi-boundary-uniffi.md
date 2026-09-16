<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-0029: A UniFFI crate boundary, `karst-ffi`, starting with enrollment

- **Status:** Accepted
- **Date:** 2026-09-16
- **Deciders:** Adrian Anderson (project owner)
- **Related:** ADR-0022 (mobile TUN backend — names this boundary as "not
  built yet"), ADR-0026/0027/0028 (macOS NetworkExtension backend, IPC,
  enrollment — the first consumer), ADR-0007 (licensing), GitHub issues #117,
  #157

---

## Context

ADR-0022 named the gap explicitly and left it open: "The UniFFI crate
boundary PLAN.md §9 names — what mobile app code actually links against, and
where `Tun::from_fd`'s `unsafe` contract gets enforced at the FFI edge rather
than merely documented — **is not built yet.**" `packaging/macos/KarstPacketTunnel`'s
`PacketTunnelProvider.swift` now has four call sites marked `TODO(karst-ffi)`
waiting on it, and #117 (iOS/Android) needs the same boundary for the same
reason.

**The tool question.** UniFFI is what PLAN.md §9 and ADR-0022 already name,
and it is the right fit on the merits: it generates idiomatic Swift and
Kotlin bindings directly from annotated Rust (proc-macro attributes, no
interface-description file to keep in sync by hand), it is what Mozilla built
for exactly this shape of problem — a Rust core linked into iOS/Android apps
— and it is battle-tested at the scale this project needs (Firefox's own
mobile apps ship it).

**The complication.** UniFFI is MPL-2.0. `deny.toml`'s license allowlist
(`MIT`, `Apache-2.0`, `BSD-2/3-Clause`, `ISC`, `Zlib`, `Unicode`, `CC0-1.0`,
`0BSD`) does not include it, and that allowlist has a stated purpose: "a new
license in the tree is a decision, and this list is where the decision is
recorded." `LICENSING.md` is pointed about the client crates carrying "no
copyleft obligation," so admitting any copyleft-flavored license, even a weak
one, is exactly the kind of thing that file exists to keep deliberate rather
than incidental.

MPL-2.0 is **file-level** copyleft: it obligates source availability for
*modifications to MPL-covered files themselves*, not for the code that links
against them, and not for the application as a whole. It does not touch
`karst-ffi`'s own MIT/Apache-2.0 licensing, and it imposes nothing on
`Karst.app`/`KarstPacketTunnel` or on anyone who ships them. This is not a
theoretical reading — Mozilla wrote UniFFI to be embedded in exactly this
position (a Rust core inside a shipped, closed-source mobile app), and ships
it that way in Firefox for iOS and Android today. The two alternatives
considered (below) avoid the license question entirely but at a real cost:
one departs from what this project's own plan already named, the other trades
a generated, maintained binding surface for hand-written glue on both the
Rust and Swift/Kotlin sides, indefinitely.

## Decision

1. **Add `MPL-2.0` to `deny.toml`'s license allowlist**, with a comment
   recording this reasoning — the same treatment the file already gives
   `0BSD`. It applies to UniFFI and its own dependency tree only; nothing
   else in the workspace is expected to pull it in.
2. **Add a new crate, `crates/karst-ffi`**, `MIT OR Apache-2.0` like every
   other crate under `crates/**`. It depends on `karstd` as a library (the
   workspace already declares `karstd` as a path dependency others can use)
   and re-exports selected operations through `#[uniffi::export]`, using
   UniFFI's proc-macro-only workflow — no `.udl` file, no `build.rs`.
3. **Ship one operation first: `enroll_invitation`**, wrapping
   `karstd::enrollment::enroll_invitation` verbatim. It is the most
   self-contained of `PacketTunnelProvider.swift`'s four `TODO(karst-ffi)`
   sites — it needs no running engine, no adopted `packetFlow` fd, and no
   netmap — and ADR-0028 item 3 already named it as the call this boundary
   should carry. The other three (`startTunnel`'s engine bring-up,
   `stopTunnel`'s teardown, and the `"status"` app-message verb) stay open
   under #157; they need the engine/netmap/DNS machinery `bins/karstd/src/run.rs`
   currently only runs as a full daemon process, which is a materially larger
   design question than exposing one already-pure function.
4. **A `uniffi-bindgen` binary lives in the same crate**
   (`src/bin/uniffi-bindgen.rs`, gated behind UniFFI's `cli` feature) so
   Swift/Kotlin bindings can be regenerated from the compiled library with
   `cargo run --bin uniffi-bindgen -- generate --library <path> --language
   swift --out-dir <dir>` — the standard UniFFI "library mode" workflow,
   needing no `.udl` to stay in sync.
5. **`Tun::from_fd`'s `unsafe` contract (ADR-0022) is out of scope for this
   ADR.** It only matters once `startTunnel`'s engine bring-up is designed,
   which item 3 above defers.

### Alternatives rejected

- **Diplomat** (MIT/Apache-2.0, used by ICU4X). Avoids the license question
  outright and would have been the pick on a blank slate. Rejected here
  specifically because ADR-0022 and PLAN.md §9 already named UniFFI before
  this ADR — switching tools is a decision that deserves its own review of
  *why*, not a side effect of a license-avoidance preference, and nothing
  about Diplomat's binding quality or maintenance is a reason to override
  what was already decided.
- **Hand-written C ABI** (`#[no_mangle] extern "C" fn`, hand-authored
  Swift/Kotlin wrappers, no codegen dependency at all). Zero license
  question and zero new dependency, the way `karst-crypto`'s ADR-0006
  agility layer and this project's general narrow-dependency posture would
  favor. Rejected because it trades a one-time license decision for
  indefinite hand-maintained glue on both sides of every function this
  boundary ever adds — the wrong trade for a boundary that ADR-0022 already
  expects to grow (engine lifecycle, netmap status, more as mobile clients
  mature under #117).
- **Waiting for the entitlement (#156) or the packaging pipeline (item 7)
  before starting this.** Rejected: this boundary is needed by #117 (mobile)
  independent of the macOS entitlement entirely, and nothing about designing
  and building it requires a signed extension to already exist — only
  loading it into a real `NEPacketTunnelProvider` does, which stays out of
  scope until packaging exists.

---

## Consequences

### Positive

- Removes the first of `PacketTunnelProvider.swift`'s four `TODO(karst-ffi)`
  gaps with a real, working call rather than another honest placeholder.
- `enroll_invitation` reaches the extension exactly as ADR-0028 item 3
  specified, with no reimplementation: the existing bundle-parsing,
  control-plane handshake, and config-publishing logic in
  `bins/karstd/src/enrollment.rs` is reused verbatim.
- The crate and its bindgen binary are useful to #117 (iOS/Android) without
  modification — nothing here is macOS-specific.

### Negative

- **MPL-2.0 is now a license class in the dependency tree**, which is the
  irreversible-in-spirit part of this decision: a future reviewer or auditor
  will see it in `cargo deny` output and needs this ADR to know it was a
  deliberate, reasoned inclusion rather than an oversight.
- The three larger `TODO(karst-ffi)` sites (engine start/stop, status) remain
  open. This ADR does not design them, and closing #157 fully still requires
  a real answer to "what does `bins/karstd`'s engine loop look like when it
  is not the daemon's own `main`."
- `karst-ffi` is compiled and unit-tested on Linux in this change, but its
  generated Swift bindings have not been linked into an actual Xcode target
  or run on macOS — the same "written and reviewed, not run" posture
  `packaging/macos`'s existing Swift files already carry, for the same
  reason (no Mac available in this environment).

### Reconsider if

- UniFFI's own dependency tree grows a license this project would not
  independently accept (this ADR reviewed UniFFI's *direct* license only).
- The engine-lifecycle design this defers turns out to need a fundamentally
  different binding shape than `#[uniffi::export]` functions — e.g. if
  `packetFlow` fd ownership needs to cross the boundary as a long-lived
  object with async callbacks UniFFI's synchronous proc-macro surface
  cannot express cleanly, which would be a reason to revisit the tool choice
  for that piece specifically, not necessarily for `enroll_invitation`.
