<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-0030: Running `karstd`'s engine embedded, over an adopted fd

- **Status:** Accepted
- **Date:** 2026-09-17
- **Deciders:** Adrian Anderson (project owner)
- **Related:** ADR-0022 (mobile TUN backend — `Tun::from_fd`, the `unsafe`
  contract this ADR is the first real caller of), ADR-0026 (macOS
  NetworkExtension backend — item 3's "no address/route work in this
  variant," which this ADR makes the code actually hold), ADR-0029 (the
  `karst-ffi` boundary and its `enroll_invitation` slice, which this
  continues), ADR-0003 (`unsafe` confined to specific, self-documenting call
  sites), GitHub issue #158

---

## Context

#158 named three things `PacketTunnelProvider.swift` still needs from
`crates/karst-ffi`: `startTunnel`'s engine bring-up, `stopTunnel`'s teardown,
and a status query — and named the real work as a design question, not three
missing `#[uniffi::export]` functions: how does `bins/karstd`'s engine loop
run somewhere other than that binary's own `main`?

**The good news: most of it already does.** `run.rs`'s `run` →
`run_with_socket` → `run_with_control` is already a layered, embeddable
library call, not something wired only to `main`. `run_with_control` takes
an `Arc<Config>`, a `&Shutdown` (already exactly the handle a background
thread and a stop call need — `request()`/`requested()`), a control-socket
path, and an optional control-plane client, and blocks until told to stop.
Nothing about *that* shape needed inventing.

**What is actually missing: how the interface itself comes to exist.**
`bring_up_interface` unconditionally calls `Tun::create`/`Userspace::create`
— it creates a device, which needs `CAP_NET_ADMIN`/root and is exactly what
a sandboxed `NEPacketTunnelProvider` may never do. `karst-tun`'s
`network-extension` feature already has the answer on the `karst-tun` side —
`Tun::from_fd` adopts a descriptor the platform handed across instead
(ADR-0022) — but `bins/karstd` has no path to it at all, and structurally
can't just flip that Cargo feature on: `network-extension` is deliberately
**not additive** (ADR-0026 item 3) — it removes `set_address`/`add_route`/
`remove_route`/`ifindex` from `karst_tun::Tun` because
`NEPacketTunnelNetworkSettings` owns addressing and routing instead. Every
one of `run.rs`'s `NetworkDevice` delegate methods calls exactly those, so
enabling the feature on `karstd` without changing `run.rs` breaks the build
— which is precisely the bug the CI fix earlier in this session's session
history papered over by *excluding* `karstd` from that feature entirely.
This ADR is what makes the feature actually usable there instead of just
avoided.

**A second, smaller finding while tracing this: `karstd`'s `#![forbid(unsafe_code)]`
is now a real constraint, not a formality.** Adopting a descriptor means
calling `Tun::from_fd`, which is `unsafe` by its own documented contract —
"the FFI boundary's own safety argument, carried across from the mobile app
runtime that obtained `fd`." `forbid` cannot be locally overridden by any
`#[allow]`, anywhere downstream, which is the whole difference between
`forbid` and `deny`. `karst-ffi`'s own crate-level `#![forbid(unsafe_code)]`
has the identical problem in reverse, for the same reason.

**A course correction on this ADR's own predecessor.** #158's text asked
"how it reports status without the Unix control socket the LaunchDaemon
build uses," reading the socket itself as the problem. It isn't. The
LaunchDaemon build's socket is a *privilege* boundary — a root-owned
listener a separate, unprivileged CLI process connects to. Inside a
`NEPacketTunnelProvider`, there is no second process: the caller asking for
status is the extension's own Swift code, in the same sandbox, with no
privilege gap to cross. A Unix socket at a path inside the extension's own
container is just ordinary intra-process IPC glue at that point, not a
repeat of the "spawn a whole daemon" problem the original TODO comment
was actually naming. Reusing it costs nothing and inherits `status_json`'s
entire tested `ipc::Command` dispatch verbatim.

## Decision

1. **Reuse `run_with_control`'s body, parameterized, not forked.** Extract
   its ~1000-line implementation into a private `run_engine`, taking one new
   parameter:

   ```rust
   enum Attachment {
       /// Create a device — the LaunchDaemon path.
       Create,
       /// Adopt an already-open descriptor — the embedding path.
       #[cfg(all(target_os = "macos", feature = "network-extension"))]
       AdoptFd(std::os::fd::RawFd),
   }
   ```

   `run_with_control` becomes a thin wrapper passing `Attachment::Create` —
   **unchanged behavior, unchanged public signature**, for its three
   existing callers (`main.rs`, `service_windows.rs`, `run_with_socket`).
2. **Add `run_with_adopted_fd`**, `unsafe fn`, gated the same way as
   `Attachment::AdoptFd`, forwarding `Tun::from_fd`'s own safety contract
   rather than re-deriving it. It keeps `run_with_control`'s socket-path and
   control-client parameters — see the status course-correction above — and
   drops only `status_socket_path`: nothing inside the same sandboxed
   process needs a *second*, unprivileged listener the way an external
   per-user client does.
3. **`bring_up_interface` grows an `Attachment` parameter.** Under
   `Attachment::AdoptFd(fd)`, it calls a new, narrowly-scoped
   `#[allow(unsafe_code)] fn adopt_tun` wrapping `Tun::from_fd`, and skips
   every address/route/secondary-address call entirely — matching ADR-0026
   item 3 exactly, not approximating it. Under `Attachment::Create`, nothing
   about today's behavior changes.
4. **`NetworkDevice`'s `set_address`/`add_route`/`remove_route`/`ifindex`
   grow a second, `#[cfg(all(target_os = "macos", feature = "network-extension"))]`-gated
   arm for `Self::Tun`**, answering `Ok(())`/`Ok(None)` rather than calling a
   method that no longer exists on that build's `Tun`. This is a **known,
   deliberate limitation, not a solved problem**: `add_route`/`remove_route`
   are also how subnet-router/exit-node policy changes reach the interface
   mid-session (`run.rs`'s dynamic route churn, not just startup). Answering
   `Ok(())` there means a route change arriving after `startTunnel` is
   silently not applied under this build — `NEPacketTunnelNetworkSettings`
   was set once, and nothing here calls `setTunnelNetworkSettings` again.
   Fixing that for real needs a callback from Rust back into the extension's
   Swift `setTunnelNetworkSettings`, which is out of scope here and tracked
   as follow-up under #158, not invented as working.
5. **`karstd`'s crate-level lint moves from `forbid(unsafe_code)` to
   `deny(unsafe_code)`**, with `adopt_tun` as the one function carrying
   `#[allow(unsafe_code)]` and its own `# Safety` argument — the identical
   posture `karst-tun`'s own crate comment already states for ADR-0003.
   `bins/karstd/src/main.rs` keeps its own `forbid`: nothing in the binary
   target needs this, only the library's `run.rs` does.
6. **`karst-ffi`'s crate-level lint gets the same treatment**, in whichever
   follow-up change actually calls `run_with_adopted_fd` from a
   `#[uniffi::export]` function — not in this one, which stops at `run.rs`'s
   own boundary and leaves the `karst-ffi` wiring to #158's next slice.
7. **`karstd` gains its own `network-extension` Cargo feature**, forwarding
   to `karst-tun/network-extension`. Nothing outside `run.rs` needs to know
   about it.

### Alternatives rejected

- **A second, forked copy of `run_with_control`'s body.** Rejected: ~1000
  lines of tested engine setup, duplicated, is exactly the kind of drift
  this codebase's "don't invent a second implementation" posture (stated for
  `karst-tun` itself in its own module docs) exists to prevent. A parameter
  costs one enum and one call site; a fork costs a second copy that silently
  stops matching the first the next time either one changes.
- **Extending `NetworkMode` (`Tun`/`Userspace`) with a third variant.**
  Rejected: `NetworkMode` is an operator-facing TOML setting an admin
  chooses ahead of time. An adopted fd is not a setting — it is a value the
  embedding Swift code hands over at the moment `startTunnel` runs, and
  `Config` has no slot for a value that only exists at that moment. Threading
  it as a call parameter (`Attachment`) rather than a config field is the
  honest shape for something that cannot be known when the config loads.
- **Dropping the Unix control socket for status, per #158's original
  wording.** Rejected on reflection — see the Context section above. The
  socket was never the actual problem; the separate process was.
- **Fixing the mid-session route-churn gap now**, e.g. by having `adopt_tun`'s
  errors bubble further or inventing a callback mechanism. Rejected as
  premature: no `karst-ffi` function calls any of this yet (#158's next
  slice does), so there is no real Swift-side `setTunnelNetworkSettings`
  hook to design against — building one blind would be exactly the kind of
  invented-before-verified work this project's own review culture pushes
  back on.

---

## Consequences

### Positive

- `run_with_control`'s ~1000 lines of tested engine setup — gateway,
  DNS-runtime start, datapath workers, netmap sync, exit-node/subnet-router
  handling — all reach the embedded path for free, with zero duplication and
  zero behavior change for the three existing LaunchDaemon-path callers.
- Status querying reuses `ipc::Command`'s entire existing dispatch, including
  `StatusJson`, verbatim — no second status format to keep in sync with the
  LaunchDaemon build's.
- `karstd`'s `unsafe` posture now says exactly what `karst-tun`'s already
  says: confined, narrow, and self-documenting at the one call site that
  needs it — not a blanket forbid that happened to be true only because
  nothing had needed `unsafe` yet.

### Negative

- **Mid-session route/address changes are silently inert under this build**,
  as item 4 states plainly. A subnet-router or exit-node grant that arrives
  after `startTunnel` will not reach the interface until something (a future
  slice) reapplies `setTunnelNetworkSettings`. This is a real functional gap
  a fleet using the NE build for exit/subnet routing would hit, not a
  hypothetical one.
- `run_with_adopted_fd` is `unsafe fn`. Every future caller — the next
  `karst-ffi` slice included — inherits `Tun::from_fd`'s full safety
  contract (exclusive fd ownership, transferred, not shared) and must
  restate it, the same as `Tun::from_fd` itself already demands of `mobile.rs`'s
  own callers.
- This ADR does not touch `karst-ffi` at all. #158 is not closed by this
  change — only `run.rs`'s half of it is.

### Reconsider if

- The mid-session route-churn gap (item 4's negative) turns out to matter
  before a callback mechanism is designed — e.g. if the public macOS beta
  actually exercises subnet routing over the NE build. That would move the
  callback design from "follow-up" to "blocking."
- Measuring this embedded engine's real memory footprint inside a System
  Extension (ADR-0026's own still-open "Reconsider if") turns up a number
  that makes reusing the full `run_engine` surface — exit nodes, SSH gating,
  relay telemetry, all of it — the wrong call for a memory-constrained
  extension process, arguing instead for a deliberately narrower engine
  built for this environment specifically.
