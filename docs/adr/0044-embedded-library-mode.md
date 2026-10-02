<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-0044: A general-purpose embedded library mode, `karst-embed`

- **Status:** Proposed
- **Date:** 2026-10-02
- **Deciders:** Adrian Anderson (project owner)
- **Related:** ADR-0029 (the `karst-ffi` UniFFI boundary this is explicitly
  not reusing), ADR-0030 (`run_engine`'s `Attachment`/`DeviceOrigin`
  parameterization, extended here a third way), GitHub issue #214

---

## Context

Every existing way to join the mesh is either a full `karstd` process (a
LaunchDaemon/service, with its own control socket, CLI, and lifecycle) or
`crates/karst-ffi`'s mobile/`NetworkExtension` boundary — a GUI app adopting
a platform-handed tunnel file descriptor (ADR-0022, ADR-0029, ADR-0030).
Neither fits a third, real shape: an arbitrary Go or Rust **backend
service** that wants to link in a mesh node directly and become a reachable
peer itself, with no sidecar process, no GUI, and no platform-owned tunnel
fd to adopt.

**The research finding that shapes this whole decision**:
`crates/karst-tun::Userspace` already exists, is already a complete
`NetworkMode` option `karstd` itself ships, and already exposes a real
**socket API** — `connect_tcp`/`listen_tcp`/`tcp_send`/`tcp_recv`,
`listen_udp`/`udp_send`/`udp_recv` — on a `Clone`-able handle, built
originally for "containers that cannot create a TUN device." It needs no
root, no `CAP_NET_ADMIN`, and no kernel device at all. `bins/karstd/src/run.rs`'s
`run_engine` (ADR-0030) already takes an `Attachment`/`DeviceOrigin`
parameter for how the interface comes to exist; `Create` with
`NetworkMode::Userspace` already runs with no privilege requirement
whatsoever. The only missing piece was a way to hand that `Userspace`
handle back to an external caller instead of only letting `run_engine`
drive it internally forever — this ADR is mostly *exposing* existing
machinery, not inventing a new engine mode.

This also makes GitHub issue #214's own acceptance criterion — "a minimal
example that becomes a reachable mesh peer with no `karstd` process
running alongside it" — **attemptable with real infrastructure in this
environment**, unlike the macOS work (ADR-0040/0043): `bins/karstd/tests/control.rs`
already proves a real Go coordination server can run on plain loopback
with no namespaces or root, so a real two-embedded-node test against it,
plus a real `karst-relay`, is this pass's verification attempt — real
code and real infrastructure, not a "written and reviewed, not run" stub,
even though (item 7) it has not yet been watched to a passing conclusion.

## Decision

1. **`bins/karstd/src/run.rs` grows one new entry point, `run_embedded`**,
   alongside `run_with_control`/`run_with_adopted_fd` — same `run_engine`
   body (ADR-0030's "parameterized, not forked" convention), zero behavior
   change for the three existing callers. It refuses immediately unless
   `config.network_mode == NetworkMode::Userspace`: an embedding caller has
   no kernel device to create or adopt, and `NetworkMode::Tun` would hand it
   nothing it could use. `run_engine` grows one new optional parameter,
   `userspace_ready: Option<&SyncSender<Userspace>>`, sent at the *same*
   point `run_with_adopted_fd`'s own `ready` channel already fires — right
   after the control socket binds, not merely once the interface exists.
   **Found chasing the identical race #161 already named for `ready`**: an
   earlier version of this change sent the signal immediately after
   `bring_up_interface`, which let `MeshNode::start` return a handle whose
   first real use (`status_json()`) could race the socket bind further down
   the function — exactly the #161 failure mode in a new guise, caught by
   actually running the two-node test below rather than left undiscovered.

2. **New crate `crates/karst-embed`** — the Rust embedding API. Plain Rust,
   no UniFFI, same `MIT OR Apache-2.0` license as every other crate (no new
   license class, unlike ADR-0029's MPL-2.0 addition for UniFFI). `MeshNode`
   mirrors `karst-ffi::engine::EngineHandle`'s lifecycle shape (background
   thread, bounded ready channel, `stop`/`Drop` split) but hands back
   `Userspace`'s TCP/UDP socket API — wrapped as `MeshTcpStream`/
   `MeshTcpListener`/`MeshUdpSocket`, each a small poll-and-sleep bridge over
   `Userspace`'s already-non-blocking methods — instead of a raw packet flow,
   since there is no kernel device or GUI on the other end for this consumer.
   `karst-tun::Userspace` also gained one small, symmetric addition here:
   `udp_release`, a `tcp_release` counterpart that did not exist before
   because its only prior caller (`karstd`'s own DNS runtime) binds one UDP
   listener for the daemon's whole life and never needed to give one back.

3. **New crate `crates/karst-embed-capi`** — a hand-rolled C ABI, not
   UniFFI and not a generated binding. UniFFI (ADR-0029) targets Swift and
   Kotlin; Go is not one of its supported languages, and the third-party
   (non-Mozilla) `uniffi-bindgen-go` generator would be a new, less mature
   tool dependency for exactly one consumer. A plain `extern "C"` boundary is
   what cgo already expects natively. The header
   (`include/karst_embed_capi.h`) is likewise **hand-written, not
   `cbindgen`-generated**: `cbindgen` is MPL-2.0, and ADR-0029's existing MPL
   allowance is scoped explicitly to UniFFI's own dependency tree, not a
   general license for this workspace — reusing it here would be a second,
   unreviewed MPL entry point this ADR would rather name as a real,
   negative trade-off (the header can drift from the Rust signatures) than
   paper over with a tool.

4. **New Go module `bindings/go/karst`**, its own `go.mod`
   (`github.com/karst-net/karst/bindings/go/karst`) — separate from
   `server/`'s netbird-fork module and `deploy/kubernetes/operator`'s module,
   matching this repo's existing precedent of per-area Go modules rather
   than one monolith. It cgo-links `karst-embed-capi`'s compiled library and
   wraps it as idiomatic Go: `net.Conn`/`net.Listener`/`net.PacketConn`
   implementations over the opaque stream/listener/socket handles, a
   thread-local-backed `error` type, `runtime.LockOSThread` around every
   call that reads the C side's thread-local last-error string.

5. **TCP and UDP both in scope this pass**, not TCP alone — both are already
   fully implemented under `Userspace`, so shipping only one would be
   withholding working functionality for no reason, unlike the macOS work's
   "minimal viable" exit-node/managed-device deferrals (ADR-0043 item 4),
   which deferred things that did not yet exist at all.

6. **Two configuration settings every embedding caller must set explicitly,
   neither obvious from `enroll`'s own output**: `network_mode = "userspace"`
   (see item 1) and `exit_node_state_file`, pointed inside the caller's own
   state directory. Left absent, `karstd::control::load_config` defaults the
   latter to `exit_node::DEFAULT_STATE_FILE` — a root-owned, fixed host path
   (`/var/lib/karst/exit-route` on Linux) `config.rs`'s own doc comment
   already names as existing for "more than one `karstd` on the same
   host... which would otherwise all share one root's worth of exit-route
   state." A non-root embedding process, or more than one embedded node on
   one host, is exactly that case — `run_engine` treats anything but
   `NotFound` opening that path as a fatal startup error, which a fresh,
   non-root embedding deployment will hit immediately as a plain permission
   error with no obvious connection to "exit routes." **Found running the
   verification in item 7**, not anticipated — documented in
   `crates/karst-embed/README.md` as the first thing a new embedder needs to
   know, not left for the next person to rediscover via a confusing EACCES.

7. **Verification: a real, local, two-node, no-root integration test**
   (`crates/karst-embed/tests/two_nodes.rs`), not unit tests alone. It
   builds and starts the real Go coordination server on loopback (mirroring
   `bins/karstd/tests/control.rs`'s `TestServer`, not `aquifer.rs`'s heavier
   netns fixture — `NetworkMode::Userspace` needs neither), enrolls two
   embedded nodes against it with real `karst-invite-v1:` invitations, and
   is written to assert a real TCP byte exchange between them with no
   `karstd` process anywhere. **Writing it surfaced real, fixed bugs** in
   this pass's own code — the `ready`-channel ordering race (item 1), the
   root-owned exit-route default (item 6), a relay roster that expires
   mid-test without a renewal thread, and this specific development
   machine's docker bridges needing AVEN's reflector (`ponor-v1.md` §7.7) to
   learn a real, usable address at all, since a "local" send between two of
   its own virtual interfaces is observably source-NATted, the same shape a
   real NAT presents.
   **What this pass did not reach: a confirmed real TCP byte exchange.**
   With every fix above applied, both nodes register, sync netmaps, exchange
   disco candidates, and reach the relay's reflector successfully — real,
   verified progress — but the handshake itself did not complete within
   several minutes of direct observation on this development machine, which
   also runs its own pre-existing `karstd`/`karst-relay` and has an unusually
   large number of virtual interfaces (several docker bridges, Tailscale, a
   VPN) that may be interacting with disco's candidate model or the relay's
   own data-forwarding path in a way this pass did not isolate. This is
   named as the honest, unresolved state, not papered over: the test is
   real infrastructure exercising real code, not a stub, but its own
   assertion that bytes actually cross has not been watched pass locally.
   The next real verification opportunity is `.github/workflows/ci.yml`'s
   new "Two embedded nodes exchange TCP with no karstd process" step, on a
   GitHub Actions runner's much simpler network (no pre-existing relay, no
   half-dozen docker bridges) — the same "push and let CI tell you" posture
   this project already used for ADR-0043's new workflows.

### Alternatives rejected

- **A generated Go binding via `uniffi-bindgen-go`.** Rejected: non-Mozilla,
  less mature than UniFFI's own Swift/Kotlin generators, and a new tool
  dependency for the one consumer that needs it. ADR-0029's own reasoning
  for choosing UniFFI over a hand-written C ABI was specifically about
  mobile's indefinite hand-maintained-glue cost on *two* sides (Rust and
  Swift/Kotlin, growing as the surface grows); a single, already-small,
  intentionally-narrow C ABI for one backend-service use case does not carry
  that same cost.
- **`cbindgen` for the header.** Rejected on license grounds — see item 3.
- **Reusing `crates/karst-ffi` itself, adding a `network_mode = "userspace"`
  branch to `EngineHandle`.** Rejected: `karst-ffi` is UniFFI-bound
  end-to-end, and UniFFI's proc-macro surface is not what a cgo consumer
  needs or can use directly; forcing Go through a UniFFI-shaped crate would
  mean either exposing UniFFI's own generated scaffolding to Go (which it
  does not support) or wrapping a wrapper. A separate crate with its own
  plain-Rust API, consumed directly by Rust callers and wrapped a second,
  thinner time for Go, is the shape that serves both without coupling them.
- **Deferring the exit-route-default config gotcha (item 6) to be
  discovered by the first real embedder.** Rejected once it was actually
  hit, in this ADR's own verification pass: it is a one-paragraph
  explanation that saves a confusing permission-error debugging session for
  every embedding caller after this one, not a hypothetical edge case.

---

## Consequences

### Positive

- Issue #214's acceptance criteria are pursued with a real, automated,
  no-privilege, no-hardware-dependent integration test — a stronger
  verification *attempt* than ADR-0029/0030/0043 could even make for their
  own, genuinely hardware-constrained, macOS-only scope. Unlike that work,
  real infrastructure (a Go control server, a relay) is reachable here
  without special hardware — item 7 is honest that the attempt has not yet
  fully succeeded locally, but the path to a real pass (CI, or a cleaner
  host) is open in a way it simply is not for anything needing a real
  Apple Developer Program certificate.
- `karst_tun::Userspace`'s socket API is exercised by a second, genuinely
  different consumer (a generic backend process, not `karstd`'s own
  SOCKS5/publish plumbing), reinforcing that nothing daemon-specific leaked
  into it — the same kind of cross-consumer confirmation ADR-0030's own
  Positive section notes for `karst-ffi` and `run_with_adopted_fd`.
- Two language bindings (Rust directly, Go via `bindings/go/karst`) share
  one engine-lifecycle implementation (`crates/karst-embed`), not two
  divergent ones — `karst-embed-capi` is a thin wrapper over it, nothing
  more.

### Negative

- **A real TCP byte exchange between two embedded nodes has not actually
  been observed to succeed, on any path** — see item 7's full account.
  Registration, netmap sync, disco candidate exchange, and reaching the
  relay's reflector are all confirmed working; the handshake completing
  is not. This is the central open item this ADR leaves: not "direct
  connectivity is unconfirmed while relay fallback works," which would be a
  narrower, more comfortable gap, but that neither path was watched to
  completion locally. The next real evidence comes from CI (item 7's
  closing paragraph) or a cleaner host, not from this ADR.
- **Two configuration settings (item 6) are easy to get wrong**, and the
  failure modes are both unhelpful: a `network_mode` left at its `Tun`
  default fails fast with a clear message (`run_embedded`'s own refusal);
  `exit_node_state_file` left absent fails with a bare permission error that
  does not mention exit routes, configuration, or this crate at all. The
  README documents both; nothing in the code itself detects and explains
  the second one yet.
- **A hand-written C header is a real, ongoing maintenance cost.** Every
  future change to `crates/karst-embed-capi`'s `#[no_mangle]` functions must
  be mirrored by hand in `include/karst_embed_capi.h`, with no compiler
  check that the two agree — a signature mismatch is a linker or runtime
  bug, not a build failure.
- Exit-node consent and managed-device/MDM coexistence do not exist on this
  surface at all — not deferred as a known gap the way ADR-0043 scoped
  exit-node parity out, but genuinely unconsidered beyond the one
  config-validation workaround item 6 names. A future embedding use case
  that needs either would need real design work, not a flag flip.

### Reconsider if

- CI's run of `two_nodes.rs` (item 7) also fails to reach a passing TCP
  exchange. That would mean the gap is in this pass's own code or design,
  not this one development machine's networking, and would need real
  investigation before this ADR's design can be trusted — most likely
  starting with the relay's own forwarding path (confirmed reachable for
  signaling; never confirmed for data) rather than disco's candidate model.
- The gap turns out to matter for a real deployment even after CI passes —
  e.g., two embedded nodes on the same host or LAN that need to work
  without a relay in the loop specifically. That would move "why does
  same-host candidate punching not converge on this one machine" from a
  shrug to a real question, and likely needs its own investigation into
  `karstd::disco`'s handling of two peers with identical or near-identical
  candidate sets.
- A real embedding deployment hits the `exit_node_state_file` gotcha despite
  the README, suggesting the config-validation error itself should name the
  likely cause (an embedding caller that forgot to set it) rather than
  surfacing as a bare `PermissionDenied`.
- Go bindings for a second non-UniFFI language are ever needed (Python,
  Node, etc.): `crates/karst-embed-capi`'s existing C ABI is very likely
  reusable as-is for any of them, which would be the point at which "one
  hand-rolled C ABI, several thin per-language wrappers" either keeps
  paying for itself or argues for revisiting the no-`cbindgen` choice (item
  3) now that more than one consumer depends on the header staying correct.
