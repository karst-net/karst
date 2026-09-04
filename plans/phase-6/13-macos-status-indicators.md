# macOS client status indicators

Added 2026-09-04. Not a beta gate (#12) — [00-overview.md](00-overview.md)
§2 item 13, best-effort against remaining capacity after TURN (#5) and the
console surfaces (#6, #7) are staffed.

## 0. What this actually requires, stated plainly

The ask is "visual status indicators for connectivity and throughput" on the
macOS client. **There is nothing to add an indicator to.** Per
[phase-5/06-macos-client.md](../phase-5/06-macos-client.md) §0, the macOS
client that shipped in Phase 5 is a `LaunchDaemon` (`karstd`, root, no GUI
session) plus a CLI (`karst status`). There is no menu-bar app, no
`NSStatusItem`, nothing running in the user's GUI session at all — this is a
new client surface, not an enhancement to an existing one, and should be
staffed and estimated that way rather than folded into "polish."

## 1. What already exists to build on

- **Connectivity data already exists and is structured.** `PeerStatus`
  (`bins/karstd/src/engine.rs:2233`) carries `established`, `rekeying`,
  `endpoint`, and `transport` (direct / relayed / TURN — deliberately not a
  bool, per the field's own doc comment: a relayed peer works, but slower and
  through a third party, and that distinction matters to a user asking "why
  is this slow"). `Command::Status` (`bins/karstd/src/ipc.rs`) already
  returns this over the daemon's local control socket, and `run.rs:3479`
  is the existing handler. A menu-bar app polling or subscribing to this
  socket gets connectivity for free.
- **Throughput data now exists.** `PeerSlot` (`bins/karstd/src/engine.rs:280`)
  carries `tx_bytes`/`rx_bytes` atomics, incremented in `send_sealed` and
  `deliver_to_host` from the plaintext length — the same length `tx_packets`/
  `rx_packets` already counted, so the two stay comparable, and not the
  sealed/padded wire size, which would make the number depend on suite
  choice. `PeerStatus` (`engine.rs:2233`) surfaces them as running totals, and
  `Command::Status`'s existing `[[peer]]` output (`run.rs`) now prints
  `tx_bytes`/`rx_bytes` alongside `transport` — no new IPC verb needed;
  item 2 below settles on the existing one rather than growing a second.
  Covered by
  `peer_status_reports_bytes_sent_and_received` in
  `bins/karstd/tests/datapath.rs`, including the case that mattered: a
  packet the sender's own ACL refused before encryption must not be counted.
  **Cumulative counters, not rates** — matching how `08-observability.md`'s
  Prometheus counters already work — so a menu-bar app samples twice and
  differences client-side to show a rate or sparkline; the daemon does not
  guess a sampling interval.
- **The admin control socket cannot be what a menu-bar app talks to — this
  was wrong in an earlier draft of this section.** It is local-only, but not
  merely "unauthenticated-by-proximity": `ipc::bind`'s directory is `0700`
  and the socket `0600`, both owned by root under the `LaunchDaemon` this
  ships (`ipc.rs`'s own module doc says why — the socket can issue
  `Command::Down`, which is administrative access). `docs/GETTING-STARTED.md`
  already documents `sudo karst status` for exactly this reason. A per-user
  `LaunchAgent` runs as the logged-in user, not root, and cannot open that
  directory at all — a menu-bar app built against it would fail every poll
  with a permission error, or would need to prompt for `sudo` continuously,
  which is not a menu-bar app.

  **Fixed, not merely noted.** `ipc::bind_unprivileged_status` opens a
  second, sibling socket — `karstd --status-socket PATH` — reachable by any
  local user (`0755`/`0666`) but answering exactly one thing: `status`.
  Anything else, `down` above all, gets refused by the listener itself
  (`run.rs`'s second control thread), not merely by convention — the admin
  socket's `Down` handling is not reachable from this path at all. Absent
  unless the flag is given; nothing binds it by default on any platform.
  `ipc::DEFAULT_STATUS_SOCKET` (`/run/karst-status/karstd.sock`) is the
  agreed path packaging and the menu-bar app should both use. Covered end to
  end, unprivileged, by `bins/karstd/tests/status_socket.rs` — a real
  `karstd` subprocess, `status` served, `down` refused and the daemon
  confirmed still up afterward, and the directory/socket modes asserted
  directly.

## 2. Shape of the work

1. **A menu-bar app**, an `NSStatusItem`-based AppKit app, distinct from
   `karstd` — it runs in the user's GUI session, `karstd` does not (it is a
   `LaunchDaemon`, not a `LaunchAgent`, and has no GUI session to run in). It
   connects to `ipc::DEFAULT_STATUS_SOCKET`, never the admin socket — see §1.
   **A first draft exists**, at `packaging/macos/KarstStatus/` (Swift
   Package Manager sources: `StatusClient.swift` opens the socket and speaks
   its request/reply framing, `StatusParser.swift` reads `karstd`'s status
   text into a small model, `AppDelegate.swift` renders the `NSStatusItem`
   and its menu on a 2 s poll, differencing `tx_bytes`/`rx_bytes` itself per
   §1's cumulative-counter contract). It covers items 3 and 4 below in
   design — distinct glyphs (`●`/`◐`/`○`/`⛔`) paired with text for every
   state, never color alone; a mixed direct/relayed roster reports the
   relayed state rather than averaging it away, matching
   `Transport`'s own non-bool design.
   **Written blind, but no longer unverified at the compiler level.**
   Written on this Linux dev machine, which has no Xcode or Swift/AppKit
   toolchain — the source was reviewed line by line against real Darwin API
   signatures from memory, not typed against a compiler. A standalone
   workflow, `.github/workflows/macos-status-swift-build.yml`, runs
   `swift build` against it on a real `macos-14` GitHub Actions runner
   (Swift 5.10, arm64-apple-macosx14.0) rather than waiting for a Mac —
   pushed on branch `macos-status-swift-check`, and it built clean on the
   first attempt: all four files compiled, the executable linked, `Build
   complete! (13.44s)`. That confirms the package compiles; it confirms
   nothing about runtime behavior — no run has actually shown an
   `NSStatusItem`, polled a real `karstd`, or exercised the parser against
   live output. `.github/workflows/ci.yml`'s `macos` job still does not
   build this package (see its existing coverage — build, unit tests, the
   `macos_pair` suite, package build — none of which is a GUI target); folding
   the new workflow into it, or promoting it from ad hoc check to real gate,
   is undecided. Remaining, in order: exercise it against a running `karstd`
   on real hardware; wrap the executable in a real `.app` bundle with
   codesigning (the existing `scripts/build-macos-pkg.sh` pattern for
   `karstd`/`karst` is the template); wire `dev.karst.karststatus.plist`
   (already written, also
   unverified) into `Distribution.xml`/`postinstall` as a second package
   component; and — deliberately not done yet — add
   `--status-socket /run/karst-status/karstd.sock` to
   `dev.karst.karstd.plist`'s `ProgramArguments`, which should land together
   with a working app, not before: the flag is opt-in so a Linux server
   upgrade never silently starts exposing peer endpoints to every local
   user, and turning it on in the shipping installer with no consumer yet
   built would spend that opt-in for nothing.
2. ~~**Throughput counters** in `karstd`, exposed through `Command::Status` or
   a new IPC verb, sampled and differenced client-side (or server-side, if a
   rate is more useful than a running total — decide against how
   `08-observability.md`'s existing metrics already choose to report rate
   vs. counter, for consistency).~~ **Done.** Landed as `PeerStatus::tx_bytes`/
   `rx_bytes` over the existing `Command::Status` verb, cumulative like every
   other counter in `Engine::Stats` — see §1.
3. **Icon/indicator states**, at minimum: no daemon running, daemon running
   with no peers established, one or more peers established (direct),
   established via relay/TURN (per `PeerStatus::transport` — this distinction
   already exists and a status indicator that collapses it back into a single
   "connected" state would be throwing away information the daemon already
   worked out), and a throughput sparkline or numeric readout. **Drafted** in
   `AppDelegate.swift`'s `render`/`throughputRate` — unverified along with
   the rest of item 1.
4. **Accessibility.** PLAN.md §8.3 sets the bar for the console: "no
   color-only status encoding (a red/green dot for connection state fails
   colorblind users — pair with shape and text)." Nothing in PLAN.md scopes
   that rule to the console specifically; apply it here too rather than
   re-deriving it (or forgetting it) for a native client. **Drafted**
   alongside item 3 — glyph and text together, everywhere a state is shown.

## 3. Exit criteria (informal — this item has no formal gate)

- The menu-bar app shows, at a glance: whether `karstd` is running, whether
  at least one peer is established, whether the mesh path is direct or
  relayed, and current throughput.
- No state is color-only.
- Killing `karstd` (`SIGKILL`-equivalent) is reflected within a few seconds,
  not left showing a stale "connected" state.
