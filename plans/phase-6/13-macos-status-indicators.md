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
  (`bins/karstd/src/engine.rs:2204`) carries `established`, `rekeying`,
  `endpoint`, and `transport` (direct / relayed / TURN — deliberately not a
  bool, per the field's own doc comment: a relayed peer works, but slower and
  through a third party, and that distinction matters to a user asking "why
  is this slow"). `Command::Status` (`bins/karstd/src/ipc.rs`) already
  returns this over the daemon's local control socket, and `run.rs:3479`
  is the existing handler. A menu-bar app polling or subscribing to this
  socket gets connectivity for free.
- **Throughput data does not exist anywhere.** `grep -rn "bytes_sent\|bytes_received\|throughput"`
  across `bins/karstd/` and `crates/karst-transport/` returns nothing but a
  doc comment. Before any indicator can show throughput, `PeerStatus` (or a
  new per-session counter alongside it) needs byte/packet counters — this is
  new plumbing in `engine.rs`'s per-session accounting and the transport
  read/write paths, not just a UI change. Scope this as its own line item
  when estimating; it is not free the way connectivity is.
- **The control socket is already local-only and unauthenticated-by-proximity**
  (Unix domain socket, filesystem permissions), which is the right model for
  a per-user menu-bar app talking to a root daemon — no new IPC mechanism is
  needed, only a client.

## 2. Shape of the work

1. **A menu-bar app**, most simply an `NSStatusItem`-based AppKit or SwiftUI
   app, distinct from `karstd` — it runs in the user's GUI session, `karstd`
   does not (it is a `LaunchDaemon`, not a `LaunchAgent`, and has no GUI
   session to run in). Packaging (`packaging/macos/`) needs a second bundle
   and, if it should launch at login, a `LaunchAgent` plist alongside the
   existing `dev.karst.karstd.plist` `LaunchDaemon` one.
2. **Throughput counters** in `karstd`, exposed through `Command::Status` or
   a new IPC verb, sampled and differenced client-side (or server-side, if a
   rate is more useful than a running total — decide against how
   `08-observability.md`'s existing metrics already choose to report rate
   vs. counter, for consistency).
3. **Icon/indicator states**, at minimum: no daemon running, daemon running
   with no peers established, one or more peers established (direct),
   established via relay/TURN (per `PeerStatus::transport` — this distinction
   already exists and a status indicator that collapses it back into a single
   "connected" state would be throwing away information the daemon already
   worked out), and a throughput sparkline or numeric readout.
4. **Accessibility.** PLAN.md §8.3 sets the bar for the console: "no
   color-only status encoding (a red/green dot for connection state fails
   colorblind users — pair with shape and text)." Nothing in PLAN.md scopes
   that rule to the console specifically; apply it here too rather than
   re-deriving it (or forgetting it) for a native client.

## 3. Exit criteria (informal — this item has no formal gate)

- The menu-bar app shows, at a glance: whether `karstd` is running, whether
  at least one peer is established, whether the mesh path is direct or
  relayed, and current throughput.
- No state is color-only.
- Killing `karstd` (`SIGKILL`-equivalent) is reflected within a few seconds,
  not left showing a stale "connected" state.
