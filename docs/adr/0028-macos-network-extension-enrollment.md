<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-0028: NetworkExtension enrollment — the invitation crosses the app↔extension boundary, not the identity

- **Status:** Proposed
- **Date:** 2026-09-16
- **Deciders:** Adrian Anderson (project owner)
- **Related:** ADR-0027 (the `sendProviderMessage`/`handleAppMessage` channel
  this reuses, and the enrollment gap it explicitly left open), ADR-0026
  (macOS NetworkExtension backend), ADR-0022 (mobile TUN backend and the
  UniFFI boundary this assumes), `bins/karstd/src/enrollment.rs` and
  `bins/karstd/src/setup.rs` (today's LaunchDaemon-build enrollment, which
  this compares against)

---

## Context

ADR-0027 named this gap without solving it: `sendProviderMessage` needs a
loaded `NETunnelProviderManager` to call it on, and nothing creates one
today. This ADR is that design.

**What enrollment does today, precisely — not from memory but from the code.**
`bins/karstd/src/enrollment.rs`'s `Bundle` is a `karst-invite-v1:`-prefixed,
base64url-encoded JSON envelope: `{server, server_kem_pin, server_verify_pin,
setup_key, control_minimum_version}`. It is short-lived, single-use bearer
material — `config.rs`'s own doc comment calls `setup_key` "Pre-shared auth
key for the first registration only" — never the node's long-term identity.
`sudo karst enroll --bundle FILE` (or `karst-setup`'s guided stdin flow) reads
it, performs the actual registration handshake against the control plane, and
writes two things to disk as root: `/etc/karst/karstd.toml` and the 64-byte
private key seed `identity_key_file` points at. `karstd`, started separately
by the service manager, reads both on its own next launch. The invitation
is consumed and gone; the identity it produced is what persists.

**Two facts, verified against Apple's own documentation and developer forum
answers rather than assumed by analogy with the LaunchDaemon build, change
what "the same shape" can mean here:**

- **A `NEPacketTunnelProvider` System Extension runs as root; the container
  app runs as the logged-in console user.** These are different Unix users.
  Keychain Access Groups and App Group shared containers both share state
  between processes running *as the same user* — neither bridges this
  boundary. This is not this project's guess: it is Apple DTS's own answer on
  their developer forums to exactly this question ("your app and your sysex
  run as two different users… keychain access groups allow you to share
  items between two programs running as the same user, not across users").
  **A shared-Keychain design for host-app-to-extension enrollment is
  therefore not merely undesirable, it does not work, structurally**, for a
  System Extension specifically — the same forum thread notes an App
  Extension (not what ADR-0026 chose) does not have this problem, which is
  exactly the trade ADR-0026 §3 already named and accepted for other reasons
  (surviving logout, running as machine infrastructure).
- **`NETunnelProviderProtocol.providerConfiguration` is the one channel the
  OS itself persists and hands to the extension at connect time**, but
  Apple's own guidance is explicit that it is not where secrets belong.
  Their Developer Technical Support's own suggested workaround — XPC the
  credential to the sysex, have the sysex store it in the (root) keychain,
  and pass back an opaque handle through `providerConfiguration` — confirms
  the shape (the sysex must be the one to receive and store the secret) while
  adding a handle-indirection step Karst does not need, for the reason below.

**Karst already has a simpler answer than the handle-indirection DTS
describes, because it already has a fixed, well-known identity file location
per host rather than a keychain item to hand a reference to.** The extension
runs as root, exactly as `karstd` does today; there is nothing stopping it
from writing the same 64-byte seed to the same kind of root-owned file
`identity_key_file` already names, the moment it finishes an enrollment
handshake it performed itself. No handle needs to travel back through
`providerConfiguration` if the extension never has to tell anyone else where
it put the secret — it just needs to find the same path again on its own next
launch, exactly as `karstd` already does.

## Decision

1. **The `NETunnelProviderManager` is created and saved before enrollment can
   begin at all.** `Karst.app`'s "Setup (Network Extension)…" flow first builds
   a minimal `NETunnelProviderProtocol` — `providerBundleIdentifier` naming
   the extension, `serverAddress` and a `providerConfiguration` carrying only
   non-secret bootstrap fields (the control-plane URL; nothing else needs to
   exist before an identity does) — and calls
   `NETunnelProviderManager.saveToPreferences`. This is the one step with no
   analogue in today's flow: `sudo karst enroll` never has to ask the OS to
   remember a VPN configuration exists, because there is no VPN
   configuration object in the LaunchDaemon model at all.
2. **The invitation crosses via `sendProviderMessage`, as an `"enroll"`
   message carrying the same `karst-invite-v1:` envelope already pasted into
   `karst-setup` today** — unparsed by the host app, exactly as
   `read_invitation` in `setup.rs` already refuses to look inside it beyond
   size-checking. The host app is a courier for bytes it cannot use, the same
   posture it already has today.
3. **The extension performs the actual enrollment handshake itself**, once
   the linked Rust core (ADR-0022's UniFFI boundary) can be called from
   inside it — reusing `enrollment::enroll_invitation`'s existing logic, not
   a reimplementation, since parsing and validating `Bundle` has nothing
   platform-specific about it. On success, it writes the resulting identity
   seed to a root-owned file at a fixed path this project already has a name
   for — `/etc/karst/identity.key`, or the NE build's own equivalent under
   `/Library/Application Support/Karst/`, decided when item 7's packaging
   work picks the NE build's directory layout — and reports success or a
   safe, non-secret-bearing error string back through the response callback,
   the same "never echo the credential" rule `parse_invitation` already
   follows.
4. **`startTunnel` reads that file on every subsequent launch**, exactly as
   `karstd::config::load_keys` already does for the LaunchDaemon build. An
   unenrolled extension (no file yet) fails `startTunnel` with a clear
   "not enrolled" error, mirroring `from_stdin`'s `resume` branch's existing
   "No usable saved device configuration. Enroll this device first."
5. **`karst-setup`'s bash script and today's `AppDelegate.swift` Setup flow
   are not reused for the NE build.** They assume a config file the caller
   can write directly for a LaunchDaemon to notice on its own next start,
   which has no counterpart here. This is a second enrollment code path to
   maintain, not a portable one — the same already-accepted cost ADR-0026
   item 8 names for shipping two builds indefinitely.

### Alternatives rejected

- **A Keychain Access Group shared between `Karst.app` and the extension.**
  Not rejected on preference — rejected because it does not work, per Apple's
  own DTS answer: the two processes run as different Unix users, and access
  groups share only within one user's keychain.
- **An App Group shared container carrying the identity file.** Same
  root-versus-console-user boundary, same source, same conclusion.
- **The long-term private key traveling through `providerConfiguration`,**
  written there by the host app after generating it itself. Rejected on two
  independent grounds: Apple's own guidance says not to put secrets there,
  and generating the key in `Karst.app` at all would mean the one process
  most likely to appear in a user's crash report or screen recording is the
  one briefly holding the node's long-term private key — worse than today's
  LaunchDaemon build, where only `karstd` itself ever does.
- **Apple DTS's full handle-indirection pattern** (XPC the secret to the
  sysex, sysex stores it, hands back an opaque `providerConfiguration`
  handle). Adopted in spirit — the sysex is the only place the secret is
  received and stored — but the handle round-trip is unneeded machinery here:
  Karst's one-identity-per-host model already gives the extension a fixed
  path to find its own secret again, so there is nothing for a handle to
  reference that a well-known path doesn't already say more simply.
- **Keeping `sudo karst enroll` as the NE build's enrollment path**, with the
  extension only ever reading what it wrote. Rejected as the *primary* path:
  it requires Terminal and admin, which a Mac App Store app is not permitted
  to ask a user to do, and unblocking the App Store SKU is ADR-0026's whole
  reason for this workstream (`plans/phase-5/06-macos-client.md`'s "On the
  App Store" section). It may still be worth keeping as a fallback for a
  Developer-ID-only NE build with no App Store ambitions — not decided here.

---

## Consequences

### Positive

- No secret ever crosses the root/console-user boundary that made Keychain
  and App Group sharing structurally unavailable — the identity is generated
  where it is used and stays there, which is a stronger property than either
  rejected alternative could have offered even if they had worked.
- Reuses `enrollment.rs`'s existing envelope parsing and validation rather
  than a second implementation of `karst-invite-v1:` — one parser, one
  Base64/JSON/version-check surface to keep correct, matching this project's
  general reluctance to duplicate anything with a wire format.
- The identity file's shape and the "not enrolled yet" failure mode are
  unchanged in kind from the LaunchDaemon build, which should make review of
  the extension's enrollment code easier for whoever already knows the
  original.

### Negative

- **Item 4 above (this ADR) still cannot ship until ADR-0027's own open
  question is answered**: whether `sendProviderMessage` reaches a System
  Extension that has never had an active tunnel session. Enrollment is the
  *first* caller that needs this to be true — unlike ordinary status polling,
  which only ever happens after a successful connect, enrollment's message
  has to reach the extension before anything has connected at all. If it
  cannot, the fallback is to perform enrollment inside `startTunnel` itself
  (triggered by a `providerConfiguration` flag meaning "enrolling, not
  connecting"), which this ADR does not fully design and would need its own
  pass if the primary path turns out not to work.
- **Whether a Developer-ID-signed (non-Mac-App-Store) System Extension is
  additionally sandboxed in a way that blocks writing to `/etc/karst/` or
  `/Library/Application Support/Karst/` is asserted from general knowledge of
  how Developer ID system extensions run, not verified against a real
  build.** If it is, the fallback is the extension's own
  `/Library/SystemExtensions/<uuid>/…` container path — still root-exclusive
  and equally private, just not the literal path the LaunchDaemon build uses,
  and `karst status`/support tooling that currently assumes
  `/etc/karst/identity.key` would need to know which build it is talking to.
- A second enrollment UI/flow to build and maintain in `Karst.app`, on top of
  `karst-setup`'s existing one — real, uncosted Swift and UI work this ADR
  does not estimate, matching ADR-0026 item 5's own honesty about the size of
  what remains.
- This ADR assumes ADR-0022's UniFFI boundary exists so the extension can
  call `enrollment::enroll_invitation` in-process. It does not: ADR-0022
  states plainly that the binding crate is not built yet. Nothing here can
  be exercised until that exists, which is true of every remaining item in
  ADR-0026's sequence, not a new limitation this ADR introduces.

### Reconsider if

- A real build shows `sendProviderMessage` cannot reach a never-connected
  extension — switch to the `startTunnel`-performs-enrollment fallback named
  above.
- A real build shows a Developer-ID system extension is sandboxed against
  `/etc/karst/` — switch to the extension's own container path, and update
  every place that currently hard-codes `/etc/karst/identity.key` to ask
  which build it is instead of assuming the LaunchDaemon's layout.
- Karst ever needs more than one identity per host (multiple concurrent
  profiles) — the fixed-well-known-path model this ADR chose specifically
  because Karst has never needed that would need to become the handle-based
  `providerConfiguration` scheme this ADR rejected as unneeded machinery for
  today's one-identity-per-host reality.
