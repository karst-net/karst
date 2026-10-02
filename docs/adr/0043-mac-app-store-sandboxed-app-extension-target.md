<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-0043: Build the sandboxed App Extension target for Mac App Store distribution

- **Status:** Proposed
- **Date:** 2026-10-02
- **Deciders:** Adrian Anderson (project owner)
- **Related:** ADR-0040 (the sandboxed-App-Extension requirement this
  implements), ADR-0026/0027/0028 (the Developer-ID System Extension this is
  a sibling to), ADR-0029/0030 (`karst-ffi`, reused as-is), GitHub issue #210

---

## Context

ADR-0040 (Accepted) established that the Mac App Store cannot accept
`Karst.app`/`KarstPacketTunnel` as they exist today — that is a Developer-ID
**System Extension** (`OSSystemExtensionRequest`, unsandboxed, the
`-systemextension`-suffixed NetworkExtension entitlement). The Store requires
the same `NEPacketTunnelProvider` extension point packaged as an **App
Extension** (`.appex`, embedded in a sandboxed container app,
`com.apple.security.app-sandbox`, the standard non-suffixed entitlement
value), and scoped that as its own follow-up (item 3). Issue #210, split from
#168, is that follow-up.

No Apple Developer Program **Mac App Store** certificates, App ID, or
provisioning profiles exist in this environment. `KarstPacketTunnel`/
`KarstStatus` were in the identical position when first written — their own
header comments say so — and this target follows the same precedent: real
code, reviewed against Apple's App Extension/App Sandbox documentation, and
compiled/tested by `.github/workflows/macos-appextension-swift-build.yml` on
a real macos-14 runner, but not verified end to end (install, sandbox
activation, real traffic) against real hardware or real Store Connect
credentials.

## Decision

1. **A new, independent pair of SPM packages**:
   `packaging/macos/KarstPacketTunnelAppExtension` (the sandboxed
   `NEPacketTunnelProvider`) and `packaging/macos/KarstAppStore` (its
   container app), each with its own `Package.swift`, rather than extracting
   a shared library out of `KarstStatus`/`KarstPacketTunnel`. Matches the
   existing architecture exactly — `KarstStatus` and `KarstPacketTunnel`
   already share zero Swift source — and keeps this change from touching
   anything in the already-shipping Developer-ID build path. The small
   amount of logic both channels need (`NetworkExtensionEnrollment`-shaped
   code, the generated `karst-ffi` Swift bindings) is duplicated, not shared.

2. **New, distinct bundle identifiers**: `dev.karst.appstore` (host app) and
   `dev.karst.appstore.packettunnel` (extension) — separate Developer Portal
   App IDs from `dev.karst.karststatus`/`dev.karst.packettunnel`, so the two
   distribution channels' entitlement configurations never need to coexist
   on one App ID.

3. **State lives in an App Group container
   (`group.dev.karst.appstore`), not a root-owned path.**
   `KarstPacketTunnel/PacketTunnelProvider.swift`'s own `stateDir` doc
   comment explains why an App Group would not bridge a System Extension
   (root) and its host app (console user) — that reasoning does not apply
   here: a sandboxed App Extension and its host app run as the *same*
   console user, so an App Group container is the correct mechanism, not a
   repeat of that earlier rejected idea. `karst-ffi`'s `EngineHandle` needed
   no change for this — ADR-0040 already confirmed it takes a config path,
   socket path, and raw fd, nothing System-Extension-specific — only the
   literal path strings passed to it differ.

4. **Minimal viable scope for this pass**: enroll/status/quit only.
   `handleAppMessage` answers `status`/`enroll`/`re-enroll`/`identity`, not
   `exit-use`/`exit-disable`; the host app's menu has no exit-node submenu
   and no managed-device-ownership banner. Per ADR-0040 item 4, the App
   Store build does not need managed-device/MDM coexistence at all, and
   exit-node parity is real, separable follow-up work, not foundational to
   proving the sandboxed target activates and enrolls at all — the same bar
   `KarstPacketTunnel`/`KarstStatus` themselves had to clear first
   (ADR-0026/27/28) before exit-node/managed-device features were layered on
   top. The lab's root-owned-file unattended-enrollment path
   (`enrollFromPendingInvitation`) is dropped entirely: it has no sandboxed
   equivalent and nothing here needs it.

5. **A sibling packaging script and CI job, not a mode flag on the existing
   ones.** `scripts/build-macos-appstore-pkg.sh` mirrors
   `scripts/build-macos-pkg.sh`'s shape (per-arch build, codesign, pkgbuild/
   productbuild) but differs in nearly everything: the `.appex` stages at
   `Contents/PlugIns/`, not `Contents/Library/SystemExtensions/`; signing
   uses an "Apple Distribution"-type identity, not "Developer ID
   Application"; there is no notarization step (Store submissions go
   through App Review instead); there is no `karst` CLI or LaunchAgent
   component (no exit-node menu to need either, per item 4). Folding these
   into one script with a mode flag would make every difference
   conditional, which is harder to read than two scripts sharing a shape.
   `.github/workflows/deliverables.yml`'s `macos-appstore-package` job
   builds it unsigned (no App Store certificates exist yet) and verifies
   the bundle layout on a real macos-14 runner; `app-store` now downloads
   that artifact instead of the Developer-ID one.

### Alternatives rejected

- **Reusing `dev.karst.karststatus`/`dev.karst.packettunnel` for both
  channels.** Rejected: it is unclear whether Apple's Developer Portal
  cleanly supports one App ID carrying both the standard and
  `-systemextension`-suffixed NetworkExtension entitlement values for two
  different distribution mechanisms, and getting it wrong risks the
  already-working Developer-ID build. Two App IDs costs nothing but a
  second registration.
- **Full feature parity (exit-node menu, managed-device banner) in this same
  pass.** Rejected as premature: most of it cannot be verified anyway
  without real Store Connect credentials, and the Developer-ID build itself
  was built incrementally across three ADRs before these features existed.
  Scoped as explicit, named follow-up work instead of attempted and left
  half-verified here.
- **Flipping `KARST_APPSTORE_READY` now that a real artifact exists.**
  Rejected: the flag exists to gate *verified* readiness, not merely
  *existing* code — nothing in this pass has installed, activated, or
  enrolled the artifact on real hardware.

---

## Consequences

### Positive

- Issue #210 / ADR-0040 item 3 gets a real, built artifact rather than
  remaining a scoped-out follow-up indefinitely.
- `karst-ffi`'s NE-agnostic design (ADR-0029/0030) is exercised a second
  time, by a genuinely different consumer (sandboxed vs. root), reinforcing
  that no NetworkExtension-packaging-specific assumptions leaked into it.
- The next person with real Mac App Store credentials has a concrete
  artifact and CI job to verify against, not a from-scratch target to build
  under release pressure.

### Negative

- **Real-hardware/real-credential verification remains entirely open.**
  Sandbox activation, App Group container resolution, enrollment, and
  packet flow are all unverified — stated honestly rather than assumed, the
  same "written and reviewed, not run" limitation ADR-0029/0030 already
  carry. This is the natural next follow-up once Mac App Store credentials
  exist, the same shape as the Developer-ID build's own history (ADR-0026
  item 1's entitlement application, then real-hardware fixes in #159/#161).
- **Feature parity with the Developer-ID build is a real, separate gap**,
  not a checklist item on top of this: exit-node consent and
  managed-device-ownership UI do not exist on this target at all yet.
- Two bundle identifiers, two entitlements files, two packaging scripts, two
  CI workflows to keep in sync with the Developer-ID build going forward —
  real, ongoing maintenance surface for shipping two channels of the same
  product.

### Reconsider if

- A future pass actually builds and tests this target end to end against
  real Mac App Store certificates and provisioning profiles — this ADR's
  design (App Group choice, bundle IDs, minimal scope) is reasoned from
  reading Apple's documentation and the existing Developer-ID code, not from
  running a real, installed, sandboxed extension.
- Feature parity work (exit-node, managed-device UI) is picked up: at that
  point, re-evaluate whether the "new independent packages, duplicated
  logic" choice (item 1) still holds, or whether the duplicated surface has
  grown large enough that a shared library is worth the coupling risk it
  was rejected for here.
