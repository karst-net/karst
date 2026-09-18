<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-0026: macOS NetworkExtension backend — a second `Tun` behind a build feature, not a replacement

- **Status:** Proposed
- **Date:** 2026-09-16
- **Deciders:** Adrian Anderson (project owner)
- **Related:** ADR-0022 (mobile TUN backend — the fd-adoption shape and
  `macos_wire` framing this extends), ADR-0003 (`unsafe` confined to `sys*`
  modules), ADR-0017 (Windows TUN provider — precedent for a platform ADR
  living beside the phase plan rather than only in it),
  `plans/phase-5/06-macos-client.md` §3 (the LaunchDaemon-not-NetworkExtension
  decision this reconsiders, not reverses), `plans/phase-6/13-macos-status-indicators.md`
  (`Karst.app`/`KarstStatus`), GitHub issues #111, #113

---

## Context

`plans/phase-5/06-macos-client.md` §3 already decided this once: a
`NEPacketTunnelProvider` needs the
`com.apple.developer.networking.networkextension` entitlement, Apple grants it
by application with a review turnaround measured in weeks and no committed
SLA, and making that Phase 5's critical path would put the exit criterion
behind someone else's queue. `packaging/macos/dev.karst.karstd.plist` carries
the same reasoning verbatim in its own header comment — this tree documents
the decision twice, not once. §3 also said to file the entitlement
application anyway, in Week 1, as paperwork alongside the certificates. **The
tree contains no record of whether that filing ever happened** — not in the
plan's closure notes, not in a commit, not in an ADR. That is the one
dependency this project cannot control the timeline of, and it is still open.

A suggestion proposing a full migration to `NEPacketTunnelProvider` was pasted
into this session from an external source with no access to this repository.
Its cost/benefit analysis of NetworkExtension versus a LaunchDaemon is broadly
sound and agrees with Apple's own published steer away from ad hoc routing
manipulation, but two things in it were invented rather than sourced, and two
real gaps it named are worth separating from the rest:

- It guessed a LaunchDaemon label (`net.karst.karstd`) and binary path. The
  real ones, from `packaging/macos/dev.karst.karstd.plist`, are
  `dev.karst.karstd` and `/usr/local/bin/karstd --config /etc/karst/karstd.toml
  --status-socket /var/run/karst-status/karstd.sock`. Any Jamf/`mobileconfig`
  work should use these, not the placeholders.
- It independently re-derived a "Swift host app + Rust core via FFI, system
  extension not app extension" architecture. That is not a new idea for this
  codebase: ADR-0022 (2026-09-13, three days before this one) already
  committed to exactly that shape for iOS and Android —
  `crates/karst-tun/src/mobile.rs`'s `Tun::from_fd` adopts a platform-supplied
  fd and reuses `macos_wire::{af_header, family_agrees}` for the framing.
  ADR-0022's own context section already states that **iOS's `packetFlow` fd
  is a `utun` socket under the hood**, reached through a private but stable
  `socket.fileDescriptor` KVC lookup. A macOS System Extension's `packetFlow`
  is the same kernel primitive reached the same way — there is no new framing
  problem here, only a new caller of code that already exists and is already
  tested.
- It correctly identifies that `karstd` lacks a machine-readable health
  surface for MDM to poll. Checked directly against `bins/karstd/src/ipc.rs`
  and `run.rs`: `Command::Status` returns the same plain text
  `packaging/macos/KarstStatus/Sources/KarstStatus/StatusParser.swift` parses.
  There is no `--json` mode today. This is a real, verified gap, not a
  speculative one.
- It does not know that `packaging/macos/KarstStatus` already ships as
  `Karst.app` — an `LSUIElement` accessory bundle
  (`packaging/macos/KarstStatus/Info.plist`, `CFBundleIdentifier
  dev.karst.karststatus`) installed by a per-user LaunchAgent
  (`dev.karst.karststatus.plist`), with a working AppKit shell and an
  established IPC pattern (`StatusClient.swift`) to `karstd`. That is the
  literal host-app seed the suggestion describes needing to build from
  scratch.

Its Jamf/MDM portion (a `com.apple.servicemanagement` profile pinning the
LaunchDaemon label, plus a policy that checks `launchctl print` and remediates)
is orthogonal to all of the above. It is correct as described, it targets the
LaunchDaemon that exists today, and it does not block on or get displaced by
anything in this ADR.

## Decision

Add NetworkExtension as an **additional** macOS backend, selected by a build
feature rather than replacing the LaunchDaemon path, sequenced so only the one
step actually gated on Apple's queue is treated as gating:

1. **File, or confirm already filed, the
   `com.apple.developer.networking.networkextension` entitlement application
   now**, in parallel with everything below. It is the only item here with a
   timeline this project doesn't control, exactly as §3 already found — every
   other step can proceed without it, up to the point of a real signed
   extension actually loading.
2. **`karst-tun`:** add a macOS System Extension variant of the existing
   fd-adoption backend. `target_os` alone can't select it the way it does for
   iOS/Android, because `target_os = "macos"` already has a full backend
   (`macos::Tun`, which creates its own `utun` and needs root) — both would
   compile for the same triple. Gate the new one behind a Cargo feature (e.g.
   `network-extension`) instead, and reuse `macos_wire`'s framing verbatim,
   the same way `mobile.rs` already does for iOS.
3. **No address/route work in this variant.** `NEPacketTunnelNetworkSettings`
   owns addressing and routing, the same as it already does for the two
   mobile backends under ADR-0022. This removes the `ifconfig`/`route`
   shell-out from `macos.rs` for this build only — the LaunchDaemon build
   keeps it, since it still needs to assign addresses itself.
4. **`karst-dns`:** add `host_integration = "network-extension"` as a third
   `HostRuntime` variant beside `"macos"` (the `/etc/resolver` one), routing
   DNS through `NEDNSSettings` instead of resolver files. Extend the existing
   seam; don't special-case NE inside `host/macos.rs`.
5. **Grow `Karst.app`** (today `packaging/macos/KarstStatus`) into the host
   app for a `PacketTunnelProvider` System Extension — a system extension, not
   an app extension, so it survives logout and runs as machine infrastructure
   the way the LaunchDaemon already does, which is also the pasted
   suggestion's own reasoning and the right one. The host-app-to-extension IPC
   needs its own design: today's plain Unix status socket pattern does not
   carry over unmodified into a sandboxed extension. **Decided in
   ADR-0027**: `NETunnelProviderSession.sendProviderMessage`, carrying the
   same JSON `status_json()` already produces — that ADR also names what it
   does *not* settle (enrollment, and the DNS variant's outbound direction).
6. **Add `karst status --json` (and consider `karst health`) to `karstd`'s IPC
   surface now, independent of the rest of this ADR.** It is the correct
   primitive for the Jamf health-check half of the pasted suggestion, which
   can and should ship against the LaunchDaemon that exists today, and it is
   also what a `NETunnelProviderManager`-based `Karst.app` will want to poll
   once item 5 exists.
7. **Packaging:** a signed system-extension bundle needs a pipeline sibling to
   `scripts/build-macos-pkg.sh` — the system-extension entitlement,
   notarization, and system-extension activation/approval (gated by an MDM
   profile or interactive user approval). Budget it the way phase-5 §7 budgeted
   signing generally: expect the first activation attempt to fail and plan for
   two rounds.

   **Verified on real hardware (#159), and it took more than signing and
   notarization to get there.** Item 1's entitlements
   (`com.apple.developer.system-extension.install`,
   `com.apple.developer.networking.vpn.api`,
   `com.apple.developer.networking.networkextension`) turned out to be
   self-service in the current Developer Portal for this account — no
   special request needed, contrary to this item's own original assumption.
   But a build signed with real Developer ID certificates *and* successfully
   notarized still refused to launch on the actual Mac, rejected by AMFI with
   "No matching profile found": restricted entitlements need a **provisioning
   profile** embedded in the bundle (`Contents/embedded.provisionprofile`),
   generated in the Developer Portal per App ID as the "Developer ID" profile
   type (not "Mac App Distribution", which is for the App Store) — a
   requirement independent of, and in addition to, signing and notarization.
   `scripts/build-macos-pkg.sh` now embeds one for `Karst.app` and one for the
   packet-tunnel system extension when `KARST_PROVISION_PROFILE_KARSTSTATUS`/
   `KARST_PROVISION_PROFILE_PACKETTUNNEL` are set (`APPLE_PROVISION_PROFILE_*`
   in CI, decoded the same way `APPLE_CERT_P12`/`APPLE_NOTARY_KEY` already
   are). Unlike notarization, profile embedding is not tag-gated: it applies
   to every signed build, because AMFI's rejection has nothing to do with
   whether the build was notarized.
8. **Ship both, indefinitely, not just during a transition.** The LaunchDaemon
   `.pkg` stays the default for direct/enterprise installs: it carries no
   entitlement risk, and it is the only path that backs Bedrock's
   cryptographically enforced network lock unconditionally — NetworkExtension's
   `includeAllNetworks` is real and relevant, but it is a routing feature, not
   a replacement for Bedrock's guarantee, which is the pasted suggestion's own
   correct point. The NE variant is additive, aimed at unblocking
   `scripts/appstore-submit-macos.sh` and at fleets that specifically want
   native VPN-On-Demand / Jamf-managed VPN state instead of the current
   process-health inference.

### Alternatives rejected

- **Replacing the LaunchDaemon once NE ships.** Rejected: it would reintroduce
  the exact risk §3 avoided — Apple's review queue on the critical path — for
  every install, forever, not only for the App Store SKU that actually needs
  it.
- **Re-deriving fd-adoption/framing independently for macOS** instead of
  extending `mobile.rs`. Rejected for the same reason ADR-0022 rejected it for
  iOS versus `macos_wire`: it is the same kernel primitive carrying the same
  bytes, and a third implementation is a third place for it to drift.
- **Deferring the Jamf/`servicemanagement` enforcement profile until the NE
  variant exists.** Rejected: the gap is real today, the LaunchDaemon is what
  is actually deployed, and the profile only needs the real `dev.karst.karstd`
  label to ship this week.
- **Treating `Karst.app` as a new app to design.** Rejected: it already exists
  as that bundle (`LSUIElement`, an established IPC pattern to `karstd`) —
  grow it, don't duplicate it.

---

## Consequences

### Positive

- Unblocks `scripts/appstore-submit-macos.sh` and the `app-store` CI stub for
  real, per `plans/phase-5/06-macos-client.md`'s "On the App Store" section.
- Reuses tested code — ADR-0022's fd adoption and `macos_wire` framing —
  instead of a third independent implementation of the same wire format.
- `karst status --json` (item 6) is a small, decoupled win that ships
  immediately and improves the MDM story regardless of how the rest of this
  ADR resolves.

### Negative

- **The entitlement-timeline risk §3 already named is now actually on the
  schedule rather than deferred paperwork.** If Apple never grants it, or
  delays past whenever this is next prioritized, the App Store variant simply
  does not ship — but nothing else here is lost, since the LaunchDaemon path
  is unaffected by that outcome.
- Two macOS backends behind a build feature is a second thing to keep
  correct. A bug in `macos::Tun`'s address/routing logic has no counterpart to
  fix in the NE variant (correct — NE doesn't do that work), but a bug in the
  shared framing (`macos_wire`) is now load-bearing for three consumers (iOS,
  and now two macOS build variants) instead of two.
- The host-app/extension IPC redesign (item 5) and the packaging pipeline
  (item 7) are both real, uncosted work. This ADR decides the
  `karst-tun`/`karst-dns` shape underneath them; it does not decide those, and
  should not be read as "the macOS NE client exists" — the same caveat
  ADR-0022 states for mobile.
- Nothing here can be exercised end-to-end without the entitlement actually
  being granted. Compilation and feature-gated unit tests can run without it
  (the same limit ADR-0022's `mobile-tun` CI job already accepts), but a real
  system-extension activation cannot.

### Reconsider if

- The entitlement application is filed and comes back declined, or with
  restrictions incompatible with how this project is packaged.
- Apple changes or removes the private `packetFlow.socket.fileDescriptor` KVC
  path — ADR-0022 already names this risk for iOS; it now has a second
  consumer.
- Measuring `karstd`'s actual memory/lifecycle footprint inside a real System
  Extension's constraints shows the "small, stable, non-blocking" bar the
  pasted suggestion names can't be met without splitting more out of the
  extension than item 5 currently scopes.
