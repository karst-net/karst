<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-0031: Managed-device mode — MDM-locked configuration and a best-effort kill switch

- **Status:** Proposed
- **Date:** 2026-09-19
- **Deciders:** TBD
- **Related:** ADR-0024 (names this exact scenario as its own "Reconsider
  if" trigger), ADR-0026 item 8 (already flags `includeAllNetworks`/
  kill-switch behavior as the one gap left by dropping the LaunchDaemon
  backend), ADR-0027 (macOS System Extension ↔ host app IPC is
  request/response only), ADR-0030 (embedded engine lifecycle — the
  mid-session route-churn gap this ADR's polling loop also closes),
  GitHub issues #158 (route-churn follow-up, closed by the FFI boundary
  this builds on), #160 (full-default-route handling — still open,
  documents the same fail-static gap), #162 (MDM-managed configuration
  detection — still open, this ADR extends its "still open" scope
  without closing it)

---

## Context

Two deployment scenarios need to coexist in the macOS client:

1. **Personal/admin.** A power user with local administrator rights
   installs Karst, enrolls via `Karst.app`'s "Enroll…" menu item, and can
   disconnect or remove it freely. This is what ships today.
2. **Managed/non-admin.** A DEP/ABM-supervised Mac where the device's
   daily user has no administrator rights. Karst must be installable,
   configurable, and removable only via MDM, and all traffic must go
   through the Karst tunnel — a fail-closed requirement, not "connected
   when possible."

ADR-0024 (Accepted) already answered a closely related question — "can an
administrator force a device's traffic through a route without the
device operator's consent?" — for the *personal/admin* case, and answered
no, on purpose: `spec/karst-control-v1.md` §5.4 requires local consent,
enforced by binding `karst exit-node use`/`disable` to a root-only
control socket. Its own "Where this genuinely does not reach" section is
explicit that this is a ceiling, not a gap:

> A device whose enrolled user also holds local administrator rights on
> it (a personally-owned, self-administered machine) can always run
> `exit-node disable` themselves. No client-side software — Karst or any
> competitor's — can prevent a local administrator from reconfiguring
> their own machine; achieving that requires device supervision/MDM,
> which is a different product than a VPN client and out of scope here.

And its "Reconsider if" section named exactly this scenario as the
trigger for a new ADR, not an amendment:

> Karst ever adds device supervision/MDM-style enrollment where the
> account, rather than the device's local operator, is the intended
> holder of ultimate control over a specific device (e.g., a
> company-owned, non-BYOD fleet with a different consent model by
> design). That is a materially different premise from every other actor
> boundary in `docs/USE-CASE-ANALYSIS.md` and would need its own ADR, not
> an amendment to this one.

This is that ADR. It does not reopen ADR-0024's decision for the
personal/admin case — that ceiling is reaffirmed below — it defines a
second mode where the premise genuinely differs, because on a supervised
device with no local admin account, there is no local operator in
ADR-0024's sense to override anything.

### Platform reality: macOS has no "can't be disabled" API

Checked directly, not assumed: macOS has no equivalent of iOS's
`OnDemandUserOverrideDisabled`, and no true Always-On VPN API at all —
confirmed against Apple's own configuration-profile reference and
multiple Apple Developer Forums threads reporting this exact gap.
Zscaler's own tamper-protection feature, the closest industry comparison,
is documented as Windows-desktop-only; on macOS, Zscaler (and everyone
else) relies on MDM: a locked configuration profile plus MDM-pre-approved
System Extensions, not client-side "can't be turned off" logic. So the
answer here has to be the same shape: MDM-delivered profile keys, not new
enforcement code inside `Karst.app` or `KarstPacketTunnel`.

For a third-party `NETunnelProviderManager`-backed VPN, Apple's
`com.apple.vpn.managed` profile payload supports exactly the keys this
needs: `ProviderBundleIdentifier` (targets this app's own
`dev.karst.packettunnel`), `IncludeAllNetworks` (routes all traffic into
the tunnel, no fallback route — the kill switch), `EnforceRoutes`,
`OnDemandEnabled`/`OnDemandRules` (auto-reconnect), and
`PayloadRemovalDisallowed` (removal requires an admin password the
device's daily user does not have). A sibling `SystemExtensions` payload
(`AllowedSystemExtensions`) pre-approves the extension so no interactive
"Allow" click is ever required. None of this needs new Karst code to
*exist* — it needs Karst's existing code to not fight it, and to make
`IncludeAllNetworks` actually mean something once the tunnel session is
under way, which is the real engineering gap below.

### The real engineering gap: no callback from engine to extension

`PacketTunnelProvider.networkSettings(fromStatusJSON:)` built its output
from a single `EngineHandle.statusJson()` snapshot taken once in
`startTunnel`. Its own doc comment already named the consequence: nothing
re-called `setTunnelNetworkSettings` if routing state changed later in
the same session — "fail-static, not a chosen kill-switch or fail-open
behavior." Issue #160's implementation comment states the same thing from
the other side, when the exit-route-as-default-route mapping shipped:

> This is a snapshot taken once, at the single `statusJson()` call
> `startTunnel` makes. Nothing re-invokes `setTunnelNetworkSettings` if
> the exit route's `active` state changes later in the same session...
> Once an exit route is installed it stays installed even after the
> engine itself would have withdrawn it — fail-static, not a deliberately
> chosen kill-switch or fail-open behavior.

`EngineHandleProtocol` (`Sources/KarstFFI/karst_ffi.swift`) exposes
exactly `statusJson() throws -> String` and `stop()` — confirmed by
reading the generated FFI bindings, not assumed missing. There is no
callback, delegate, or push channel from the embedded Rust engine back
into the Swift extension. Polling is the only mechanism available today.
For `IncludeAllNetworks` to mean anything beyond the instant `startTunnel`
first runs, the extension needs to notice when it's unhealthy and — this
is the important part — never respond to that by tearing the session
down, since ending the session is exactly what lets the OS fall back to a
route outside the tunnel.

### Issue #162 already tried, and correctly rejected, a weaker version of this

Issue #162 ("macOS: support MDM-managed (.mobileconfig) configuration —
no end-user enroll/re-enroll/quit") scoped exactly the UI-detection
question this ADR also touches, researched it, and made a deliberate,
recorded decision to scope down rather than ship a risky heuristic:

> The closest thing to established practice... treat "a manager already
> exists at launch for our provider bundle ID" as the signal to never
> call `saveToPreferences()`/`removeFromPreferences()` on it... That's a
> heuristic, not a documented contract... implementing menu-hiding/
> Quit-blocking on top of it risked locking a normal, non-MDM user out of
> enrolling entirely on a false positive. Scoped down instead: make
> config handling correct regardless of who owns a given configuration,
> skip the detection heuristic.

That decision — `ensureConfiguration` never mutates a manager it did not
create, full stop, no ownership detection — stands, unchanged, in this
ADR. What this ADR adds is a *different*, more precise heuristic (a
persisted marker, not "no prior call this app remembers in memory," which
survives relaunches the way #162's rejected version could not) used only
for an **informational** UI line, never to hide or disable anything — see
Decision below.

## Decision

Adopt a two-mode model, distinguished entirely by which entity owns the
`NETunnelProviderManager` configuration for `dev.karst.packettunnel` —
not by any new flag Karst's own code invents:

1. **Personal/admin mode (unchanged).** `NetworkExtensionEnrollment.ensureConfiguration`
   still creates its own per-user manager when none exists. New: that
   manager now also sets `isOnDemandEnabled = true` and
   `onDemandRules = [NEOnDemandRuleConnect()]` — reconnect-for-convenience
   only, no `IncludeAllNetworks`, so this changes nothing about who can
   disable the tunnel. ADR-0024's ceiling is reaffirmed, not reopened: an
   admin on this machine can always disable or remove Karst.
2. **Managed mode (new).** MDM pushes a `com.apple.vpn.managed` profile
   carrying the keys listed above, including `IncludeAllNetworks` and
   `PayloadRemovalDisallowed`. Karst's own code never sets
   `IncludeAllNetworks` itself, on any configuration, ever — its presence
   is entirely a fact about who owns the configuration, and only MDM
   should be able to make that true.
3. **One reassert mechanism serves both modes.** `PacketTunnelProvider`
   now runs a polling timer (`healthTimer`/`pollHealth()`, ~2s interval)
   that re-derives routing from `engine.statusJson()` and reapplies it
   when it changes. When the engine is unreachable, it sets
   `reasserting = true` and does nothing else — critically, it never
   calls `stopTunnel`/`cancelTunnelWithError`/
   `setTunnelNetworkSettings(nil)`, which would end the session and let a
   fallback route reopen. This is what makes an MDM-set
   `IncludeAllNetworks` meaningful in practice instead of only at the
   instant `startTunnel` first runs, and it is the same mechanism that
   closes the pre-existing mid-session route-churn gap (#158/#160) as a
   side effect, since both problems are "routing state went stale and
   nothing re-synced it."
4. **A UI-only ownership heuristic, informational only.** A `UserDefaults`
   marker, written only when `ensureConfiguration` actually creates a new
   manager, lets `AppDelegate` show "VPN configuration managed by your
   organization" when the current manager's ownership can't be confirmed
   as self-created. This never hides or disables Enroll/Re-enroll — #162
   already judged that stronger move too risky on a weaker heuristic than
   this one, and the failure mode (a personal user losing their own
   enroll controls on a false positive) is exactly the one to keep
   avoiding.
5. **Confirmed with the requester: strict fail-closed, no automatic
   safety valve.** If the tunnel cannot establish on a managed device,
   there is no timeout-based fallback to open networking. Recovery is via
   MDM/IT intervention only.

### Alternatives rejected

- **In-app detection that blocks disabling/removing a managed
  configuration.** Rejected for the same reason #162 already rejected a
  weaker version of it: there is no reliable, documented way to confirm a
  configuration is MDM-owned, so gating real functionality on a guess
  risks locking out a normal personal-mode user. The OS-level enforcement
  (`PayloadRemovalDisallowed`, no local admin account) does the actual
  blocking; Karst's code only needs to not fight it.
- **Karst setting `IncludeAllNetworks` itself on personal-mode
  configurations**, to approximate a kill switch without MDM. Rejected:
  this ADR's target is the non-admin managed case specifically. On a
  personal/admin machine, a local admin can always undo it (ADR-0024's
  ceiling), so shipping it there would be a false promise with no MDM
  backstop to make it real — worse than not having the feature, since it
  would look like a guarantee it isn't.
- **A push-based extension→app IPC channel** so the menu bar could show
  live kill-switch/reasserting state. Rejected for now: ADR-0027 already
  settled on request/response only ("The extension cannot push a state
  change to `Karst.app` between polls"), and reopening it is a larger
  change than this ADR needs — the app already polls status every 2
  seconds (`AppDelegate.pollInterval`), which is an acceptable latency for
  a status indicator, distinct from `pollHealth()`'s own, separate,
  faster poll running inside the extension.
- **Blocking "Quit" outright** (e.g. `applicationShouldTerminate`
  returning `.terminateCancel`), one of the questions #162 itself left
  open. Rejected: quitting `Karst.app` already does not stop the tunnel —
  the System Extension is an independent, root-owned process that
  survives the host app quitting, being force-quit, or even being
  uninstalled (`packaging/macos/uninstall.sh` documents this directly).
  Blocking Quit would add user-visible friction — an undismissable
  menu-bar icon — without adding any real enforcement, since the actual
  enforcement surface (the extension and the locked profile) is
  untouched either way.
- **Solving initial enrollment-invitation delivery to a non-admin managed
  device** as part of this ADR. Out of scope, noted honestly below rather
  than silently dropped — see Negative consequences.

## Consequences

### Positive

- Managed fleets get an MDM-enforced, non-removable configuration with a
  real (if bounded, see below) kill switch, without any change to how
  personal/admin installs behave.
- Personal-mode users get free on-demand reconnect as a side effect.
- Reuses #162's existing "never mutate a manager we didn't create"
  boundary rather than replacing it, and extends rather than reverses its
  UI-detection decision.
- The same polling mechanism that makes the kill switch meaningful also
  closes the pre-existing mid-session route-churn gap (#158/#160) for
  free.

### Negative

Be honest here, per this project's own template:

- **This is a best-effort, tight-window kill switch bounded by platform
  APIs — not an absolute guarantee against a determined local admin.**
  For the personal/admin ceiling, this ADR reaches no further than
  ADR-0024 already conceded — that is by design, not a gap. For the
  *targeted* managed case, two real limits remain even where no local
  admin exists to disable anything: (a) **whether `IncludeAllNetworks` is
  actually honored reliably for a third-party `NETunnelProviderManager`
  on current macOS versions has not been empirically verified on real
  hardware** — this is the single biggest assumption the whole design
  rests on, and it must be validated before this ships as a customer-
  facing guarantee, not assumed from Apple's documentation alone (this
  codebase's own established pattern, per ADR-0026's entire fix chain,
  is that this class of NetworkExtension behavior is routinely wrong
  until checked for real); (b) `pollHealth()` is polling-based on a ~2s
  interval, so there is a real, bounded window between the engine going
  unhealthy and the extension noticing — "tight-window," not
  "zero-window."
- **No active packet-level black-holing.** `pollHealth()`'s unhealthy
  branch leaves routing exactly as last applied; it does not itself
  discard in-flight packets, because this Swift code has no access to
  `packetFlow` once `EngineHandle.start` took exclusive ownership of its
  file descriptor. Whatever blocking occurs while unhealthy is an
  emergent property of "no fallback route (MDM's `IncludeAllNetworks`)
  plus a degraded engine," not new packet-dropping code. Genuine
  packet-level blocking, and restarting the Rust engine in place after a
  crash without a fresh file descriptor, are both out of scope here and
  would need their own follow-up once the fd-lifecycle question is
  answered.
- **Whether a locally `profiles install -type configuration`-loaded test
  profile enforces `PayloadRemovalDisallowed`/`OnDemandEnabled`
  identically to a real DEP/ABM-supervised MDM push is not confirmed** —
  plausible, not verified; a real gap between the recommended local test
  method (`docs/operations/macos-managed-device-mdm.md`) and production
  behavior.
- **Initial enrollment-invitation delivery to a non-admin managed device
  is not solved here.** `Karst.app`'s "Enroll…" flow (pasting an
  invitation into an `NSAlert`) works identically for a non-admin user —
  saving a `NETunnelProviderManager` never required admin rights — but
  *getting* the invitation text to that user without any admin-mediated
  step is an adjacent, unsolved problem this ADR does not attempt.

### Reconsider if

Apple ever ships a documented, supported way to distinguish an
app-created `NETunnelProviderManager` from an MDM-owned one. If that
happens, revisit whether behavior — not just an informational UI line —
should key off real ownership rather than `IncludeAllNetworks`'s presence
being the only managed-mode signal Karst's own code relies on.
