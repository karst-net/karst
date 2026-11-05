<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-0036: Exit-route consent on the macOS Network Extension client

- **Status:** Proposed
- **Date:** 2026-09-25 (revised 2026-11-02: dropped the local authorization
  gate for self-service installs — see Decision item 3 and "Revision";
  extended 2026-11-04 to the Mac App Store build — see "Addendum")
- **Deciders:** TBD
- **Related:** #160 (exit-route validation, blocked on this), #165 (its
  active-exit-withdrawal criterion), #499 (this ADR's extension to the Mac
  App Store build), ADR-0024 (consent stays local and root-gated), ADR-0031
  (managed-device mode), ADR-0026 (Network Extension backend), ADR-0040
  (the sandboxed App Extension this ADR's Addendum covers),
  `spec/karst-control-v1.md` §5.4,
  `docs/subnet-routers-and-exit-nodes.md` §3,
  `bins/karstd/src/exit_node.rs`, `bins/karstd/src/exit_policy.rs`,
  `packaging/macos/KarstPacketTunnel/Sources/KarstPacketTunnel/PacketTunnelProvider.swift`,
  `packaging/macos/KarstPacketTunnelAppExtension/Sources/KarstPacketTunnelAppExtension/PacketTunnelProvider.swift`

---

## Context

An exit route is offered by the control plane but becomes active only with
**local consent** (`spec/karst-control-v1.md` §5.4; ADR-0024 reaffirmed it
must never be forceable from the console). On Linux and Windows the local
operator gives it with `karst exit-node use <route-id>` over karstd's
root-only control socket, and it is stored durably in the exit-route state
file.

The macOS client ships only the Network Extension (`Karst.app` plus
`KarstPacketTunnel`), and on the lab hardware (2026-09-25) exit routes were
unusable end to end:

| Layer | Found on the physical lab Mac |
| --- | --- |
| Offer delivery | Works: `exit-list` over the extension's admin socket shows the offer |
| Consent storage | Works: `exit-use` writes `/var/db/karst/exit-route` (root, 0600), as on Linux |
| **Activation** | Fails: `reconcile_exit` calls `exit_policy::activate`, Linux policy routing built on the `ip` tool; on macOS that is `ENOENT` ("No such file or directory"), so the exit never becomes active |
| Default route | Exists: the provider maps an *active* recipient exit into `0.0.0.0/0`/`::/0` included routes, and since #193 re-applies it mid-session |
| **Who may consent** | Only root over the raw socket, with no shipped tool and no UI (this was the starting point the Decision below changes for self-service installs) |

Two constraints decide the shape before preference does:

1. **ADR-0024's authority model, applied — and, on reflection, deliberately
   narrowed for this one platform's self-service case (see "Revision"
   below).** ADR-0024 draws its line at the *local operator*: whoever can
   already reconfigure the machine, which on Linux/Windows is whoever can
   reach the root-only control socket. The original version of this ADR
   mapped that to "whoever holds administrator rights" on macOS too, because
   `Karst.app` runs as whichever user is logged in, so a plain menu item
   sending a provider message would hand the power to change the exit node
   to any console user, admin or not — and ADR-0024's own worked example is
   a parent/child household where that distinction matters. The revision
   below keeps ADR-0024's actual boundary (the control plane can never force
   or imply consent) but stops reproducing Linux's *root-only* half of it on
   macOS for a self-service install: see "Revision" for why.
2. **macOS has no Linux policy routing, and doesn't need it.** In a Network
   Extension the provider owns routing through `NEPacketTunnelNetworkSettings`
   (the engine's `add_route` is already a no-op there), and the system keeps a
   provider's own sockets out of its own tunnel. The problem Linux's
   escape rules solve, Karst's control, relay and peer traffic being captured
   by its own default route, is handled by the platform.

## Decision

1. **Engine: on Network Extension builds, exit activation is delegated to
   the provider.** Under `all(target_os = "macos", feature =
   "network-extension")`, `reconcile_exit` records the selection and reports
   the exit installed when a matching recipient exit offer is present. It
   does not call `exit_policy`, which stays the Linux implementation. The
   provider turns the resulting `active` recipient exit into the default
   route, as it already does. Consent semantics are unchanged: durable in the
   same state file, dormant while the offer is absent, and never set by the
   control plane.

2. **Underlay escapes: rely on the platform, and prove it.** No
   `excludedRoutes` are added for control, relay or peer endpoints. The lab's
   exit scenario must demonstrate that the control plane and relay stay
   reachable, and the tunnel stays up, while the exit is active, with
   control and relay off-link from the Mac so the check is not trivially
   satisfied by a connected LAN route. If it shows a loop, reconsider (see
   below).

3. **Personal mode: two front doors; neither needs a password any more.**
   - **CLI.** The package ships the `karst` CLI, defaulting on macOS to the
     extension's admin socket
     (`/Library/Application Support/dev.karst.packettunnel/control.sock`,
     root-only). `sudo karst exit-node list | use <route-id> | disable` works
     as documented for Linux, unchanged by this revision — this path still
     needs `sudo`, for the same reason it does on Linux/Windows. The CI
     harness uses this path.
   - **Karst.app menu.** An **Exit node ▸** submenu lists offered exit routes
     (gateway name and prefix) and **Off**. Choosing one shows the existing
     privacy disclosure ("the exit node sees your traffic's destinations",
     `docs/subnet-routers-and-exit-nodes.md` §3) and, on confirmation, sends
     the provider a plain `exit-use`/`exit-disable` message — no
     authorization token, no password or Touch ID prompt. **The extension
     only checks whether the install is managed** (`managedExitAutoConsent`,
     ADR-0036 §4 below); if it is not, the command reaches the engine
     unconditionally. Any console user, administrator or not, can change
     the exit node this way on a self-service Mac.

4. **Managed mode (ADR-0031): consent comes from the profile.** A
   `providerConfiguration` key in the `com.apple.vpn.managed` payload,
   `ExitNodeAutoConsent` (boolean), makes the extension consent to *the* exit
   route offered to the device. If exactly one recipient exit offer is
   present, it is selected. If more than one is present, none is selected and
   the conflict is reported in status and the menu. It is re-evaluated at
   start and whenever the offer set changes, so it survives server-side
   route-ID churn. When the key is present, the menu shows the exit as
   "Managed by your organization" and offers no local change. On a
   supervised device the account is the operator (ADR-0031's premise), so
   this does not reopen ADR-0024.

5. **Invariants kept.** A default prefix enters the tunnel only through an
   *active* recipient exit, never from `allowed_ips` alone (#193). Consent
   never originates from the control plane. Withdrawing the offer removes
   the route on the next health-poll tick and leaves consent dormant.

### Alternatives rejected

- **Keeping the Authorization Services gate for every console user, as the
  original version of this ADR did.** Superseded — see "Revision" below for
  why a self-service install no longer reproduces Linux's root-only-socket
  boundary on macOS.
- **Porting `exit_policy`'s policy routing to macOS (PF or `route`).**
  Rejected: inside a Network Extension routing is the provider's job, and
  duplicating it in the engine would fight `NEPacketTunnelNetworkSettings`.
- **Adding explicit `excludedRoutes` for underlay endpoints now.** Deferred,
  not rejected: it needs the engine to publish its underlay endpoints, and it
  also diverts non-Karst traffic to those hosts. Adopt it only if the lab
  test shows a loop.
- **A profile key naming a route ID.** Rejected: route IDs are
  server-generated, so recreating the route on the server silently breaks
  every deployed profile.
- **CLI only.** Rejected for personal use: a GUI client whose one
  consent-bearing feature needs Terminal and `sudo` is not usable for its
  intended audience. The CLI still ships, for parity and automation.

---

## Consequences

### Positive

- Exit routes become usable on macOS, unblocking #160 and #165's
  active-exit-withdrawal criterion. The lab's exit scenario can run via
  `sudo karst exit-node use`.
- The control plane still cannot force or imply consent on macOS, which is
  the part of ADR-0024's boundary that actually matters: the server can
  offer a route, never activate one.
- Changing the exit node from `Karst.app` now needs no password or Touch ID
  prompt on a self-service Mac, matching the CLI's own ADR-0024 ceiling (an
  admin on a personally-owned machine could already do this via `sudo`
  regardless of what the GUI gated) instead of adding GUI-only friction on
  top of it.
- Managed deployments get a no-touch exit without a route-ID dependency,
  unaffected by this revision.

### Negative

- **Any console user on a self-service Mac — not only an administrator —
  can now change the exit node from the menu, with no credential at all.**
  This reopens exactly the household scenario ADR-0024 names (a non-admin
  child account) for the macOS GUI path specifically: a parent's chosen
  exit can be turned off, or a different one chosen, from a non-admin
  session. ADR-0024 itself names the escape hatch for anyone who needs that
  boundary enforced: managed/MDM mode (ADR-0036 §4), where the device's
  account is not the intended holder of control and the exit is already
  fully locked to the profile's choice with no local override of any kind.
  Self-service installs are, by this revision, no longer where that
  boundary is enforced.
- The CLI's root-only socket and the GUI's unauthenticated provider message
  are now two different privilege levels for the same action — `sudo karst
  exit-node use` still needs an admin password; the menu item next to it
  does not. This is intentional (the GUI path has no OS-level privilege
  gate available to it the way a Unix socket does, so there was never
  parity to preserve once the password requirement was dropped), but it is
  a visible asymmetry worth stating plainly rather than leaving implicit.
- `ExitNodeAutoConsent` picks nothing when more than one exit is offered to
  a device. Deployments that offer several exits to managed Macs need a
  follow-up (for example selecting by gateway name).
- Relying on the platform to exclude the provider's own traffic is an
  assumption until the lab proves it on the macOS versions Karst supports.

### Reconsider if

- The lab exit scenario shows control, relay or peer traffic captured by the
  exit route. Then add engine-published underlay `excludedRoutes` (decision
  item 2).
- Managed fleets need several exits per device. Then extend the profile key
  to select by gateway rather than by count.
- A self-service, multi-account household wants the pre-revision behavior
  back (a non-admin console user blocked from changing the exit node)
  without adopting MDM. No such request has been made; if one is, it needs
  its own ADR per ADR-0024's own "Reconsider if" clause, not a reversal
  folded back into this one.

---

## Revision (2026-11-02): dropped the local authorization gate

The Decision above originally required Authorization Services on the
`Karst.app` menu path (an admin password or Touch ID prompt on every
`exit-use`/`exit-disable`, deliberately not cached — see the postinstall
comment history for why a longer timeout was tried and reverted). On
direction from the project, that gate is removed for self-service installs:
**unless the configuration is managed (`ExitNodeAutoConsent` present,
§4), whoever is logged in locally may change this Mac's exit node without
a password**, from either front door the CLI already had (`sudo karst
exit-node use`, unchanged) or the menu (now ungated).

This is a deliberate, scoped narrowing of ADR-0024's authority model for
macOS's self-service case, not a bug fix: the Context section above
explains why the original design treated "administrator" as the local
operator on macOS the same way "root over the socket" is the local operator
on Linux/Windows. The friction that boundary bought — a password on every
switch, with no session caching, by design — was reconsidered and found not
worth paying on a platform where, per ADR-0024's own "Where this genuinely
does not reach" section, an admin could always reach the same result
through the CLI anyway. What the revision gives up is the piece ADR-0024's
household example actually depended on: a non-admin console user on a
self-service Mac can now also change the exit node. Anyone who needs that
specific boundary enforced should use managed/MDM mode, which this revision
does not touch.

---

## Addendum (2026-11-04): the Mac App Store build (#499)

This ADR's Decision and Revision above were written against
`KarstPacketTunnel`, the Developer-ID **System Extension** that runs as
root, with `Karst.app` running as the console user calling into it. ADR-0040
added a second, **sandboxed App Extension** build —
`KarstPacketTunnelAppExtension`, hosted by `KarstAppStore` — for Mac App
Store distribution, which #499 asked this ADR to design consent for: does
the existing `authd`/`AuthorizationExternalForm` administrator-authorization
round trip apply when the extension isn't root, or is some other mechanism
needed?

**Decision: the same mechanism applies unchanged, and the root/non-root
question above does not actually arise.** The Revision's condition for
dropping the authorization gate was never "the extension happens to run as
root" — it was that *neither side of the channel has a credential check
available to it*: `Karst.app` runs as whoever is logged in, and any console
user can already reach the extension's `sendProviderMessage` endpoint
without OS help, so an authorization prompt in front of it would gate a
request that already arrived with no stronger claim than "some local
process asked." That condition holds, if anything more plainly, for the App
Store build: `KarstAppStore` and `KarstPacketTunnelAppExtension` both run as
the *same* sandboxed console user (this build's own `stateDir` doc comment
on `PacketTunnelProvider.swift`), with neither ever holding root. There is
no `authd` round trip to port because there was never a root boundary on
either side of this specific channel to authorize across — `exit-use`/
`exit-disable` just reuses the identical unauthenticated verb pair, and
`ExitConsent.swift` (`KarstPacketTunnelAppExtension`'s copy, trimmed of
`ManagedDecision`/`managedDecision`) is a straight port of
`KarstPacketTunnel`'s own.

The one real difference is `ExitNodeAutoConsent` (§4): the Mac App Store
build has no managed-device story at all (ADR-0040 item 4 — this
distribution channel is self-service only), so `handleAppMessage`'s
`exit-use`/`exit-disable` branch on this build carries no
`managedExitAutoConsent` check and never refuses on that basis. That is a
narrower surface than the Developer-ID build, not a gap this Addendum
defers: managed-device coexistence was never in scope for this channel in
the first place.
