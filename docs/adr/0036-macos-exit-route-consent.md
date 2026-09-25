<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-0036: Exit-route consent on the macOS Network Extension client

- **Status:** Proposed
- **Date:** 2026-09-25
- **Deciders:** TBD
- **Related:** #160 (exit-route validation, blocked on this), #165 (its
  active-exit-withdrawal criterion), ADR-0024 (consent stays local and
  root-gated), ADR-0031 (managed-device mode), ADR-0026 (Network Extension
  backend), `spec/karst-control-v1.md` §5.4,
  `docs/subnet-routers-and-exit-nodes.md` §3,
  `bins/karstd/src/exit_node.rs`, `bins/karstd/src/exit_policy.rs`,
  `packaging/macos/KarstPacketTunnel/Sources/KarstPacketTunnel/PacketTunnelProvider.swift`

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
| **Who may consent** | Only root over the raw socket, with no shipped tool and no UI |

Two constraints decide the shape before preference does:

1. **ADR-0024's authority model.** Consent, and its withdrawal, belong to the
   device's *local operator*: whoever holds administrator rights, not the
   enrolled user. A child's non-admin account must not be able to turn a
   parent's chosen exit off, or pick one of its own. On macOS, `Karst.app`
   runs as whichever user is logged in, so a plain menu item sending a
   provider message would hand that power to any console user.
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

3. **Personal mode: two front doors, both requiring administrator rights.**
   - **CLI.** The package ships the `karst` CLI, defaulting on macOS to the
     extension's admin socket
     (`/Library/Application Support/dev.karst.packettunnel/control.sock`,
     root-only). `sudo karst exit-node list | use <route-id> | disable` works
     as documented for Linux. The CI harness uses this path.
   - **Karst.app menu.** An **Exit node ▸** submenu lists offered exit routes
     (gateway name and prefix) and **Off**. Choosing one first shows the
     existing privacy disclosure ("the exit node sees your traffic's
     destinations", `docs/subnet-routers-and-exit-nodes.md` §3), then
     requests the authorization right `dev.karst.exit-node.consent` (rule:
     authenticate as an administrator, credentials not shared, valid for 5
     seconds: long enough for the extension's check, short enough that every
     change prompts) with Authorization Services. The app
     sends the provider an `exit-use`/`exit-disable` message carrying the
     `AuthorizationExternalForm`. **The extension, running as root,
     reconstructs it and checks the right itself** (`AuthorizationCopyRights`
     without interaction) before relaying the command to the engine; a
     missing or unauthorized token is refused. A non-admin user sees the
     current exit but cannot change it.

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

- **A menu item that sends `exit-use` without authorization.** Rejected: it
  lets any console user, including a managed child account, give or withdraw
  consent, which ADR-0024 exists to prevent.
- **Asking for admin credentials in the app and trusting the app's word.**
  Rejected: the provider cannot tell a checked request from an unchecked
  one. Only a token the root side verifies itself carries the guarantee.
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
- ADR-0024's authority boundary holds on macOS: consent needs an
  administrator, checked by the root side, in both front doors.
- Managed deployments get a no-touch exit without a route-ID dependency.

### Negative

- Authorization Services is new surface area in both the app and the
  extension: a custom right in the authorization database, installed by the
  package, and a verification path that must fail closed.
- The shipped CLI is a second consent path to keep aligned with the menu,
  though both end at the same engine IPC.
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
- Apple ships a supported per-user consent or VPN-configuration API that
  makes Authorization Services unnecessary.
