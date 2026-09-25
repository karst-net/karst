<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# macOS managed-device deployment (MDM)

Background and the design decisions behind this are in
docs/adr/0031-managed-device-mode-reconsiders-adr-0024.md. This document is
the operational how-to for an IT admin; read the ADR first if you need the
"why," including the honest list of what this does and does not guarantee.

## Two modes, one client

`Karst.app`/`KarstPacketTunnel` behave differently depending entirely on
who owns the `NETunnelProviderManager` configuration for
`dev.karst.packettunnel` — there is no separate "managed" build or
install flag.

- **Personal/BYOD**: the end user enrolls themselves via `Karst.app`'s
  "Enroll…" menu item. They can disconnect or remove Karst at any time —
  this is unchanged and is not something MDM deployment overrides.
- **Managed**: you push the VPN configuration via MDM as a
  `.mobileconfig` profile. Karst detects (heuristically, for UI purposes
  only — see the ADR) that it does not own the configuration and shows
  "VPN configuration managed by your organization" in its menu instead of
  Enroll/Re-enroll actually being hidden. Removal is blocked at the OS
  level by the profile itself (`PayloadRemovalDisallowed`) combined with
  the device's daily user having no local admin rights to authenticate a
  removal even if they tried — not by anything Karst's own code refuses
  to let them do.

## Pushing the profile

A template is at
`packaging/macos/mdm/dev.karst.packettunnel.example.mobileconfig`. It is
not ready to push as-is:

1. Replace every `REPLACE_ME` placeholder (payload identifiers, your
   control-plane address, your MDM organization name).
2. Generate fresh `PayloadUUID` values for the top-level profile and each
   payload — do not reuse the placeholders across more than one profile
   definition.
3. Push it through your MDM console's own "custom configuration profile"
   mechanism, scoped to the device group you intend to manage. Most MDM
   consoles (Jamf Pro, Kandji, Mosyle, etc.) also let you set a
   profile-removal password independently of the XML itself — set one if
   your MDM supports it, since `PayloadRemovalDisallowed` alone is a
   request the OS honors, not a secret.
4. The bundled `SystemExtensions` payload pre-approves
   `dev.karst.packettunnel` for team identifier `WJ3MJC4KV7` so the device
   never shows an interactive "Allow" prompt for the extension.

Install `Karst.app` itself the same way you install any other managed
app (a `.pkg` pushed via your MDM's software-distribution mechanism, or
your existing internal catalog) — this document is only about the VPN
configuration and System Extension approval, not app distribution.

## Choosing an exit route for managed Macs

Exit-route consent is normally the Mac administrator's (ADR-0024, ADR-0036).
On a managed device the organization is the operator (ADR-0031), so the
profile can give it instead: set `ExitNodeAutoConsent` to `true` in the VPN
payload's `VendorConfig`. The extension then consents to the exit route
offered to the device, provided exactly one recipient exit is offered; it
follows that offer if the server recreates it under a new route ID. With
several offered it chooses none and Karst.app's **Exit node** menu says so.
While the key is set, the menu shows the exit as "Managed by your
organization" and offers no change, and the extension refuses the menu's
change requests. A local administrator's `sudo karst exit-node disable` still
works, but the extension re-consents on its next health-poll tick.

## The one problem this does not solve: initial enrollment

Pushing the profile above configures the *tunnel*, but Karst still needs
one enrollment invitation (`karst-invite-v1:…`) pasted through
`Karst.app`'s "Enroll…" dialog before it has an identity to actually
connect with. That paste step works identically for a non-admin user —
saving the underlying `NETunnelProviderManager` config has never required
admin rights — but *getting* the invitation text to a device's daily user
without any admin-mediated step is not solved by this profile or by
Karst's code. Until your organization has its own answer for that (an
MDM custom-attribute push, a help-desk-assisted one-time paste, etc.),
plan for a brief admin-assisted step during initial provisioning.

## Validating a deployment before wider rollout

Treat every step below as required, not optional, per ADR-0031's own
admission that several of these behaviors are not yet verified against
real hardware:

1. **Personal-mode regression, first.** On a separate, non-managed test
   Mac, confirm ordinary self-service enroll/disconnect/removal still
   works exactly as before pushing anything from this document — this
   must never regress.
2. **Local profile-install simulation.** On a test Mac (does not need to
   be DEP/ABM-supervised for this step), run:
   ```sh
   sudo profiles install -type configuration -path dev.karst.packettunnel.example.mobileconfig
   ```
   Confirm `Karst.app`'s menu shows "VPN configuration managed by your
   organization" and that System Settings shows the profile's "Remove
   Configuration" control greyed out or password-gated. **Known gap**:
   this does not prove real DEP/ABM-supervised behavior is identical —
   validate the same checks again on an actual supervised test device
   before wide rollout.
3. **Kill-switch traffic test — the most important one.** With the
   profile active and the tunnel connected, force the engine to fail
   mid-session (kill the extension process, or corrupt its
   `config.toml`/socket state) and attempt to reach the open internet
   from another app. Confirm zero packets escape. This is the single
   check that validates the `IncludeAllNetworks` assumption
   ADR-0031 explicitly flags as unverified — do not skip it.
4. **On-demand reconnect.** Toggle Wi-Fi off/on, or sleep/wake the
   machine, and confirm the tunnel re-establishes automatically.
5. **Route-churn handling.** While connected, toggle an exit route active
   or inactive from another enrolled peer/console action mid-session and
   confirm routing updates without requiring a full tunnel restart.

Record results using the same format as `docs/manual-tests/`'s existing
tables — see that directory's `02-clients-and-networking.md` for the
personal-mode rows this deployment must not regress.
