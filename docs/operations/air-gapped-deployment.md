<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Deploying Karst with no external network path

Background and the scope decision behind this are in
docs/adr/0039-air-gapped-deployment-scope.md — read that first if you need
the "why," including what this deliberately does not cover. This document
is the operational how-to.

## What "air-gapped" means here

Run-time network isolation of a deployed instance, not building Karst from
source inside a sealed network. Concretely: once installed, a Karst control
plane, relay, and node population run indefinitely with no reachable
network beyond the mesh peers and control plane you explicitly configured.
Building Karst itself still needs a normally-connected machine (a developer
workstation or this project's own CI) — you build or download release
artifacts on the connected side of the gap and carry them across, the same
way you'd bring in any other piece of infrastructure software.

## Before you carry anything across the gap

1. **Get prebuilt artifacts, not source.** Use a release build (signed
   packages/binaries) or build them yourself on a connected machine —
   `just check` and the packaging scripts in `scripts/` all assume normal
   internet reachability (crates.io, the Go module proxy, npm/pnpm's
   registry). There is no vendored/mirrored build path today; see the ADR's
   "Reconsider if" if that ever becomes a real requirement for you.
2. **Pre-stage Linux desktop-helper dependencies, if you're installing the
   client package.** `karst-client-linux`'s `.deb`/`.rpm` declares
   `zenity`+`pkexec` (Debian) or `polkit` (RPM, recommending `zenity`) for
   `karst-setup`'s consent prompts. On a network with no reachable package
   repository, `apt`/`dnf` cannot resolve these unless your own local
   mirror already carries them — stage them there before installing Karst,
   the same as you would for any other package with OS-level dependencies.
   A headless server deployment (`karstd`/`karst-control` only, no desktop
   `karst-setup` prompts) doesn't need this at all.
3. **Stand up your own control plane, relay, and (if you want SSO) nothing
   external at all.** The embedded local IdP
   (`server/management/server/idp/embedded.go`) needs no external identity
   provider — it's a self-contained Dex connector. There is no hosted
   default for `[control] server`, relay, or TURN anywhere in this
   project's own config examples (`docs/GETTING-STARTED.md`): every
   deployment, air-gapped or not, points at infrastructure the operator
   stood up themselves.

## What needs no reachability at all (verified, not assumed)

- **DNS resolution.** `karst-dns`'s resolver takes its upstreams from your
  own configuration; there is no compiled-in public fallback resolver to
  accidentally reach.
- **The admin console.** No external CDN, font service, or analytics
  endpoint — it's fully self-contained static assets plus your own control
  plane's API.
- **Bedrock anchor-age.** If you've read anything suggesting Bedrock
  anchoring needs an externally-reachable time authority, that's incorrect
  — see the ADR. An `anchor` is a signed head-hash of your own account's
  audit log, signed by a key that lives on your own admin device or server.
  `management_karst_bedrock_anchor_age_seconds` is a wall-clock delta since
  that locally-signed entry, nothing more. Run the ceremony
  (`docs/manual-tests/04-bedrock-audit-and-operations.md`) exactly as you
  would on a connected deployment.
- **Cryptography.** CNSA 2.0 is already the only suite (ADR-0018) — there
  is no separate "strict mode" to enable.

## Operational hygiene worth doing anyway

- **Run your own NTP inside the air-gapped network.** Not a Karst
  dependency — TLS certificate validity windows and any interpretation of
  `anchor_age_seconds` against wall-clock time both assume the system clock
  is roughly right. That's an operator responsibility on any deployment,
  air-gapped or not; it's just easier to forget when there's no public NTP
  pool to fall back to by accident.
- **Verify with a default-deny egress policy**, not by inspection alone: if
  you can firewall the deployment to allow only the control plane, relay,
  and mesh peer addresses you configured and Karst keeps working, that's a
  stronger proof than reading source. Treat this as a real verification
  step for your specific deployment, not something this document can do
  for you in the abstract.

## What this does not cover

Building Karst itself on the sealed side of the gap. If that's a real
requirement for you, see docs/adr/0039-air-gapped-deployment-scope.md's
"Reconsider if" and open an issue — that's a materially larger effort
(vendoring or mirroring Cargo, Go modules, and npm/pnpm) than anything in
this document.
