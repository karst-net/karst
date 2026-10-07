<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-0046: NOC view — location and visibility policy for clients, relays, and other components

- **Status:** Proposed
- **Date:** 2026-10-07
- **Deciders:** TBD
- **Related:** #241 (NOC view, this ADR's tracking issue — Phase 0), ADR-0023
  (declining device-activity visibility for account owners — this ADR must
  not reopen it), ADR-0024 (exit-node routing reconsiders ADR-0023 — the
  precedent for how a narrow reconsideration is done, on the record, as its
  own ADR), ADR-0033/ADR-0037 (multi-tenant scoping and operator-granted
  cross-tenant access), ADR-0035 (per-account audit partitioning), ADR-0039
  (air-gapped scope — no GeoIP, no external tile/CDN lookups), ADR-0021
  (relay telemetry — aggregate-only, the precedent this follows),
  `docs/THREAT-MODEL.md` A9 and B4/B5, `server/management/internals/karst/relayreg/relayreg.go`

---

## Context

#241 asks for a map that places a marker for "every component of a Karst
network," naming client nodes alongside relays, exit nodes, subnet routers,
TURN servers, and the control plane, with per-component throughput. It
flags, correctly, that this is adjacent to two decisions this project has
already made and must not silently redo:

- **ADR-0023** declined to build a feature that surfaces a device's own
  activity to its account owner, on authority-asymmetry grounds — the
  objection was to the capability existing with no disclosure to the
  device's own user, not to any particular implementation.
- **THREAT-MODEL.md A9** ("communication metadata... who talks to whom,
  when, volume") is already partially exposed by design, mitigated for the
  control-plane telemetry case by scoping it to "authorized admin/auditor
  views." A map is a *more legible* presentation of exactly that data than
  a table row — the same bytes, read at a glance instead of parsed from a
  grid.

Checked directly against the tree before deciding anything:

- `relayreg.Entry` (`server/management/internals/karst/relayreg/relayreg.go`)
  has no coordinate field — only a free-form `Region` string, confirmed by
  reading the struct and its `compile()`. There is no stored geographic
  location for any component today, and no GeoIP lookup anywhere in the
  relay or node path.
- ADR-0021 already drew the line this ADR extends for relays specifically:
  telemetry is "aggregate only... never per-node data," because a metrics
  endpoint naming every node by id "would publish the tailnet's membership
  to anything that could reach it." The NOC's per-client question is the
  same shape of problem, one layer up: would a map naming every *device* by
  location publish the account's membership-and-whereabouts to anything
  that could reach the NOC view?
- `docs/admin-console.md`'s "Per-node throughput" section shows throughput
  is already per-peer and per-session in the existing Paths dialog —
  visible to the node's own owner and to an administrator with console
  access, which is the existing authority boundary, not a new one. The NOC
  view must not casually widen that boundary just because a map is a more
  convenient way to look at the same account.

ADR-0023's own "Reconsider if" and "Alternatives rejected" sections name the
exact traps to avoid: gating a surveillance-shaped capability by role
instead of asking whether it should exist with no disclosure at all, and
reusing a fleet-management primitive (here: a NOC operational view) across a
relationship (admin and a person's own device) it was not built for.

## Decision

**Infrastructure gets declared locations and real markers. Client nodes get
regional aggregates and no individual marker, ever, in this view.**

### 1. Infrastructure location is operator-declared, never inferred

Relays, exit nodes, subnet routers, TURN servers, the control plane, and
Bedrock/anchor services each gain an optional, operator-entered
`Location {lat, lon, label}` in their respective registry entries (a new
field on `relayreg.Entry` and the equivalent for other component kinds,
following the same validated-at-load pattern `relayreg.Parse` already
uses). No GeoIP, no reverse lookup from an observed IP — the same
"operator-supplied, not discovered" posture `relayreg`'s own package
comment already argues for the registry as a whole, and required by
ADR-0039's bar for air-gapped deployments (no external lookups of any
kind). An entry with no declared location shows on the map as "location
unknown," never a guessed pin.

### 2. Client nodes are shown only as per-region, per-aquifer aggregates

The map shows a count and an aggregate throughput figure per (region,
aquifer) — e.g. "42 clients, aquifer acme-prod, region eu-west" — computed
server-side from data the control plane already holds. There is no
per-device pin, no per-device coordinate, and no way to click an aggregate
and reach an individual device from the NOC view. "Region" here is the
client's home relay's declared region (already known through existing
home-relay selection, ADR-0021) or the account's own declared site — never
GeoIP of an observed endpoint. GeoIP-of-endpoint is explicitly rejected:
inferring a device's physical location from its network behavior is
involuntary observation of exactly the kind ADR-0023 declined to build,
merely sourced from metadata instead of the device's own reports.

This mirrors ADR-0021's relay-telemetry line exactly: aggregate load
information is infrastructure-capacity data a NOC legitimately needs
("where is the load, is a region near capacity"); a per-device inventory
with location is the account's membership and whereabouts, which is not
the NOC's to show.

### 3. Single-device detail stays exactly where it already lives

A device's own detail — name, status, individual throughput, paths — stays
visible only to that device's own owner (and to an administrator through
the existing node-detail/Paths views console access already grants, per
`docs/admin-console.md`), unchanged by this ADR. The NOC role is not
granted a capability over an individual device that the existing
administrator role does not already have, and the NOC map specifically
does not become a new path to it. A service operator debugging one
misbehaving client uses the existing node-detail tooling, not the NOC map —
named here as a real, accepted limitation, not an oversight (see
Consequences).

### 4. Links show aggregate counts, never a client-identified endpoint

A link drawn between a relay and "its clients" is labeled by count and
aggregate rate (e.g. "118 sessions, 42 Mbit/s"), not by an enumerable list
of client handles. The infrastructure-facing end of a link (which relay,
which exit node) is a real, named marker; the client-facing end is always
a number.

### 5. Audience: one view, scoped by the existing grant mechanism

#241's open question of "one view for tenant admins and a second for the
service operator, or one view with scoped data" is resolved as **one view,
scoped data, reusing ADR-0037's existing operator-granted cross-tenant
access** rather than inventing a NOC-specific second surface. A service
operator who needs to see every aquifer's relays gets there the same way
they reach every other scoped console page today: a grant naming the
(user, account) pair, and the `?account=` override ADR-0037 already built
and enforces server-side. No new bypass of account scoping is introduced
for this feature specifically.

### 6. A distinct NOC/read-only role, and audit logging from the start

A new role is added to the existing RBAC matrix (`docs/THREAT-MODEL.md`
B4/B5): read-only, scoped the same way every other role is, carrying no
write capability over policy, relays, or nodes. Every NOC view load and
every drill-down (opening a component's detail panel) is an audit-logged
action, attributed to the viewing account via the existing per-account
partitioned log (ADR-0035) — not a new, separate log.

### 7. Threat model updated

`docs/THREAT-MODEL.md`'s A9 mitigation row (B2) and the B4/B5 table are
updated (this ADR's companion change) to name the NOC view as a consumer of
the existing "restricted to authorized admin/auditor views" mitigation, and
to record the per-client aggregation rule above as the control that keeps
a more legible presentation of the same data from becoming a wider
disclosure than the table-row view it replaces.

### Alternatives rejected

- **Per-client markers, gated by a stricter role** (e.g., only a
  "super-admin" sees individual device pins). Rejected for the same reason
  ADR-0023 rejected "build it as an administrator capability, gated by
  role": gating controls *who* can turn the capability on, not *whether*
  it exists with no disclosure to the device's own user. The asymmetry is
  the problem, not the permission bit in front of it.
- **GeoIP-based client location, opt-in per deployment, for operators who
  want it.** Rejected: conflicts with ADR-0039's bundled/offline/no-external-
  lookup bar for air-gapped deployments, and reintroduces involuntary
  device-location inference — the same objection ADR-0023 raised, sourced
  from network metadata instead of the device's own report.
- **A second, NOC-specific cross-tenant surface**, separate from ADR-0037's
  grant mechanism. Rejected: duplicates an access-control mechanism this
  project only just built and reasoned carefully about. Two places
  enforcing "which accounts can this viewer reach" is two places to get it
  wrong.
- **Distinguish "my org's own employee device" (shown in detail to that
  org's admin) from "a NOC viewing another tenant's device" (aggregate
  only).** Rejected for this pass: ADR-0023's objection was to the
  *relationship* between viewer and device-owner, not the viewer's job
  title. An enterprise fleet-management case for more detail than this ADR
  allows is a real, separate question — but it is a amendment to ADR-0023
  itself, decided on the record the way ADR-0024 did for exit-node
  routing, not a side door opened through the NOC's own ADR.

---

## Consequences

### Positive

- Resolves #241's own flagged tension (client visibility vs ADR-0023)
  before any NOC code lands, rather than discovering it during review.
- Keeps the ADR-0023 boundary intact and extends ADR-0021's aggregate-only
  precedent consistently to a second, more visually legible surface, instead
  of each feature drawing its own version of the same line.
- Infrastructure markers (relays, exit nodes, TURN, control plane) are real,
  useful, and require no new trust decision — they are the same registry
  data an operator already declares, drawn instead of tabulated.
- Reuses ADR-0037's grant mechanism rather than adding a second one,
  keeping cross-tenant enforcement in one place.

### Negative

- **A NOC operator cannot click a dot and find out which device it is.**
  This is a real, permanent limitation of the feature as decided here, not
  a Phase-4-unlocks-it gap the way #241's own phasing implied — reaching a
  single device still requires the existing node-detail tooling, under the
  existing node-owner/administrator authority, never the NOC role.
- **"Region" for a client is a proxy (home relay's declared region), not
  the client's actual location.** A traveling device shows up under its
  home relay's region until it re-homes, which can be stale by the margin
  ADR-0045 §"Verified: client re-homing" already documented (tens of
  minutes). This ADR does not attempt to fix that latency; it only decides
  that the proxy, however stale, is the data source — never GeoIP.
- A deployment that wants finer-grained client visibility for its own
  fleet (the enterprise-device case named in Alternatives rejected) gets
  nothing from this ADR and must pursue its own ADR against ADR-0023
  directly.

### Reconsider if

- Karst ever adds the household/guardian account model ADR-0023 itself
  named as its own reconsideration trigger — decide client visibility for
  the NOC against that model then, not by amendment here.
- A disclosed, consenting enterprise-device location/activity opt-in is
  designed as its own ADR (the "build it as an opt-in the device's own user
  must accept" path ADR-0023 left open) — the NOC could then consume that
  feature's output, once it exists, rather than this ADR inventing a
  parallel mechanism.
