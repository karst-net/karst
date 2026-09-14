<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-0023: Declining a first-class device-activity visibility feature for account owners

- **Status:** Rejected
- **Date:** 2026-09-14
- **Deciders:** TBD
- **Related:** docs/USE-CASE-ANALYSIS.md UC-05, UC-06, UC-10; docs/THREAT-MODEL.md
  §7; docs/CUSTOMER-SCENARIOS.md SC-05; GitHub issue #150

---

## Context

Issue #150, tracked from `docs/CUSTOMER-SCENARIOS.md` SC-05 ("Parent
monitoring a child's website activity"), asked Karst to give an account
owner visibility into what an enrolled device has been reaching — in effect,
a browsing-activity report surfaced to someone other than the device's own
user.

This is not a cryptographic non-goal the way relay-observed metadata is
(`THREAT-MODEL.md` §7 item 1). `karstd` runs on the device itself, upstream
of PHREATIC encryption for outbound traffic and downstream of it for
inbound — it is architecturally *capable* of observing every DNS query and
connection the device makes. Nothing in the protocol prevents building this;
the question is entirely whether Karst's identity and authority model should
carry it.

That model already answers a version of this question. Per
`docs/USE-CASE-ANALYSIS.md`'s actor table, a **client user**'s authority
boundary is to "enroll, name, view, and revoke only their own devices,"
receiving "only access granted by policy." An **administrator** "manages
users, groups, access policy, relays, DNS, routes, settings, and lifecycle
actions" — a fleet-management relationship over organization-owned
infrastructure, whose actions "must be audited" (UC-03, UC-10). Neither role
is "a person who watches what another person's device does." The audit log
(UC-10) exists to make an *administrator's own actions* accountable to the
account, not to make a *user's behavior* legible to the account owner —
that asymmetry is intentional, not an oversight to be closed.

SC-05's household framing sharpens this: "parent as administrator, child as
enrolled user" is not the enterprise admin/employee relationship the rest of
the identity model was built around. An employee's device is
organization-owned infrastructure under an employment relationship with its
own disclosure norms; a family member's device and a family member's own
choices about what they read are not the same thing wearing a different
label. Reusing the administrator role to grant that visibility would be
extending an enterprise fleet-management primitive into a surveillance
capability over a person, silently, because the two relationships happen to
share a data model.

## Decision

**Karst will not build a feature that surfaces a device's browsing or
connection activity to its account owner.** This is a decline, not a
deferral: the objection is to what the feature *is* (a legible authority
asymmetry between the party being watched and the party watching, with no
disclosure requirement designed in), not to unresolved implementation
questions that a future iteration would fix.

### What stays true

- **Node ownership is unchanged.** A client user retains full authority to
  view, name, and revoke their own device. No new administrator capability
  is added.
- **The audit log's scope is unchanged.** It continues to record
  administrative control-plane events (UC-10), not a device's own traffic.
- **This is specific to Karst's core.** Nothing here prevents a household
  from composing this outcome themselves with what already exists (below) —
  the decision is that Karst does not ship it as a built-in, one-click
  account-owner capability.

### The honest alternative, using what already exists

`docs/CUSTOMER-SCENARIOS.md` SC-06 already documents the mechanism: point a
device's DNS queries at a resolver the household controls, using KarstDNS's
existing split-DNS upstream configuration (UC-06). This is not new Karst
engineering — it is the DNS-configuration feature already shipped, pointed
at a logging or filtering resolver of the household's choosing.

The distinction that matters is **disclosure**. A DNS upstream is
configuration that ships in the device's own netmap and is visible to that
device's user via ordinary `karst status`/DNS inspection, the same way any
other DNS setting is. It is not a hidden channel. A household that wants
this outcome gets it through a visible, inspectable configuration choice,
not a covert reporting feature — which is the difference this ADR is
actually about.

### Alternatives rejected

- **Build it as an administrator capability, gated by role.** Rejected: role
  gating controls *who* can turn on monitoring, not *whether* the device's
  own user can see that it's happening. The asymmetry problem is the
  capability existing at all with no disclosure requirement, not who holds
  the button.
- **Build it as an opt-in the device's own user must accept.** This is a
  materially different, plausible feature — a consenting adult device owner
  choosing to share their own activity with another account member. It was
  considered out of scope for this ADR because it needs its own product
  decision (what "consent" means for a household account with a minor,
  whether consent can be revoked unilaterally, what happens to
  already-collected data on revocation) that goes well beyond extending
  UC-10's audit log, and no such design currently exists. If someone wants to
  pursue it, it deserves its own ADR built around consent and revocation as
  first-class requirements, not a checkbox bolted onto this one.
- **Extend UC-10's audit log to include device DNS/connection events,
  gated by the same permissions as other audit data.** Rejected: UC-10's
  audit access model (`docs/USE-CASE-ANALYSIS.md`'s authorization table)
  is built around administrators and auditors reviewing *administrative*
  history: policy changes, enrollments, blocks. Reusing that pipe for a
  device's own traffic would quietly change what "audit access" means
  account-wide, affecting every existing auditor-role grant, not just the
  household case that motivated the request.

## Consequences

### Positive

- The client-user/administrator authority boundary in
  `docs/USE-CASE-ANALYSIS.md` stays coherent: an administrator's power is
  over infrastructure and policy, never over a person's behavior, in every
  case, not just the enterprise one.
- No new observation point is added to `karstd`, which stays consistent with
  Ponor's own stated posture of not inspecting payloads
  (`spec/ponor-v1.md` §"It does not inspect the payload").
- The composition path (SC-06's split-DNS mechanism, once SC-06 itself is
  resolved) gives the actual use case a real, visible answer instead of
  leaving it fully unaddressed.

### Negative

- **This does not fully satisfy the scenario that motivated it.** A parent
  who specifically wants a *report* of what a child visited, rather than a
  filtering/logging resolver they configure themselves, does not get that
  from Karst. Stated plainly rather than implied away — see
  `docs/CUSTOMER-SCENARIOS.md` SC-05.
- Anyone who *does* want a consenting-adult activity-sharing feature (the
  first rejected alternative above) has no path to it from this ADR; that
  request would need to start over as its own design.

### Reconsider if

Karst ever adds a household/guardian account model that is explicitly
distinct from the enterprise administrator role, with disclosure and consent
as first-class, designed-in requirements rather than a permission bit on the
existing administrator capability. That is a larger product decision than
this ADR, and should get its own ADR rather than reopening this one.
