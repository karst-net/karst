<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-0049: Billing and plan enforcement are in scope for the multi-tenant offering

- **Status:** Accepted (scope decision only; mechanism, pricing and plan
  tiers are explicitly not decided here — see "Not decided")
- **Date:** 2026-10-03
- **Deciders:** adriananderson (decision recorded on #205)
- **Related:** #232 (business-model inputs and first mechanism ADR), #205
  (the placeholder issue this ADR resolves), #166
  (multi-tenant SaaS — closed with #205 standing in for its last item), #131
  (original disposition record: multi-tenant SaaS — pursue), ADR-0033
  (per-account aquifer scoping), ADR-0035 (per-account audit-log
  partitioning), ADR-0037 (admin-console cross-tenant access), ADR-0038
  (relay per-aquifer capacity fairness), ADR-0007 (licensing),
  `server/management/server/types/account_components.go` (the account model)

---

## Record history

Restored on 2026-10-09 from commit
[`41e944f`](https://github.com/karst-net/karst/commit/41e944ff43ecf20cbc76fd7a77c7ca8438dee2e5)
on `claude/adr-0045-billing-plan-enforcement`. That branch recorded this
scope decision as ADR-0045 on 2026-10-03 but did not land on `main`;
ADR-0045 was independently assigned to cost-aware geographic scaling.
This restoration assigns ADR-0049 and preserves the original decision and
decision date. References in #205 and #232 to the billing ADR-0045 refer to
this record, not the geographic-scaling ADR.

## Context

#166 listed "billing/plan enforcement, if this is meant to be a commercial
offering rather than just 'one binary, many orgs'" as a scope item. Every
other #166 sub-item was an architecture question and shipped through an ADR
(0033, 0035, 0037, 0038). This one was parked as #205 because it was a
business-model question — should this product have a commercial,
metered or plan-gated offering at all — and not something the codebase could
answer.

That question has now been answered: **yes.** Nothing else about the business
model was decided with it. #205 listed pricing, plan tiers, what gets
metered and managed-service-versus-self-hosted as the substance of the
question; this ADR records the "yes" and does not invent answers to the rest.

The mechanisms the multi-tenant work already shipped are the raw material
for any enforcement: accounts and aquifers as the tenant boundary (ADR-0033),
per-account audit partitioning (ADR-0035), a cross-tenant operator console
(ADR-0037), and a per-aquifer relay capacity cap (ADR-0038). #205 named the
obvious per-account metering candidates: invite/enrollment counts, relay
bandwidth, DNS query volume and Bedrock anchoring frequency.

## Decision

Billing and plan enforcement are **in scope** for Karst's multi-tenant
offering. Work on it is authorized to proceed through the normal design
process: each concrete mechanism gets its own ADR before it ships.

Constraints on that future work, so it does not drift:

- **Additive to the account model, not a rewrite.** Plan state attaches to
  the existing account/org model, following the "additive, not a rewrite"
  pattern #166's other items confirmed.
- **Metering and enforcement are separate concerns.** Recording per-account
  usage must be designable and shippable without any plan ever blocking
  anything; enforcement consumes metering, not the reverse.
- **No plan gating on a deployment that does not configure plans.** A
  self-hosted operator who configures nothing sees no behavior change, the
  same opt-in posture ADR-0038 took. Enforcement defaults to off.
- **Licensing is unchanged.** This ADR does not alter ADR-0007 or the DCO
  no-relicensing constraint in `CONTRIBUTING.md`. Whether any capability is
  offered only in the managed service is a question for a later ADR that
  must engage with ADR-0007 directly; this one does not answer it.

### Not decided

Deliberately left open, each to be settled by the people who sell this and
then recorded in its own ADR or issue:

1. Pricing and plan tiers.
2. Which units are metered (the candidates above are candidates, not a list).
3. Where enforcement lives: the control plane, a separate billing service,
   or an operator's own reverse-proxy/quota layer.
4. Whether Karst is sold as a managed service, remains purely
   self-hosted/AGPL, or both — and what, if anything, differs between them.
5. Payment-provider integration and the data-protection obligations that
   come with handling billing data.

### Alternatives rejected

- **Decide "no" and close #205 as not planned.** Not what was decided; kept
  here only because it was the other live option.
- **Leave #205 open until the full business model is settled.** Rejected:
  the scope decision is made, and an open placeholder for a settled
  question hides the fact that the remaining questions are different ones.
  They get their own tracking issue instead.
- **Write the full design now.** Rejected: items 1-5 above are inputs to
  any design and none has been decided. A design written without them would
  be guesses presented as architecture.

---

## Consequences

### Positive

- #166's last item is resolved rather than silently dropped, and the
  multi-tenant effort has an unambiguous "billing is in" answer.
- Constraints are fixed early (additive, metering separate from
  enforcement, off by default), which keeps later ADRs from relitigating
  them.

### Negative

- **This ADR delivers no mechanism.** It authorizes work; it does not
  scope, size or schedule it. Until the open items are settled there is
  nothing to build.
- **Commercial intent changes the project's posture.** Maintaining a paid
  offering brings support, uptime, billing-data handling and
  AGPL-compatibility questions that a pure "one binary, many orgs"
  project did not carry. These are acknowledged here, not analyzed.
- **Reversal is cheap now and gets costlier.** Today, backing out means
  closing an issue. Once plans or metered data exist on accounts, removing
  them means a data migration and possibly customer-facing commitments.

### Reconsider if

- The business-model questions above cannot be answered in a reasonable
  time, in which case this ADR should be superseded by a "not now" record
  rather than left as an indefinite authorization.
- Any proposed enforcement mechanism would require removing a capability
  from the AGPL server, which collides with ADR-0007's constraints.
