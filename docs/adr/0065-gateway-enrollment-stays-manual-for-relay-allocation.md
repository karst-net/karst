<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-0065: Node-agent/Gateway enrollment stays manual for admin-triggered relay allocation

- **Status:** Accepted
- **Date:** 2026-11-02
- **Deciders:** Project owner (issue #503)
- **Related:** [#503](https://github.com/karst-net/karst/issues/503), #439 (parent epic), #455, ADR-0056, ADR-0057, ADR-0062, ADR-0063

---

## Context

#439's own worked example grants internet egress on a freshly provisioned
host in the same one-form workflow used to allocate the relay. #455/ADR-0063
shipped that form without egress: `relayalloc.validateDraft`
(`server/management/internals/karst/relayalloc/store.go:170-172`) rejects
`EgressV4`/`EgressV6` on every allocation, because `granting`'s own target,
`relayservice.configureAccess`, hard-requires a `GatewayHandle` that resolves
to an already-enrolled `nbpeer.Peer` row
(`server/management/internals/karst/relayservice/access.go:101-109`) with
`Meta.GoOS == "linux"` — a full node-agent identity, not the relay's own
lighter registration. #503 asks for an ADR deciding whether and how to close
that gap by automating node-agent/Gateway enrollment as part of allocation.

Two credential tiers already exist, and they are not interchangeable:

- **Relay-enroll token** (`MintRelayEnrollKey`,
  `server/management/server/relayenroll.go:42,59`): single-use, 10-minute
  default expiry, consumable only through `ConsumeRelayEnrollKey`, and good
  for nothing but registering one `relayreg.Store` row. `AwsDriver` already
  mints and injects it into EC2 `UserData`/IMDS at instance boot
  (`bins/karst-scaler-aws/src/driver.rs:71-73`, `enroll.rs`). This is the
  channel ADR-0063's `provisioning` step already uses.
- **Node-agent setup key**: `karstd`'s own enrollment
  (`bins/karstd/src/enrollment.rs`) consumes a `setup_key`-bearing bundle
  that, once redeemed, grants PHREATIC sessions, AVEN path selection, local
  filtering, KarstDNS, and — the specific thing `granting` needs — optional
  Gateway capability: termination and forwarding of overlay traffic. That
  file's own comment calls the human delivery deliberate, "a materially more
  powerful credential than the relay-enroll token," not an oversight to
  automate. ADR-0056 drew the same line on purpose: "Co-location does not
  combine keys, privileges, or security claims."

No machine-mintable analogue of the relay-enroll token exists for this
tier. The nearest primitive, `CreateEnrollmentKey`
(`server/management/server/setupkey.go:302`), mints a one-off, 15-minute key
with no `AutoGroups` — but it requires an authenticated member session
(`GetUserByUserID`, then checks `user.AccountID`, blocked/pending status) and
is documented as "not JWT authentication" on its `OwnerUserID` field. It has
no scaler-PAT-equivalent entry point; nothing today lets a machine caller
mint a node-agent credential the way `UserRoleScaler` lets one mint a
relay-enroll token.

That human-delivered setup-key path is also not a design the project has
left untouched by accident. The 2026-09-06 enrollment review
(`docs/reviews/enrollment-2026-09-06.md`) found and the matching
implementation follow-up fixed real correctness defects in exactly this
consumption path: a portal-issued key's owner binding could bypass expiry
and revocation checks (P0), and issuance/binding/redemption were split
across non-atomic writes (P1). Getting the human-delivered path safe took a
dedicated source-level review. Folding an unattended, system-initiated
consumer onto the same primitive is new exposure of the same kind, not a
corollary of this ADR's other two questions.

## Decision

**A scaler-driven flow may not mint a node-agent/Gateway enrollment
credential.** `relayalloc.validateDraft`'s rejection of `EgressV4`/`EgressV6`
stays exactly as it is. Egress on a freshly provisioned host remains the
documented two-step workflow #455 already shipped: enroll the instance as a
Gateway by hand (`karst enroll --bundle FILE`), then grant access through
`relay-access.tsx`. This ADR does not change code; it closes #503 by
declining, with reasons, to build the automation #503 asked it to evaluate.

The decision rests on the asymmetry Context lays out, not on cost alone:

- The relay-enroll token is scoped to "nothing but registering a relay row"
  on purpose. A node-agent identity is the single most privileged role in
  ADR-0056's four-family model — it decrypts and forwards overlay traffic,
  where Relay only ever forwards ciphertext. Minting that tier of credential
  from the same `provisioning` step that already injects the lesser token
  over EC2 `UserData`/IMDS would be the first system-initiated flow to
  collapse a trust boundary ADR-0056 drew intentionally, for egress
  specifically — the highest-consequence capability to hand to unattended
  machinery first, not the lowest.
- There is no existing machine-mintable primitive to reuse. Building one
  (scope, lifetime, which caller identity can request it, how it is
  consumed) is exactly decision point 1's question, and the 2026-09-06
  review is direct evidence that this primitive's safety is subtle enough to
  need a dedicated review of its own — not a decision folded into an ADR
  that also has two other questions to settle.
- Because no credential is minted, decision points 2 (where Gateway runs)
  and 3 (two-identity failure semantics) have nothing to attach to yet. They
  are recorded below as guidance for whoever designs the follow-up, not
  decided here.

**For point 2, if a future ADR approves a scoped Gateway-enroll primitive:**
run `karstd` as a second process on the same instance `AwsDriver` already
boots, not a companion instance. ADR-0056 frames Gateway as "an optional
capability of an enrolled node agent," not a separately deployable role, and
a companion instance would need its own entry in ADR-0045's cost solver, its
own boot/lifecycle tracking, and its own address/TLS identity — none of
which exists today for anything that isn't a relay.

**For point 3, same condition:** `granting` would need a two-leg sub-state
distinguishing "relay registered" from "node-agent/Gateway registered."
`relayalloc.Allocation` carries exactly one `FailedStep`/`FailureReason` pair
sized for today's single-credential `granting` step; a future design
extends that shape for two independently-failing registrations rather than
overloading it.

### Alternatives rejected

- **Design a new, narrowly-scoped Gateway-enroll token now** (zero
  `AutoGroups`, single-use, minutes-scoped, consumable only by `karstd`),
  mirroring the relay-enroll token's shape, and wire it into `granting`
  directly. Rejected for this ADR: inventing that credential's scope and
  lifetime as a side effect of answering "may this be automated at all" is
  the shortcut the 2026-09-06 review showed is costly to get wrong on this
  exact family of primitive.
- **Automate only when egress is requested**, leaving relay-transport-only
  allocations untouched. Rejected: the subset that needs egress still
  crosses the same trust boundary, and gating automation on a checkbox does
  not reduce the credential-design work decision point 1 asks for.
- **Have `granting` call `CreateEnrollmentKey` with a service-user session
  standing in for a member.** Rejected: that function is written for an
  authenticated member enrolling their own device, with membership and
  status checks that assume a human owner; stretching it to a
  machine-triggered caller changes its threat model without changing its
  code — the same category of problem ADR-0058 already rejected for calling
  a provider inside a transaction.
- **Add an in-form "bind an already-enrolled Gateway" picker to the
  allocation form**, reusing `relay-access.tsx`'s existing component, as a
  stand-in for "the same one-form workflow." Considered as a smaller, safe,
  near-term improvement — it introduces no new credential and crosses no
  boundary. Rejected from this ADR's scope because it only helps an admin
  who already has a spare enrolled Gateway; it does not grant egress on the
  *freshly provisioned* host #439's worked example and #503's title both
  describe, and counting it as closing #503 would misrepresent what it
  does. Worth its own, much smaller issue if there is demand for it.

---

## Consequences

### Positive

No change to the trust boundaries ADR-0056 drew, or to the human-delivered
enrollment path the 2026-09-06 review just finished hardening.
`relayalloc.validateDraft` and `relayservice.configureAccess` need no code
change; #455 ships exactly as it already has. The credential-scope question
is left for a future ADR to answer with its own security review, rather than
as a rider on this one.

### Negative

#439's own worked example — one form, egress included, on a freshly
provisioned host — remains unmet, and this ADR does not schedule its
closure. Every admin-triggered relay allocation that wants egress still
needs the documented two-step workflow: enroll a Gateway by hand, then grant
access through `relay-access.tsx`. This is the same scope cut #439 already
shipped with, now reaffirmed rather than closed; it joins ADR-0062's own
undated "Gateway agent installation... remain[s] follow-up work for #439."

### Reconsider if

- A machine-mintable, narrowly-scoped Gateway-enroll primitive is designed
  and reviewed on its own terms — its own ADR, its own security review
  comparable in depth to `docs/reviews/enrollment-2026-09-06.md` — at which
  point revisit extending `granting` to drive it, using the point-2/point-3
  guidance above.
- The scaler gains a general pattern for booting a second,
  differently-privileged process per allocated instance, making "where does
  Gateway run" a solved problem rather than a one-off design here.
- Demand for the freshly-provisioned-host egress gap turns out high enough
  to justify the smaller "bind an existing enrolled Gateway in the same
  form" alternative above, even knowing it would not close #439's original
  worked example.
