<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-0033: Multi-tenant SaaS — per-account Aquifer scoping and dynamic Bedrock anchoring

- **Status:** Proposed
- **Date:** 2026-09-22
- **Deciders:** TBD
- **Related:** #166 (this ADR's tracking issue, scoped from #131), spec/ponor-v1.md
  §5.4 (Aquifer scoping) and §7.4 (rate limiting), `server/management/internals/karst/roster`
  (the roster renderer this ADR changes), ADR-0021 (relay telemetry — established
  that a relay is not scoped to one account by design), ADR-0014/ADR-0016
  (Bedrock trust hierarchy and capability-scoped anchor authorities — the
  online anchor-signer key this ADR proposes sharing across tenants), ADR-0032
  (mesh domains — a hierarchy that lives *inside* one account and is
  deliberately not this)

---

## Context

#166 asked to pursue a multi-tenant SaaS deployment variant, deferred by
`PLAN.md` §0 with the claim that "the data model is built so [it is] additive,
not a rewrite." That claim needed checking directly against the tree, not
assumed — #166's own scope note says so. Checked. The account/DB model
genuinely is already multi-account-capable: every relevant table carries an
`AccountID` foreign key, inherited from NetBird's own multi-account design.

**That capability is not hypothetical or SaaS-future — it is reachable
today.** `management/cmd/root.go`'s `--single-account-mode-domain` flag is
what currently produces single-tenancy, and its own help text says plainly:
*"If the installation has more than one account, the property is
ineffective."* Any deployment where `singleAccountMode` is off, or where IdP
users span more than one domain, already has multiple `Account` rows
coexisting in one running server. `docs/GETTING-STARTED.md`'s own comment on
`KARST_AQUIFER=default` — *"One value for a single-tenant deployment"* — is
describing an operator assumption, not an enforced boundary.

Two mechanisms that exist specifically to enforce tenant-shaped boundaries do
not currently follow the account boundary the rest of the system already
uses everywhere else:

### 1. Aquifer — the relay's actual tenant-isolation primitive — is one fixed string, not per-account

`spec/ponor-v1.md` §5.4: *"A relay MUST refuse to forward a frame unless the
source and destination are in the **same** aquifer."* This is the mechanism
that stops a shared relay from being a general-purpose message bus. Checked
both ends:

- **The relay side is already generic and needs no change.**
  `crates/karst-relay-proto/src/handshake.rs`'s `AquiferId(pub String)` is an
  arbitrary string per roster entry, and `bins/karst-relay/src/hub.rs`
  already enforces same-aquifer-only forwarding per connection
  (`same_aquifer = ... s.aquifer == d.aquifer`). Nothing here assumes one
  value per deployment.
- **The Go control-plane side is the actual gap.**
  `roster.Config.Aquifer` is a single operator-supplied string
  (`KARST_AQUIFER`), and `roster.Render(identities []node.Identity, aquifer
  string)` stamps that one string onto *every* admitted node, unconditionally
  (`roster.go:157`). `node.Identity` itself carries no `AccountID` at all —
  it is the raw ML-DSA-87 identity registry (`node.Store.Register`,
  keyed by `Handle`), deliberately decoupled from account membership, which
  lives on `nbpeer.Peer` instead.

**Consequence, stated plainly:** any deployment running more than one
account behind a co-located relay today gets zero relay-level tenant
isolation. Two nodes enrolled in two unrelated accounts are admitted into
the *same* aquifer and the relay will forward between them — not a future
SaaS gap, a live one, in a configuration the codebase already allows and
that NetBird's own upstream behavior (multi-domain IdP grouping) can produce
without anyone deliberately opting into "multi-tenant."

### 2. The Bedrock anchor scheduler anchors exactly one account, chosen once, at boot

`server/cmd/karst-control/main.go`'s `startBedrockAnchorScheduler` resolves
a single `AccountID` via `GetAccountIDFromUserAuth` at process startup and
starts exactly one `bedrock.Scheduler` goroutine for it. Its own comment
acknowledges the shape: *"Single-account mode's resolution... routes to the
one account a self-hosted deployment has."* `bedrock.Configuration`
(`bedrock/store.go`) is already correctly account-scoped
(`AccountID string \`gorm:"primaryKey"\``, one row per account, `Mode`
defaulting to `ModeOff`) — the *config* model has no gap. The *scheduler
bootstrap* does: a second account created in the same deployment, even with
Bedrock explicitly enabled for it, gets no automated anchoring at all. This
is exactly the failure mode ADR-0016 named for the manual-ceremony case it
replaced — *"anchoring that depends on a human ceremony... degrades
silently"* — reintroduced structurally for every account past the first.

### A named non-goal: relay capacity is not tenant-fair either way

`spec/ponor-v1.md` §7.4's rate limiting is a per-`node_id` token bucket only
— there is no per-account/tenant budget. A tenant with many nodes can
consume proportionally more of a shared relay's capacity than a tenant with
few, regardless of how aquifer scoping is fixed. Real, and not addressed by
this ADR — see Consequences and Reconsider-if.

---

## Decision

### 1. Aquifer becomes account-derived, not operator-fixed

Replace the single `KARST_AQUIFER` value used for every node with a
per-node aquifer derived from the account each node belongs to:

- `roster.Render` changes from taking one `aquifer string` to resolving a
  per-entry value, keyed by the account each node belongs to. The exact
  plumbing — adding an `AccountID` column to `node.Identity` directly versus
  joining through `nbpeer.Peer` at the point `roster.Source.All()` is
  implemented — is left to implementation, matching this project's usual
  practice of not specifying wire/schema mechanics in the ADR when either
  shape satisfies the decision.
- The aquifer value itself is the account ID, optionally namespaced by an
  operator-supplied deployment prefix: `KARST_AQUIFER` is repurposed from a
  required fixed value to an **optional** prefix (default empty), producing
  `{prefix:}{account-id}` or bare `{account-id}`. The prefix exists for an
  operator running more than one independent karst-control deployment
  against a shared relay pool who wants a human-legible namespace on top of
  account-ID collision-avoidance (already vanishingly unlikely given account
  IDs are unique per deployment, but the prefix is nearly free and makes
  relay-side logs legible by deployment).
- **A single-account deployment is unaffected in substance.** One account
  still produces one effective aquifer value, functionally identical to
  today's `KARST_AQUIFER=default` — derived instead of operator-typed, not a
  behavior change for the common case this ships to first.

This directly makes spec/ponor-v1.md §5.4 the actual tenant boundary, rather
than an operator convention the spec's own guarantee was silently resting on.

### 2. The Bedrock anchor scheduler becomes multi-account-aware

Replace the one-time `AccountID` resolution with a periodic
account-enumeration loop: list every account whose
`bedrock.Configuration.Mode != ModeOff`, ensure exactly one
`bedrock.Scheduler` goroutine is running per such account, starting new ones
as accounts are created or Bedrock is enabled for them and stopping ones for
accounts deleted or set back to `ModeOff` — without a process restart.

**The online anchor-signer key may be shared across every tenant's
scheduler.** ADR-0016's capability scoping restricts what an anchor-tier key
can sign — anchor operations only, never `node-sign`, the one capability
Bedrock exists to keep out of a server's reach — and each anchor entry is
already bound to one specific account's chain head. Reusing one signer key
across tenants' independent chains does not, on this reasoning, grant any
tenant privilege over another's chain. This is stated as a judgment call
resting on that reasoning holding under review, not a certainty — see
Consequences.

### 3. Explicitly out of scope for this ADR

- **Relay per-tenant capacity/fairness.** §7.4 stays per-node_id. A future
  account-scoped budget layered on top is a `spec/ponor-v1.md` change, not
  a Go-side one, and is real additional protocol work — named, not designed,
  here.
- **Billing/plan enforcement.** A product/business decision, not an
  architecture one. Stays an open scope item under #166.
- **Admin-console cross-tenant surfaces** (account switching, cross-tenant
  admin views). Deferred to implementation/console work; nothing here
  blocks or requires a particular console shape.

### Alternatives rejected

- **Keep `KARST_AQUIFER` fixed; document "one account per deployment, run N
  deployments for N tenants."** Rejected: this is what is already true
  today, and is exactly the operational shape #166 exists to move past —
  N independently-run single-tenant deployments is not a multi-tenant SaaS
  offering, it's the status quo with extra process management.
- **Give every tenant its own dedicated relay instead of a shared one with
  per-account aquifer tagging.** Rejected: defeats the resource-sharing
  point of a SaaS offering, and ADR-0021 already established that a relay
  is deliberately *not* scoped to one account — it authenticates by key,
  and the same relay key can already be registered under more than one
  account by design. Fighting that existing shape would be a larger,
  unjustified change in the opposite direction from what's needed.
- **Give every account its own dedicated online Bedrock anchor-signer key**
  instead of sharing one. More conservative and simpler to reason about in
  isolation, but rejected for this pass: N tenants would mean N key files
  to provision, protect, and rotate, which is real ongoing operational
  weight, and the capability-scoping argument above is a real, checkable
  reason it isn't necessary. Named as the fallback if that argument doesn't
  survive review — see Reconsider if.
- **Derive tenant scope from a new concept layered above or below
  `Account`**, rather than `Account` itself. Rejected: `Account` is already
  the enforced isolation unit everywhere else in this codebase — every
  table's `AccountID` foreign key, RBAC (`permissions/`), Bedrock
  configuration. ADR-0032 just finished building a hierarchy (mesh domains)
  that lives *inside* one account on purpose, precisely to avoid a second
  competing notion of tenancy; inventing one here for aquifer/Bedrock scope
  would fragment exactly what ADR-0032 consolidated.

---

## Consequences

### Positive

- Closes a gap that is live today, not merely a SaaS prerequisite: any
  current deployment running more than one account already has zero
  relay-level tenant isolation, and misses Bedrock anchoring for every
  account past the first if enabled. This ADR is best read as fixing an
  existing security gap that also happens to be the prerequisite for SaaS.
- No wire or protocol change required. `spec/ponor-v1.md` §5.4 and the relay
  (`hub.rs`, `AquiferId`) already support a per-node value; the fix is
  confined to the Go control plane's roster rendering and scheduler
  bootstrap.
- Makes the aquifer and Bedrock-scheduler boundary consistent with the
  isolation unit (`Account`) already used everywhere else in the system,
  rather than introducing a new one.

### Negative

- **This is a live security fix as much as a feature**, and arguably should
  ship — at minimum the aquifer change — ahead of and independent from any
  product/billing SaaS work, rather than bundled into a "SaaS launch"
  milestone. Bundling it risks leaving an already-reachable
  multi-account misconfiguration unpatched longer than necessary.
- **Relay capacity is still not tenant-fair.** A large tenant can crowd out
  a small one sharing the same relay pool; not addressed here (see
  Reconsider if).
- **The shared-anchor-key decision is a judgment call**, not a proof. If
  ADR-0016's capability-scoping argument doesn't hold up under review here,
  the fallback (per-tenant keys) is real additional operational surface —
  provisioning, protected storage, rotation — this ADR does not design.
- **Migration needs an explicit transition, not an assumed one.** Any
  already-running deployment that already has more than one account (real,
  possible today) needs a re-roster on upgrade before every affected node's
  aquifer reflects its account. Mixed old/new roster state during rollout
  is a real window this ADR flags but does not design the rollout sequence
  for.

### Reconsider if

- A tenant ever needs relay-level QoS/capacity guarantees independent of
  node count — extend §7.4 with an account-scoped budget on top of the
  per-node one; a `spec/ponor-v1.md` change, its own decision.
- The shared-anchor-key assumption is rejected on review — design per-tenant
  anchor-key provisioning and rotation, likely deserving its own ADR given
  the operational weight it adds.
- A genuine cross-account relay-forwarding need ever arises (e.g. a
  "partner network" spanning two accounts) — would need an explicit
  multi-aquifer membership model per node, a real broadening of §5.4 the
  spec does not have today, and should not be backed into via this ADR's
  single-aquifer-per-account shape.

---

## Scoping note (2026-09-22): the audit log this ADR's §2 anchors is global, not per-account

Written while scoping the Bedrock-scheduler implementation this ADR's §2
described. §2's own text — *"`bedrock.Configuration`... is already correctly
account-scoped... The *scheduler bootstrap* does [have a gap]"* — undersold
the problem. Checked directly, rather than assumed from that framing:

- `bootstrap.Karst.Audit` is a single `*audit.Log` instance, constructed once
  per deployment, not once per account. `audit.Entry` (`audit/audit.go`)
  carries no `AccountID` column at all — `Seq`, `Actor`, `Action`, `Target`,
  `Detail`, and the hash-chain fields, nothing else. `Log.Head(ctx)` and
  `Log.VerifyFrom(ctx, ...)` (the two methods `bedrock.AuditHead` requires)
  take no account parameter and operate over the one shared, deployment-wide
  chain.
- `bedrock.Log` (`s.Log` in Scheduler, backing `karst_bedrock_configuration`'s
  sibling `karst_bedrock_log` table) genuinely *is* per-account, exactly as §2
  said — each account's own chain of `anchor`/`node-sign`/etc. entries is
  independently stored and verified.
- What an `anchor` entry commits to, though, is a `(AuditSeq, AuditHash)` pair
  read from that one shared `audit.Log` (`PrepareAnchor` → `s.Audit.Head(ctx)`
  → `anchor.go`'s `Anchor{AuditHead, AuditSeq}`). Confirmed live in the
  console-facing path that already exists: `api/nodes.go`'s
  `EntriesSinceAnchor` is `seq - state.Anchor.AuditSeq`, where `seq` comes
  from the same shared `h.audit.Head(ctx)` every account's handler calls.
  **An account with no activity of its own, sharing a deployment with a busy
  one, would see `entries_since_anchor` climb from other tenants' actions —
  today, in the single console handler that already ships**, not a
  hypothetical multi-account consequence.

### What this does and does not break

This is not a security hole in the sense of one tenant forging or reading
another's data: the shared chain is a single hash-linked sequence, so an
account's anchor arguably *does* still prove "everything up to this point,
across the whole shared log, is unmodified" — if anything, one tenant
enabling Bedrock enforcement incidentally strengthens tamper-evidence for the
whole shared log, since truncating the tail invalidates every account's
verification, not just the anchoring account's. What breaks is the
**framing**: Bedrock's mode/enforcement is a per-account operator choice
(`Configuration.Mode`), but what gets anchored and reported is a
deployment-wide quantity dressed as a per-account one, and the console
surface above already leaks that seam as confusing (not exploitable) numbers.

### Decision: fix the scheduler now; treat per-tenant audit partitioning as separate, larger, and explicitly deferred

The scheduler-bootstrap fix this ADR's §2 described is still correct and
worth shipping on its own: an account with Bedrock explicitly enabled
getting *zero* automated anchoring (today's actual behavior past the first
account) is strictly worse than getting anchoring against a shared log with
an honestly-scoped caveat. Splitting the audit log itself into per-account
partitions is a materially bigger change — a schema change to `audit.Entry`
(every write site needs an `AccountID` to tag, and some existing audit
actions are not obviously attributable to one account at all, e.g.
deployment-level IdP-sync or startup events) — and is out of scope for this
pass. §2's implementation proceeds as designed (dynamic per-account scheduler
management, one shared online anchor-signer key), with two additions:

- `EntriesSinceAnchor` and any equivalent per-account-looking Bedrock metric
  gets a one-line clarification in its console/API doc comment that the
  audit sequence it counts from is deployment-wide, not this account's own —
  a documentation fix, shippable immediately, independent of the scheduler
  work.
- This scoping note's finding is carried forward as a named "Reconsider if"
  trigger below rather than silently dropped once the scheduler fix ships.

### Reconsider if (added)

- Per-tenant confidentiality or a stronger tamper-evidence framing is ever
  required for the audit trail itself (not just Bedrock's enable/enforce
  toggle) — would need `audit.Entry` partitioned by account, a real schema
  and write-path change touching every audit call site, and deserves its own
  ADR given the size. Whether cross-account system-level events (IdP sync,
  startup, deployment-wide config changes) get a null/sentinel account or
  their own separate log is exactly the kind of question that ADR would need
  to answer, not this one.
