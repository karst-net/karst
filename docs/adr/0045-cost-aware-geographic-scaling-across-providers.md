<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-0045: Cost-aware geographic scaling across cloud and on-prem capacity

- **Status:** Proposed
- **Date:** 2026-10-04
- **Deciders:** TBD
- **Related:** ADR-0008 (relay infrastructure and funding — the "single region,
  single point of failure" gap this ADR addresses), ADR-0021 (relay telemetry —
  the demand signal), ADR-0038 (per-aquifer relay capacity — the capacity unit),
  ADR-0039 (air-gapped scope — the zero-cloud floor this must not break),
  ADR-0016 (capability-scoped authorities — the model for scoping the scaler's
  credentials), `deploy/kubernetes/`, `deploy/compose/ha/`. Tracking issue: TBD.

---

## Context

ADR-0008 settled who pays for relay bandwidth (the operator) and left one
problem standing in its own words: *"a single relay is a single region, so a
geographically spread aquifer gets poor fallback latency, and it is a single
point of failure."* Its answer is that "self-hosters wanting multi-region
fallback must configure something." Today that "something" is a human
registering relays in the registry and deciding where, how many, and on whose
account.

Organizations with that problem rarely have one kind of capacity. A realistic
operator holds some mix of:

- **On-prem / colo / owned hardware.** Cost is largely **fixed** (capex or a
  committed circuit). Marginal cost of one more GB is near zero *until the
  capacity or the uplink is full*, at which point it is infinite, not
  expensive.
- **Hyperscaler accounts (AWS, Azure, others).** Cost is **variable**, billed
  on several independent meters: instance-hours, GB egress, GB transferred
  cross-region or cross-AZ, public IPv4 address-hours, and so on.
- **Other providers** (commodity VPS, bare-metal hosts, sovereign clouds) with
  their own shapes — often a flat monthly price with a bundled egress
  allowance, then a per-GB overage.

The goal is to place and size relay (and, later, other horizontally scalable)
capacity across these pools so a stated **SLA is met at minimum cost**, and to
do it geographically — more capacity near where clients are, less where they
are not.

### Why this is not "just autoscaling"

Three properties of the cost structure make a per-provider autoscaler the
wrong tool, and they are the reason this needs a decision rather than a
script:

1. **Prices are not scalars; they are stateful functions.** A tiered meter
   ("first W hours/GB at X, next Y at Z") means the *marginal* price of the
   next unit depends on **month-to-date usage of that meter**, and resets on
   the billing cycle. Free allowances are the same thing with X = 0. Tiers
   can be *graduated* (each band priced separately) or *volume* (the whole
   quantity reprices at the tier reached) — both exist in the wild and they
   optimize differently. A placement that is cheapest on the 1st of the month
   can be the most expensive on the 28th.
2. **Traffic cost lives on edges, not nodes.** What a relay costs depends on
   *where its traffic goes*: egress to the internet, to another region of the
   same provider, to another provider, or to on-prem over a private link are
   five different prices. Cost is therefore a function of
   (pool, pool) pairs — a matrix — not of the pool alone. Placing a relay next
   to the clients it serves can be cheaper *or* dearer than placing it next to
   cheap egress, and the answer changes per aquifer.
3. **Fixed and variable costs interact.** On-prem is sunk, so the optimizer
   should fill it first — but only up to its capacity and uplink, and only
   where its latency satisfies the SLA. Everything beyond that spills to
   metered capacity, where tier position and commitments (reserved instances,
   savings plans, negotiated discounts) now matter.

Cloud-native autoscalers (ASG, VMSS, cluster autoscaler) optimize one account
against one meter. None of them knows that the cheaper place to serve São Paulo
this month is the on-prem rack in Miami that is 40% idle.

### What is already in the tree

- `bins/karst-relay` exposes Prometheus metrics, and per ADR-0021 pushes signed
  aggregate telemetry to the control server — the demand signal exists.
- ADR-0038 gives a per-aquifer aggregate token-bucket budget — a unit in which
  to *size* capacity.
- The relay registry already carries a region map and latency-probed selection
  (PLAN.md Phase 4). Clients already choose among relays; scaling does not
  need a new client-side mechanism, only a way to change what is in the
  registry.
- ADR-0008 §6 makes signed-roster admission **mandatory** for pool relays.
  A relay that appears automatically is only usable if its enrollment is also
  automatic and still signed — this is the hard integration point (see
  Decision §6).

### Constraints that eliminate options before preference applies

- **Karst is self-hosted-first (ADR-0008) and has an air-gapped mode
  (ADR-0039).** A deployment with zero cloud accounts, or zero network egress,
  must work exactly as it does today. The scaler is optional and its absence
  must not be observable.
- **No hardcoded prices.** Provider prices change, differ by region, and are
  overridden by negotiated contracts. A baked-in table is wrong on arrival.
- **Cloud credentials are a new, high-value secret** in a system whose product
  is security. The scaler can be compromised like anything else; the design
  must bound what that costs.
- **Billing data lags.** Invoices and cost-explorer APIs trail usage by hours
  to days. Real-time decisions run on *metered estimates*, not on the bill.

---

## Decision

Introduce an **optional, provider-neutral capacity planner** that treats every
account — cloud or on-prem — as a *capacity pool* with a declarative cost model,
and continuously chooses pool sizes to satisfy a declared SLA at minimum
estimated cost. It is delivered in phases; each phase is independently useful
and the first two actuate nothing.

The working name is **`karst-scaler`**. Naming follows ADR-0010; the name is a
placeholder until that is settled.

### 1. Capacity pools

A pool is the unit the planner reasons about:

```
pool {
  id, provider,           # aws | azure | gcp | onprem | generic
  region / site,          # geography, with coordinates or a latency-probe target
  capacity {              # hard ceilings; on-prem is bounded, cloud is "large"
    nodes_max, uplink_mbps_max, ...
  },
  min_nodes,              # floor: N+1 / always-on presence
  cost_model,             # §2
  driver                  # §5; how nodes are actually created and destroyed
}
```

On-prem is a pool whose cost model is "fixed amount per period, zero marginal
price, finite capacity." It is not a special case in the planner — it is a
pool whose marginal price curve is flat at zero and then vertical.

### 2. Cost model: declarative, composable, stateful

Cost is expressed as **data**, not code, and composed from three primitives:

- **Meter** — a quantity with a unit and a billing period:
  `instance_hours`, `egress_gb`, `ipv4_hours`, `provisioned_mbps`, …
- **Price schedule** attached to a meter — an ordered list of bands
  `[{up_to, unit_price}, …]` with an explicit `mode: graduated | volume`, an
  optional `free_allowance`, and a `period` (month, or the provider's actual
  cycle anchor). Minimum billing increments (per-second vs per-hour, minimum
  one minute) are part of the schedule, because they set the *cost of
  churn*.
- **Edge price** — a price schedule keyed on a **(source pool, destination
  class)** pair, where class is one of `internet`, `same-region`,
  `cross-region`, `cross-provider`, `private-link`. This is where
  cross-region and "within-AWS" traffic pricing lives.

Plus **commitments**: a reserved or savings-plan quantity is a prepaid band at
price zero (or a discounted rate) that the optimizer consumes before reaching
on-demand, with the commitment's own cost counted whether or not it is used.

Sources of the numbers, in precedence order:

1. Operator-supplied overrides (contracts, EDP/MACC discounts, committed
   spend) — authoritative.
2. Provider public price APIs where they exist (the AWS Price List and Azure
   Retail Prices APIs are public and unauthenticated), fetched by a separate
   helper and **committed as a reviewable file**, never silently
   hot-reloaded into decisions.
3. Nothing else. A pool with no cost model is rejected at validation, not
   defaulted to "free."

The planner tracks **month-to-date usage per meter per pool**, so a tier
position is state it owns, rebuilt from relay telemetry (ADR-0021) and
reconciled against provider billing exports when they arrive. Where estimate
and bill diverge, the bill wins and the divergence is exported as a metric —
it is the planner's own calibration error.

### 3. SLA as constraints; cost as the objective

The SLA is the **constraint set**; cost is only minimized *inside* it.
Nothing trades SLA for savings unless the operator explicitly marks a
constraint `soft` with a penalty.

Initial constraint vocabulary (deliberately small):

| Constraint | Example |
|---|---|
| Latency | for clients in region R, p95 RTT to nearest relay ≤ X ms |
| Availability | survive loss of any one pool / any one region (N+1, N+region) |
| Headroom | provisioned capacity ≥ demand × (1 + h) at the 95th percentile of the last window |
| Residency | aquifer A's relays only in pools tagged `eu` (compliance) |
| Budget | month-to-date + projected spend ≤ cap (§7) |

Residency and trust constraints are **hard and not tradeable for cost**. A
cheaper pool in a disallowed jurisdiction is not a candidate, not a
penalized candidate.

### 4. The planner

Inputs: demand per (region, aquifer) from relay telemetry; pool state and
month-to-date meter positions; the cost models; the constraints.
Output: a desired node count per pool, plus the **estimated cost delta and the
constraint that bound the choice**, so every decision is explainable.

Because tiered and volume pricing make the cost curve **non-convex**, a
greedy "pick the cheapest next unit" strategy is wrong in exactly the cases
that matter (it will refuse to move into a pool whose price falls after a tier
boundary). The problem sizes are small — tens of pools, not thousands — so the
planner uses an exact or near-exact search over pool allocations (a small
mixed-integer program, or bounded enumeration with the on-prem-first ordering
as the incumbent) rather than a heuristic. The solver choice is an
implementation detail; the requirement is **"never worse than the on-prem-first
greedy baseline, and says so."**

Stability is a first-class requirement, not an afterthought:

- **Hysteresis and minimum dwell.** Scale-down requires the lower demand to
  persist for a window at least as long as the pool's billing increment;
  creating then destroying a node inside a minimum-billed hour is a pure loss.
- **Scale-up leads demand.** Instances take time to boot and enroll (§6);
  headroom must cover that lag or the SLA is violated during the very ramp the
  scaler is reacting to.
- **Drain, don't kill.** A node chosen for removal is removed from the
  registry first, allowed to shed its clients to other relays (this
  relies on clients re-homing when a relay leaves the registry, which Phase 0
  must verify rather than assume), and destroyed only once its session count
  falls under a threshold or a drain deadline passes.

### 5. Drivers: actuation behind a narrow interface

The planner never calls a cloud API. It emits desired state to a **driver**
that implements roughly four verbs — `list`, `create(n)`, `drain(id)`,
`destroy(id)` — against one pool. Initial drivers worth building:
Kubernetes (`deploy/kubernetes/operator` already exists), one hyperscaler
(AWS, as the most common), and a **no-op/"advise" driver** that records what
it *would* do. Azure and others follow the same interface. Existing
infrastructure-as-code (Terraform, Crossplane, ASG/VMSS) is a valid *driver
implementation*: the planner decides the number, the driver delegates to
whatever the operator already trusts.

### 6. Security boundaries (the part that must not be skipped)

- **The scaler is a separate process and separate trust domain** from the
  control server. The coordination server must not gain cloud-account
  credentials as a side effect of this feature. A compromise of the control
  plane must not yield the ability to spend the operator's money.
- **Least-privilege, tag-scoped credentials.** Each driver's credential may
  create/destroy only resources carrying a Karst ownership tag, in the pool's
  own account/region, bounded by instance-type and count. It must not be able
  to create IAM principals, open arbitrary security-group rules, or touch
  untagged resources. This follows ADR-0016's capability-scoped model rather
  than inventing a new one. (Concretely: an AWS role with a tag-conditioned
  policy, an Azure role scoped to one resource group.)
- **Automatic enrollment stays signed.** A scaled-up relay must obtain its
  identity and roster admission through the existing signed path (ADR-0008 §6
  admission control; ADR-0021 ML-DSA-87 identity) — via a short-lived,
  single-use enrollment token minted for that specific instance — never a
  long-lived shared secret baked into an image. No new bypass of roster
  admission is acceptable, even for the scaler.
- **Spend is bounded independently of the planner's correctness.** The budget
  cap (§3) is enforced as a **circuit breaker in the driver layer**, not only
  inside the optimizer: a bug in the planner, corrupt telemetry, or a
  malicious demand spike (a metered-bandwidth DoS is also a billing attack)
  must not be able to scale without limit. Hard ceilings on node count per
  pool and per period are mandatory configuration, with no "unlimited"
  value.
- **Demand telemetry is treated as untrusted-ish input.** It comes from relays
  that may be compromised or misreporting; the planner clamps per-relay
  contributions and ignores a relay whose report is not signed by its roster
  identity.

### 7. Phasing

| Phase | Deliverable | Actuates anything? |
|---|---|---|
| **0 — Cost model and simulator** | The declarative schema (§2); an offline tool that replays recorded relay telemetry against a cost model and reports spend per pool, per meter, per edge. | No |
| **1 — Advisor** | The planner and constraint set (§3, §4) running continuously, publishing "recommended vs actual" as metrics and a console view. Humans act on it. | No |
| **2 — Reactive actuation** | Drivers (§5), enrollment (§6), circuit breaker. Scales on observed demand with headroom. | Yes, bounded |
| **3 — Predictive scaling and pattern of life** | A forecaster behind the same planner interface: learns daily/weekly/seasonal demand per (region, aquifer) and leads the ramp. | Yes |

Phases 0 and 1 deliver most of the *insight* with none of the credential risk,
and they are the empirical basis for deciding whether Phase 2 is worth its
attack surface. They can be the stopping point for an operator who never wants
auto-actuation.

### 8. Predictive scaling (Phase 3) — constraints recorded now

The future refinement is in scope of the design, not of the first
implementation. Its shape is fixed here so Phases 0–2 do not paint it into a
corner:

- The forecaster **may only move *when* capacity is added, never *whether* an
  SLA constraint holds.** The reactive path from Phase 2 remains the floor; a
  wrong forecast costs money, never availability. Forecast confidence widens
  headroom or is ignored — it is never trusted to *remove* headroom below the
  reactive requirement.
- **Phase 0–1 must record the history it will need** — per (region, aquifer)
  demand at a fixed resolution, with the calendar context to explain it —
  because a forecaster has no data on day one, and starting retention at
  Phase 3 wastes the months that would train it.
- **Pattern-of-life data is itself sensitive.** When an organization's traffic
  rises and falls is metadata about the organization (shift patterns, incident
  response, exercises). It is stored and processed **inside the operator's
  deployment only**, subject to the same retention and access controls as
  audit data, and is never sent to a Karst-operated service. This is the
  same line ADR-0008 draws on relay metadata.
- Known events (a planned migration, a company all-hands, a holiday calendar)
  are first-class operator inputs — often more valuable than inferred
  seasonality.

### Alternatives rejected

- **Per-provider native autoscaling only (ASG, VMSS, cluster autoscaler,
  Karpenter).** Rejected *as the decision-maker*: each optimizes one account
  against one meter and cannot know that the cheaper place to serve a region
  this month is idle on-prem capacity, or that a tier boundary is about to
  change the answer. Retained *as driver implementations* (§5), which is
  where they are good.
- **A single scalar "cost per GB" per provider.** Rejected: it is the
  simplest model and wrong in precisely the ways §Context lists — it cannot
  express tiers, free allowances, cross-region edges, or commitments, so it
  would pick the wrong pool in the cases where the choice is worth money.
- **Operator edits infrastructure-as-code by hand (status quo).** Rejected as
  the answer, retained as a floor: it is what ADR-0008 prescribes today and it
  does not scale with geography or time. Phase 0–1 are explicitly designed so
  operators who stop there lose nothing.
- **Cost reporting and FinOps tooling (cloud cost explorers, Kubecost,
  Infracost).** Rejected as the mechanism: they report after the fact or per
  account. They cannot choose a placement, and none spans on-prem plus
  several clouds with the SLA as a constraint. Their *data* is a useful
  reconciliation input for §2.
- **Greedy cheapest-next-unit placement.** Rejected: non-convex tier pricing
  makes it systematically wrong (§4). Retained only as the baseline the real
  planner must beat.
- **Predictive-first.** Rejected: there is no historical data on day one, a
  forecast-driven system that is wrong fails by under-provisioning (an SLA
  breach) or by over-provisioning (a cost breach), and it is not debuggable
  without the reactive path to compare against. Prediction is Phase 3 for
  that reason, not for lack of interest.
- **Fold the planner into the coordination server.** Rejected on trust
  grounds (§6): it would put cloud spend authority inside the component whose
  compromise is already the worst case.
- **A Karst-operated managed scaling service.** Rejected: ADR-0008 §5 rules
  out a Karst-operated fleet, and a service that held operators' cloud
  credentials and traffic-pattern history would be the most sensitive thing
  Karst could run.

---

## Consequences

### Positive

- Closes the multi-region and single-point-of-failure gap ADR-0008 left open,
  without a new client mechanism — only the registry's contents change.
- Makes the fixed-versus-variable cost trade explicit and auditable: every
  placement decision records its estimated cost and the binding constraint.
- Phases 0 and 1 have standalone value (a cost simulator and advisor) with no
  new credentials and no actuation.
- On-prem is a first-class pool, so an organization with owned capacity is not
  forced to treat it as an afterthought to a cloud-first tool.
- The driver interface keeps the planner independent of any one provider and
  lets operators reuse the IaC they already trust.

### Negative

- **A cloud-spend credential enters the Karst ecosystem for the first time**
  (Phase 2). That is a standing new attack surface in a security product, and
  the mitigations in §6 reduce it without eliminating it. An operator who
  never enables Phase 2 never takes the risk.
- **The cost models are a maintenance burden Karst does not control.**
  Provider pricing changes; negotiated discounts are invisible to us;
  estimates will drift from invoices. The planner's usefulness is bounded by
  the accuracy of data it is handed, and "the model is stale" will be the
  most common failure.
- **Decisions run on estimates, not bills,** because billing lags. A
  well-behaved planner can still overspend if its meters under-count.
  Reconciliation reduces this; it does not remove it.
- **Scope pressure.** This is infrastructure-management software adjacent to a
  VPN. It will attract requests (more providers, more resource types, spot
  instances, GPU) that have nothing to do with the mesh. The decision to ship
  Phases 0–1 first is partly a defense against building a cloud-cost product
  by accident.
- **Optimizer complexity.** A non-convex planner is harder to reason about
  and test than a threshold autoscaler, and "why did it do that" must be
  answerable or operators will turn it off.
- **A metered-bandwidth attack is also a billing attack.** Demand-driven
  scaling converts a traffic flood into cloud spend. The circuit breaker
  bounds that; it does not make it free.
- **Irreversible if it reaches data:** once pattern-of-life history is
  collected (Phase 0–1 retention), it exists and can be subpoenaed or
  exfiltrated like any operational data. Retention length is a security
  decision, not just a modeling one.

### Reconsider if

- Phase 1 advisor output shows operators cannot supply accurate cost models —
  if the inputs are not obtainable, the optimizer's precision is fiction.
- Phase 1 shows the on-prem-first greedy baseline is within a few percent of
  the planner on real topologies; then the non-convex solver is not earning
  its complexity.
- A credible way to meet SLA without long-lived cloud credentials appears
  (for example workload-identity federation making the credential short-lived
  and non-exportable by default); that would change the §6 risk calculus.
- Operators overwhelmingly want a managed service rather than self-run
  scaling; that conflicts with ADR-0008 §5 and would need that ADR revisited
  first.

---

## Open questions

These are real unknowns to resolve in Phase 0, not rhetorical ones.

1. **What scales?** Relays are the obvious first target (stateless-ish,
   bandwidth-heavy, already in a registry). Do TURN gateways, exit nodes,
   subnet routers and regional coordination replicas share the same pool
   abstraction, or do they need different handling (they carry state, or are
   tied to specific networks)?
2. **How is demand attributed to a region?** Relay telemetry says what a relay
   carried, not where the *unmet* demand is. Home-relay selection already
   clusters clients; do we need client-reported RTT histograms (more
   metadata) or is relay-side data enough?
3. **Which SLA metric is operator-meaningful?** p95 RTT to nearest relay is
   measurable by clients but is not the same as an application SLA. The
   vocabulary in §3 should be validated against real operators before it is
   frozen.
4. **Spot / preemptible capacity.** Large savings, but preemption interacts
   badly with long-lived sessions and with N+1 accounting. Out of scope for
   Phases 0–2 unless Phase 1 shows the savings justify the complexity.
5. **Commitment planning is a different problem** (buy a one-year plan or
   not). The planner consumes commitments; recommending them is out of scope
   here, though Phase 0's simulator is the right place to evaluate one.
6. **Multi-aquifer cost attribution.** ADR-0038 gives per-aquifer capacity;
   chargeback of shared pool cost across aquifers (relevant to the
   multi-tenant case, #166) is a separate decision.
7. **Default retention for demand history** (§8): long enough to see
   seasonality, short enough to bound the sensitivity.
