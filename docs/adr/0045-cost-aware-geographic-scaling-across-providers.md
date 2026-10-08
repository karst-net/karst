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
  credentials), ADR-0023 (declining device-activity visibility — the authority-
  asymmetry reasoning §4a below applies to demand attribution) and ADR-0046
  (NOC location/visibility policy — the companion decision this one stays
  consistent with), ADR-0048 (relay self-reported location via cloud
  metadata — §4b's anchor dispatcher follows the same plain-function,
  no-trait-until-a-second-provider pattern), ADR-0037 (operator-granted
  tenancy grants — §4c's `allowed_regions` follows the same file-loaded,
  operator-only, no-self-service-endpoint-yet shape), `deploy/kubernetes/`,
  `deploy/compose/ha/`. Tracking issue: #234; re-homing hardening (Phase 0b):
  #233.

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
  (PLAN.md Phase 4). Clients already choose among relays (`ponor-v1.md` §9,
  `bins/karstd/src/home.rs`), so scaling needs no new *selection* mechanism —
  but it does depend on how fast and how gracefully that mechanism reacts.
  That was checked rather than assumed; see **Verified: client re-homing**
  below, which found gaps that must close before Phase 2.
- ADR-0008 §6 makes signed-roster admission **mandatory** for pool relays.
  A relay that appears automatically is only usable if its enrollment is also
  automatic and still signed — this is the hard integration point (see
  Decision §6).

### Verified: client re-homing (checked against the tree, 2026-10-04)

The first draft of this ADR assumed clients re-home when a relay leaves the
registry. Reading `home.rs`, `run.rs` and `spec/ponor-v1.md` §9:

**Works today**

- *Withdrawn relay.* `Selector::retain` releases a relay the netmap no longer
  lists, even if it was the choice (`home.rs`, test
  `a_withdrawn_relay_is_released_even_if_it_was_the_choice`). `home_target`
  then moves the home connection to the best measured relay, or the first in the
  registry if nothing is measured, and `handover` keeps the old relay as an
  on-demand connection so peers still pointing at it are not black-holed until
  the netmap propagates.
- *Dead relay.* After `HOME_RELAY_ATTEMPTS` (3) failed connects the node
  abandons the relay and walks the registry (`abandon_relay`), with backoff that
  survives the move.
- *Hysteresis.* §9.2's margin (the larger of 20 ms or 20%) must be beaten on
  `HYSTERESIS_SAMPLES` (3) consecutive rounds, and the relay held at start-up
  is treated as an incumbent.

**Gaps that matter for scaling and for mobile clients**

1. **A busy home connection does not move.** `moved_home` is checked only on the
   send loop's *idle* path (`relay_send_loop`, `run.rs`), "because a relay
   change is a thing that happens in minutes." A node with continuous traffic
   never reaches that branch, so a *chosen* move, and the move away from a
   relay the scaler is draining, can be deferred indefinitely. This is
   precisely the case of a client in transit that is also in use.
2. **Reaction time is tens of minutes.** `PROBE_INTERVAL` is 60 s;
   each alternative is measured for `PROBE_ROUNDS` (4) consecutive rounds, then
   `REST_ROUNDS` (6) rounds pass before the next candidate. With *N*
   alternatives a specific one is measured roughly every 10·*N* minutes, then
   needs three more wins. A device that has just changed networks, or a
   geography that has just woken up, waits that long for a better relay.
3. **No network-change trigger.** `run.rs` already re-enumerates interfaces and
   calls `rediscover` for AVEN path discovery, but nothing there resets or
   accelerates the home-relay `Rotation` or `Selector`. A roam is invisible to
   relay selection until the slow cycle comes round.
4. **`Restarting` is specified but unused.** `ponor-v1.md` §7.6 says a relay
   SHOULD send `Restarting(reconnect_in_ms, try_for_ms)` before a planned close,
   and clients SHOULD jitter. The frame exists in `karst-relay-proto`, but
   `karst-relay` never sends it and `karstd` has no handler. Scale-down
   therefore has no graceful-drain signal: a relay removed by the scaler drops
   its clients at once, who then take the dead-relay path (three attempts plus
   backoff) rather than a coordinated, jittered move.
5. **Selection is purely latency.** The selector knows nothing about relay
   load, cost or a drain request. That is correct for §9.2's goals, and
   means a planner can influence placement only by changing *which relays
   exist and where*, not by steering clients.

These gaps are independent of this ADR — gap 1 and gap 3 matter to any
roaming client today — which is why the remediation (§7, Phase 0b) is scoped
as its own work item rather than a sub-task of the scaler.

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
  id, provider,           # aws | aws-gov-cloud | azure | azure-gov-cloud | gcp | onprem | generic
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

A region can also exist below the level of a pool at all: a **candidate
region** (§4b) has no cost model, no capacity, no driver — just a region
code and a way to measure RTT against it. It is not provisioned and costs
nothing; it exists purely to be measured, and is promoted into a real pool
only once §4b's aggregate signal and §2's cost model together justify it,
**and only if §4c's allowlist permits that region at all.**

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
  cross-region and within-provider traffic pricing lives.

Plus **commitments**: a reserved or savings-plan quantity is a prepaid band at
price zero (or a discounted rate) that the optimizer consumes before reaching
on-demand, with the commitment's own cost counted whether or not it is used.

Sources of the numbers, in precedence order:

1. Operator-supplied entries (contracts, EDP/MACC discounts, committed
   spend, a colo's rate card) — authoritative.
2. Provider public price APIs where they exist (the AWS Price List and Azure
   Retail Prices APIs are public and unauthenticated), fetched by a separate
   helper and **committed as a reviewable file**, never silently
   hot-reloaded into decisions.
3. Nothing else. A pool with no cost model is rejected at validation, not
   defaulted to "free."

**A provider with no API is a first-class case, not a degraded one.** A small
colocation or VPS host's pricing is entered by an administrator in the same
schema an API fetch would populate — the schema is the contract, and an API
helper is only one way of writing it. Every entry carries `as_of` and an
optional `review_by`; the planner warns, and in Phase 2 refuses to *add*
capacity to a pool whose model is past `review_by`, so a stale hand-entered
price cannot silently drive spend. Operator entries override fetched ones
field by field, so a negotiated discount on top of a list price is a
two-line file.

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

Residency as written here is a **per-aquifer** tag match — it says which
*tagged* pools a given tenant's relays may land on, among pools that
already exist. It presumes the pool itself was something the operator was
willing to have at all. §4c adds the layer underneath that: a
deployment-wide bound on which regions may ever become a pool in the
first place, regardless of aquifer. Per-aquifer residency can only narrow
within what §4c allows — it is never a way to reach a region §4c
excludes.

### 4. The planner

Inputs: demand per (region, aquifer) from relay telemetry, including the
aggregate RTT-histogram signal §4a adds; pool state and month-to-date meter
positions; the cost models; the constraints.
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
  registry first, allowed to shed its clients to other relays (clients
  do re-home when a relay leaves the registry, but a busy connection may not
  move and no graceful-drain signal is sent today — see *Verified: client
  re-homing* and Phase 0b), and destroyed only once its session count
  falls under a threshold or a drain deadline passes.

### 4a. Demand attribution: an aggregate RTT signal, not client location

This resolves Open Question #2 below. A pure client *count* per relay
(ADR-0021's existing telemetry) cannot distinguish "this relay is well
placed" from "this relay is the least-bad option a distant group of
clients is stuck with" — a count says nothing about quality. The
concrete case that exposes this: an organization's usual East Coast
users fly to a West Coast conference. Their clients keep using their
usual relay (nothing closer exists to measure against), so the
headcount barely moves — only the RTT to it gets worse.

The signal that is actually missing is *how badly served clients are*,
not *where they are*. That can be measured and reported without
identifying or locating anyone:

- **A relay already measures round-trip latency to every client it
  terminates a connection with** — no new client cooperation, no new
  reporting from the node side. ADR-0021's existing signed telemetry
  push gains one more aggregate field: a bucketed RTT histogram ("N
  clients under 20 ms, N at 20–50 ms, N at 50–100 ms, N over 100 ms").
  Bucketed and relay-wide, matching the aggregate-only discipline
  ADR-0021 already established for `local_clients`/`mesh_peers`/
  `bytes_total` — this is an extension of that same wire format by one
  field, not a new reporting channel.
- **The planner never resolves where a client is.** It evaluates the
  RTT-histogram signal against pools it already has declared locations
  for (§1's `pool { region/site, geography, ... }`) — the same
  operator-declared-location principle ADR-0046 §1 uses for the NOC
  map. A fat high-latency tail on relay R tells the planner "something
  near R is underserved"; deciding *where* to respond means picking the
  best-fitting pool among ones the operator already registered as
  candidates, never discovering a new point on the map from a client's
  address.
- **The real prerequisite is pool coverage, not location data.** If an
  operator never registered a West Coast candidate pool (even at
  `min_nodes: 0`), the planner has nothing to activate no matter how bad
  the RTT signal gets — that is a provisioning decision for the
  operator, not something the scaler can route around by locating
  people. Demand-history retention (§8, Open Question 7) should keep
  this histogram per relay, not any client-identifying key.

### 4b. Discovering a wholly new region: provider-operated anchors, not client location

§4a's own prerequisite is the gap this closes: a relay-side histogram can
say "something near me is underserved," never *which direction* — and if
the operator never registered a candidate pool anywhere nearby, the
planner has nothing to point at no matter how bad the signal gets. Only
the client, sitting at the point of the complaint, can supply directional
information. The discipline that makes this acceptable is the same one
§4a already established, applied to a different measurement: the client
never reports *where it is* — it reports RTT to a small set of known,
fixed points, and the server folds that into a histogram **per point**,
discarding the reporting node's identity once aggregated.

**The points are the cloud provider's own infrastructure, not ours.**
Every AWS region runs a permanent, multi-tenant, public endpoint that
exists whether or not we are a customer of it — `s3.<region>.amazonaws.com`
resolves to an address physically inside that region and completes a TCP
handshake with no authentication required. This is not a novel trick:
public tools (e.g. cloudping.info) have measured browser-to-region latency
this way for years, against the exact reachability S3's regional endpoints
are built to offer. The client times the TCP handshake, not an ICMP ping —
ICMP is widely filtered by providers and corporate networks alike, and
sending it needs a raw socket `karstd` does not otherwise require; a plain
`connect()` to port 443 needs neither.

**Nothing of Karst's own is provisioned anywhere for this.** Not an
ephemeral instance, not a standing probe VM, nothing to patch or
decommission. Discovering the candidate list needs no CIDR data either —
a small, stable, public list of AWS region codes plus ordinary DNS
resolution is the entire input. (AWS's published `ip-ranges.json` is a
defense-in-depth cross-check against DNS spoofing, if ever wanted — not a
requirement for the mechanism to work.)

**One anchor pattern per provider, each verified against the real
service (2026-10-08).** The same bar applies to every provider: a
permanent, multi-tenant, public endpoint per region that completes an
unauthenticated TCP handshake, needs nothing provisioned, and is keyed by
the provider's own region code so §4c's `allowed_regions` lists drive it
with no mapping table.

| Provider | Anchor | Coverage | Evidence the address is in-region |
|---|---|---|---|
| AWS | `s3.<region>.amazonaws.com` | all regions | `ip-ranges.json` tags each prefix with its region |
| Azure | `<region>.livediagnostics.monitor.azure.com` | every public region tried except `westcentralus` | each address sits in that region's own `AzureCloud.<region>` prefix in the published service tags; no address is shared between regions |
| Azure (fallback) | `<region>.api.cognitive.microsoft.com` | 37 regions, including `westcentralus` | same check, 37 of 37 in-region, none shared |
| GCP | `storage.<region>.rep.googleapis.com` | 45 of 47 regions (not yet `asia-southeast3`, `europe-west15`) | Google documents that traffic to a regional endpoint is "processed and TLS terminated entirely within the specified region"; each region resolves to its own distinct address |

What these replace, and why the obvious candidates fail:

- **GCP's default storage endpoint is global anycast**, as is every
  `<region>-<service>.googleapis.com` name checked (`-aiplatform`, `-run`,
  `-docker.pkg.dev`): every region resolves to the same handful of
  addresses, so a handshake measures distance to Google's edge, not to the
  region. The regional endpoints (`*.rep.googleapis.com`, built for data
  residency) are the exception, and the only GCP names that pass.
- **Azure Storage has no per-region shared hostname** — account names are
  global, so a storage anchor would need one account per region, which is
  the provisioning §4b exists to avoid. Azure Monitor's Live Metrics
  ingestion endpoint is the service that does pass. Regional ARM
  (`<region>.management.azure.com`) looks regional and is not: every region
  resolves to the same two front-door addresses.
- **GCP is the weakest of the three.** The regional-endpoint addresses are
  in Google's services ranges (`goog.json`), not the region-tagged
  `cloud.json`, so there is no published address-to-region mapping to
  cross-check against the way `ip-ranges.json` and the Azure service tags
  allow. The evidence is Google's documented in-region TLS termination plus
  one distinct address per region. An RTT check from two distant vantage
  points (near/far must flip between them) is what closes that gap, and
  should be done before the GCP arm ships.

The dispatcher stays ADR-0048's shape — a plain function per provider, not
a trait — with each arm formatting its own hostname from a region code. A
region whose anchor does not resolve (GCP's newest regions, Azure's
restricted ones) is simply unmeasured, not an error.

**None of these services exist to be probed.** Each is a provider's
production endpoint, used here for reachability it already offers, and
each can change: regional ARM shows exactly how a regional-looking name
ends up behind a global front door. The guard is cheap and lives outside
the client — a periodic check (CI or a scheduled job) that resolves every
allowlisted region's anchor and fails if any two regions share an address,
which is the signature of a service moving behind anycast. Checking
resolved addresses against each provider's published region ranges, where
one exists, is the same defense-in-depth cross-check already described
for AWS above.

**New client-side network dependency, same treatment as ADR-0048's relay
side.** This is telemetry `karstd` does not emit today — §4a's histogram
is relay-side only. It needs its own opt-in flag, defaulting off, and
must be a true no-op in air-gapped deployments (ADR-0039): a node that
never enables it never resolves a single provider hostname. Default-off for
the same reason `detect_location` is default-off on the relay side —
every node silently gaining a new outbound target on upgrade is the
"quietly ignored, not told" pattern this project avoids elsewhere;
opting in costs one config line.

**No AZ granularity, and it isn't needed.** Each provider's region list is
the resolvable unit; there is no public, free way to distinguish AZs
within a region this way, and AZs within a region are typically
sub-millisecond apart by design. The decision this signal feeds is which
*region* to stand capacity up in — AZ placement within a chosen region is
a capacity/availability decision, not a latency one.

A candidate region is promoted to a real pool (§1) — gaining a cost model
(§2) and a driver (§5) — only when the aggregate signal here shows a
meaningful share of currently badly-served clients would get materially
better RTT there, weighed against what standing it up would cost. Until
then it costs nothing and commits to nothing.

### 4c. Bounding where any resource may ever be created: a deployment-wide region allowlist

§4b makes the planner capable of noticing a region it has never been told
about. That is exactly the moment a real operational risk shows up: an
organization can have reasons — sanctions exposure, data-residency
obligations, a board-level "we do not operate infrastructure in country
X," or simply not wanting to explain to legal why a relay appeared
somewhere nobody chose — to never have Karst stand anything up in a given
region, independent of cost or latency. §4b's own candidate-discovery
capability is what makes this worth deciding explicitly now rather than
assuming it will never come up: before this ADR, the only regions in play
were ones an operator typed in by hand; after it, the system itself
proposes ones nobody did.

**The mechanism is an allowlist, not a denylist, enforced in two places.**

- **At discovery (§4b).** The anchor dispatcher only ever enumerates and
  probes region codes present in the operator's `allowed_regions` list for
  that provider. A region not on the list is never measured, never
  resolved, never appears in the Phase 1 Advisor's output as a
  possibility — it generates zero network traffic of any kind, because it
  was never a candidate to begin with. This is deliberately stronger than
  "don't recommend it": the system never even looks.
- **At pool creation (§1), for every pool regardless of how it was
  proposed.** A pool — operator-declared by hand, or a candidate region
  being promoted by the planner — is validated against the allowlist for
  its provider before it can exist at all, with the same named-field,
  fail-fast rejection style `relayreg.go`'s `compile()` already uses for a
  malformed declared location. This is the actual backstop: it catches an
  operator's own typo the same way it catches anything the planner might
  otherwise have proposed, and it does not depend on §4b having run
  first — an operator who never enables region discovery and only ever
  adds pools by hand still gets the same guardrail.

**Allowlist, because a denylist fails open.** A provider opening a new
region tomorrow is automatically *excluded* under an allowlist until an
operator deliberately adds it, and automatically *included* under a
denylist until someone remembers to block it. The harm this section
exists to prevent — something appearing somewhere nobody intended — is
exactly the failure mode a denylist cannot structurally rule out and an
allowlist can.

**Scoped to region codes, not inferred jurisdictions.** The list is
`allowed_regions: { aws: [...], gcp: [...], azure: [...] }` — provider
region codes, the same identifier §1's pools and §4b's anchors already
use. Karst does not maintain its own mapping from region code to country
or legal jurisdiction to decide this *for* the operator — that mapping
can change, differs by who's asking (a compliance team's definition of
"in the EU" is not always a geography question), and getting it wrong
quietly would be worse than not having it, the same accuracy argument §4a
already made against GeoIP. An operator who wants "no EU regions" writes
down the EU region codes themselves; Karst enforces the list exactly as
written, nothing it infers on top of it. On-prem and `generic` pools are
exempt — their location is a single operator decision made once per pool,
not something auto-discovered or auto-proposed.

**A sovereign cloud with its own account/auth boundary is a separate
provider, not a region — but only where that boundary actually exists.**
AWS GovCloud and Azure Government are each a distinct partition from
their commercial cloud: a separate account (AWS) or tenant/ARM endpoint
(Azure), a separate ARN/resource-ID namespace, and separate pricing. Each
gets its own key — `allowed_regions.aws-gov-cloud`,
`allowed_regions.azure-gov-cloud` — independent of `allowed_regions.aws`
and `allowed_regions.azure`. Folding either under its commercial parent
would let a commercial-region entry (or a typo) reach across a boundary
the provider itself treats as a hard separation; keeping it a separate
provider means the allowlist can only ever widen one partition at a
time, by name. **GCP has no equivalent arm**, not because it was missed
but because it has no equivalent boundary: Google's government/compliance
offerings (Assured Workloads and similar) are policy layered onto the
same commercial account, API surface, and region list `gcp` already
covers — there is no second partition for a second provider key to name.

**Enforced independently of the planner's correctness, the same way §6
already requires for spend.** The allowlist check is not only a filter
inside the optimizer — it is also a hard gate in the driver layer (§5),
mirroring §6's "spend is bounded independently of the planner's
correctness" circuit breaker exactly. A bug in the planner, a corrupted
candidate list, or a compromised component upstream of the driver must
not be able to create a resource in a region the operator excluded; the
driver refuses regardless of what it is asked to do.

**No default.** Until an operator configures `allowed_regions` for a
provider, §4b's discovery for that provider does not run (it has nothing
to enumerate) and §1 pool creation for that provider is refused outright,
including by hand. This is a deliberate fail-closed default, not an
oversight: the alternative — defaulting to "every region" until someone
locks it down — is precisely the gap this section exists to close, and
this project's own convention is to tell an operator what they must set
rather than quietly assume the permissive answer (the same reasoning
`detect_location` and §4b's own opt-in flag already apply one level up).

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
- **The region allowlist (§4c) is enforced in the driver, not only in the
  planner.** Same shape as the budget circuit breaker above: a bug in the
  planner or a corrupted candidate list must not be able to create a
  resource in a region the operator excluded. The driver checks
  independently and refuses regardless of what it is asked to do.

### 7. Phasing

| Phase | Deliverable | Actuates anything? |
|---|---|---|
| **0 — Cost model and simulator** | The declarative schema (§2); an offline tool that replays recorded relay telemetry against a cost model and reports spend per pool, per meter, per edge. | No |
| **0b — Re-homing hardening** | Close the client/relay gaps in *Verified: client re-homing* (move a busy connection, network-change trigger, `Restarting` sent and honoured, faster probing). Independently valuable; a prerequisite for Phase 2 scale-down. | No (client/relay behaviour only) |
| **1 — Advisor** | The planner and constraint set (§3, §4) running continuously, publishing "recommended vs actual" as metrics and a console view. Humans act on it. | No |
| **2 — Reactive actuation** | Drivers (§5), enrollment (§6), circuit breaker. Scales on observed demand with headroom. | Yes, bounded |
| **3 — Predictive scaling and pattern of life** | A forecaster behind the same planner interface: learns daily/weekly/seasonal demand per (region, aquifer) and leads the ramp. | Yes |

Phases 0 and 1 deliver most of the *insight* with none of the credential risk,
and they are the empirical basis for deciding whether Phase 2 is worth its
attack surface. They can be the stopping point for an operator who never wants
auto-actuation.

### 7a. Geography moves: clients in transit and follow-the-sun demand

Demand is not stationary in space. A client crossing regions during a day
should move to a closer relay, and an organization's load shifts from one
region to the next as the working day travels. Both change *where* capacity
is needed, and both interact with scaling:

- **Client-driven moves are the fast loop; the scaler is the slow loop.**
  Clients re-home by measured RTT in minutes (once Phase 0b lands); the scaler
  adds or removes capacity over longer horizons. The planner must treat
  re-homing as *demand it cannot control and must observe*, not as a mechanism
  it steers. It sees the result as telemetry and sizes against it.
- **Capacity must exist where a client is *going*, not only where it is.**
  A traveller landing in a region with no relay re-homes to a far one and
  experiences it as the SLA failing. The latency constraint (§3) is therefore
  evaluated over *regions where clients appear*, including transient ones,
  not only home regions. Phase 3's pattern-of-life model is where
  predictable movement (a commute, a rotation, a recurring trip) is
  anticipated; until then it is covered by minimum headroom at the nearest pool.
- **Scale-down and roaming must not fight.** Draining a relay should use
  `Restarting` (Phase 0b), and the drained clients must land somewhere that
  still meets the SLA, so a drain is itself a placement decision the planner
  checks before issuing.
- **Hysteresis cuts both ways.** Faster re-homing (Phase 0b) risks the netmap
  churn §9.2 warns about; the selector stays hysteresis-governed, and any
  speed-up comes from measuring sooner (on a detected network change), not
  from lowering the margin.

### 7b. Beyond relays: which components can share the model

Relays are the first target because they are bandwidth-bound, carry little
durable state, and already sit in a registry that clients consult. The pool
model is intended to extend, but each candidate differs in a way that changes
what "scale" means, and the order below is a judgment, not a commitment:

| Component | Scales how | What differs from a relay |
|---|---|---|
| **Relays** (`karst-relay`) | Add/remove nodes in a region | Baseline. Stateless-ish, clients re-home. |
| **TURN gateways** (ADR-0008 §4) | Same | Credentials are minted by the control server; allocations are stateful per client, so drain is slower. |
| **AVEN reflectors** | Co-located with relays | Ride along with relay placement; no separate pool. |
| **KarstDNS resolvers** | Add/remove | Latency-sensitive, tiny bandwidth; cost is almost all instance-hours. |
| **Exit nodes and subnet routers** | Add/remove, but each is bound to a network or address range | Not interchangeable: an exit node's egress IP and a subnet router's reachable network are part of its identity. HA failover exists (`docs/operations/ha.md`); *placement* is a policy decision, not capacity. |
| **Regional coordination/control replicas** | Add read replicas | Carry the signing keys and roster; scaling them enlarges the most sensitive trust boundary. Out of scope until the threat model covers it. |

The abstraction must not bake in "relay" (§1's pool has a `kind`), but
nothing beyond relays is designed here. Components that are *identity-bound*
rather than *capacity-bound* are the likeliest to need a different model
entirely, and the ADR commits only to not foreclosing that.

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
- **Resolving a client's IP to a physical location (GeoIP), as the
  demand-attribution or new-region-discovery signal (§4a/§4b).** Rejected on
  accuracy grounds before privacy ones: GeoIP databases fail *confidently*,
  not gracefully — unresolvable ranges get assigned a default centroid that
  is a real place, and a planner that trusts it can confidently place
  capacity in the wrong city, or misattribute a whole ISP's traffic to one
  location indefinitely. RTT measures the thing that actually matters
  (network path quality) directly; geographic closeness is a proxy for RTT
  that can diverge from it on a bad peering path. Secondarily, it is also a
  new inference step ADR-0046 already declined to add for relay location,
  for the authority-asymmetry reasons ADR-0023 established.
- **Client-reported RTT to its *chosen relay*, as a substitute for the
  relay-side histogram (§4a specifically).** Rejected as redundant: a relay
  already measures this with no client cooperation at all, so asking the
  client to report the same number again adds a new reporting channel for
  no new information. This is narrower than, and does not extend to, §4b's
  client-reported RTT *to fixed provider anchors* — that measures something
  no relay can see (distance to a region with no relay in it), which is the
  actual gap §4b exists to close, with the same never-retain-per-client
  discipline enforced at the aggregation point.
- **An ephemeral instance per candidate region, with clients probing an
  address inside its published CIDR (§4b).** Rejected: discovering the CIDR
  is free (providers publish it), but an arbitrary address inside it
  usually answers nothing — most of a CIDR is unassigned space a provider's
  edge may silently drop, or someone else's instance with no reason to
  answer a stranger. A reliable answer needs something of ours actually
  running there, which is exactly the cost and operational burden §4b is
  designed to avoid.
- **A standing probe-only anchor we operate in every candidate region
  (§4b).** Rejected for the same reason: every provider §4b supports
  already runs a permanent, multi-tenant, public service in each region
  (S3 for AWS, Azure Monitor Live Metrics, GCP's regional endpoints) built
  for exactly this kind of reachability, or close enough to repurpose.
  Standing up a parallel one duplicates infrastructure that already exists
  for free.
- **A region denylist instead of an allowlist (§4c).** Rejected: a denylist
  is automatically *permissive* for any region nobody has thought to add
  yet, including a new one a provider opens tomorrow — exactly the "it
  appeared somewhere nobody intended" failure this section exists to rule
  out. An allowlist is automatically *restrictive* until an operator
  deliberately widens it, which is the direction a legal-exposure control
  should fail in.
- **Karst inferring jurisdiction from region code (§4c)**, so an operator
  could write "no EU" instead of enumerating region codes. Rejected: that
  mapping is a legal judgment, not a technical fact Karst can look up
  once and trust — it changes, and whose definition of "the EU" applies
  depends on who's asking. Getting it wrong silently would undermine the
  entire point of the control. The operator writes the region codes;
  Karst enforces exactly what was written.
- **Defaulting `allowed_regions` to "every region" until an operator locks
  it down (§4c).** Rejected: that is the exact gap this section exists to
  close, just deferred to whether someone remembers to configure it.
  Fail-closed — no pool creation for a provider with no configured
  allowlist — costs an operator one config file and removes the gap
  entirely rather than narrowing it.

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
- **A new third-party dependency, opt-in but real (§4b).** A node with
  region-discovery enabled depends on each provider's anchor endpoint (S3
  for AWS, Azure Monitor Live Metrics, GCP regional endpoints) staying
  reachable and behaving the way it does today. The non-AWS anchors are
  services that were never meant as probe targets, which is why §4b pairs
  them with a shared-address check. This is a dependency on another
  company's infrastructure behaving as documented, not
  infrastructure Karst controls — named here rather than assumed away.
- **The region allowlist (§4c) is a technical control, not legal advice.**
  Karst enforces exactly the region codes an operator writes down; it has
  no opinion on and makes no claim about whether that list actually
  satisfies whatever sanctions, residency, or export-control obligation
  motivated it. Getting the list right is the operator's and their
  legal team's call.
- **No default means genuinely no pools until configured.** An operator who
  enables the scaler at all now has one more required piece of
  configuration before any pool — even a hand-declared one — can exist.
  This is a real, if small, new setup step for every deployment that uses
  §1's pool model, not only ones that also use §4b.

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
- A provider materially changes its anchor's behavior (auth requirement,
  deprecation, rate limiting a bare TCP handshake, or moving it behind
  anycast, which §4b's shared-address check is there to catch) — that
  provider's arm would need a different anchor, not just a config change.
- Operators ask for self-service editing of `allowed_regions` through the
  console rather than a boot-time file — the same "file-loaded,
  operator-only, no HTTP endpoint in this pass" deferral ADR-0037 already
  made for tenancy grants, and the same answer applies here until this
  shape has seen real use.

---

## Open questions

These are real unknowns to resolve in Phase 0, not rhetorical ones.

1. **Which non-relay components, in what order?** §7b sketches the
   candidates; the open part is whether identity-bound components (exit nodes,
   subnet routers) fit the pool abstraction at all, or need placement
   policy instead of capacity scaling.
2. **~~How is demand attributed to a region?~~ Resolved — see §4a.** A
   relay-reported, bucketed RTT histogram (an extension of ADR-0021's
   existing signed telemetry, not a new per-client signal) tells the planner
   when existing clients are being badly served, without resolving where any
   of them physically are. The planner matches that signal against
   operator-declared candidate pools (§1), the same declared-not-inferred
   principle ADR-0046 uses for relay locations on the NOC map. Client IP
   geolocation was considered and rejected on accuracy grounds (GeoIP fails
   confidently, not gracefully) and, secondarily, for the same inference
   concern ADR-0046 already raised — see *Alternatives rejected*. Discovering
   a region with no relay nearby at all needed a different mechanism; see
   §4b. What remains open here: the exact bucket boundaries and histogram
   retention window, which is an ordinary tuning question, not a design one.
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
8. **~~GCP and Azure equivalents of §4b's AWS anchor mechanism.~~
   Resolved — see §4b.** Azure uses its Monitor Live Metrics regional
   endpoint (`<region>.livediagnostics.monitor.azure.com`), GCP its
   regional service endpoints (`storage.<region>.rep.googleapis.com`), each
   checked against published IP ranges or provider documentation on
   2026-10-08. What remains open: a two-vantage-point RTT check of the GCP
   anchor before its arm ships, since GCP publishes no region mapping for
   those addresses.
