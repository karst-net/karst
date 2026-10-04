# Title: Cost-aware geographic scaling across cloud and on-prem capacity (ADR-0045)

Tracking issue for [ADR-0045](docs/adr/0045-cost-aware-geographic-scaling-across-providers.md)
(Proposed).

## Idea
Given AWS, Azure, on-prem and/or other provider accounts, scale relay capacity
(later other components) up and down geographically to meet a stated SLA at
minimum cost. Some costs are fixed (on-prem); others are variable and tiered
(per-hour, per-GB, graduated or volume bands, cross-region and within-provider
traffic). A later refinement is predictive scaling from an organization's
pattern of life.

## Why a decision, not a script
Prices are stateful (tier position depends on month-to-date usage), traffic
cost lives on (pool, pool) edges, and fixed and variable costs interact.
Per-provider autoscalers can't see across providers.

## Phases (see ADR §7)
- [ ] **0** Cost-model schema + offline simulator over recorded relay telemetry
- [ ] **0b** Re-homing hardening: #TBD (prerequisite for scale-down)
- [ ] **1** Advisor: planner + constraints, no actuation
- [ ] **2** Reactive actuation: drivers, signed enrollment, budget circuit breaker
- [ ] **3** Predictive scaling / pattern of life

## Decisions recorded
- Separate process/trust domain from the control server; tag-scoped credentials
- Admin-entered pricing is first-class for providers without an API (`as_of`/`review_by`)
- Forecasts may move *when* capacity is added, never *whether* the SLA holds
- Pattern-of-life data stays inside the operator's deployment

## Open
Working name `karst-scaler` is a placeholder (ADR-0010 naming); non-relay
components (§7b); demand attribution by region; SLA vocabulary; spot capacity;
cost attribution across aquifers; demand-history retention. See ADR "Open
questions".

Related: ADR-0008, 0021, 0038, 0039, 0016.
