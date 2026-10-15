<!--
SPDX-License-Identifier: CC-BY-4.0
Copyright the Karst contributors.
-->

# Spot/preemptible capacity — is the savings-vs-churn gate even checkable?

**2026-10-15.** Harness: `karst-scaler spot-report`, run against
[`spot-capacity-evaluation-2026-10-15-cost-model.toml`](spot-capacity-evaluation-2026-10-15-cost-model.toml)
and
[`spot-capacity-evaluation-2026-10-15-usage.log`](spot-capacity-evaluation-2026-10-15-usage.log).

## The question

ADR-0045 Open Question #4 put spot/preemptible capacity out of scope for
Phases 0–2 "unless Phase 1 shows the savings justify the complexity" — but
that gate was never actually evaluated. Nothing in `bins/karst-scaler`
modeled spot pricing or reclaim rate at all, so there was no way to check
it either way. [Issue #339](https://github.com/karst-net/karst/issues/339)
scoped a data-only simulator extension to make the gate checkable, without
building any driver: a spot/preemptible price ratio alongside the existing
on-demand schedule, a synthetic reclaim-rate model (with a knob for the
correlated-failure concern — a provider reclaiming a whole AZ's spot pool
at once, which overstates N+1 redundancy if spot nodes are counted at
face value), and a report showing headroom, savings, and churn together
rather than just the savings half.

That extension is what this run exercises: `cost_model::SpotModel`
(`pools.*.spot` — meter, `price_ratio`, `reclaim_rate_per_hour`,
`correlation`) and `simulate::evaluate_spot`, reachable as
`karst-scaler spot-report COST_MODEL.toml USAGE_LOG`.

## No real telemetry was available

Same posture the Kubernetes and AWS driver work already documented for
their own real-cluster/real-account verification gaps: this environment
has no production relay fleet to pull recorded usage from. The fixture
beside this file is a **documented synthetic input**, not a real bill —
issue #339 explicitly allows this ("a simulator run against real recorded
telemetry, *or a documented synthetic fixture if none is available*").
What follows checks that the tool answers the right question correctly;
it is not itself the go/no-go decision, which still needs real usage data.

### Fixture shape

One AWS pool, `min_nodes = 3` (its N+1 floor), `instance_hours` priced
flat at $0.0416/hr (on-demand `m5.large`-class), spot `price_ratio = 0.3`
(pay 30% of on-demand — a 70% discount, in range for real `m5.large` spot
pricing), `reclaim_rate_per_hour = 0.00015` (≈10% probability any given
node is reclaimed over a 720-hour month — in range for AWS's own
published spot interruption-frequency categories, not picked to flatter
the result), `correlation = 0.4`. Three synthetic months of recorded
`instance_hours`, with February modeling a demand spike (14 average
nodes against 8 and 9 in the other two) — deliberately, since a demand
spike is exactly when a provider is most likely to reclaim spot capacity
(Open Question #4's own concern) and exactly when losing it hurts most.

## Result

```
pool aws-use1 (spot meter instance_hours):
  avg nodes: 10.21 total, 7.21 headroom (70.6% of pool)
  cost of headroom: 647.96 on-demand, 194.39 spot, 453.57 savings
  expected re-homes: 2.34 (0.93 from correlated/multi-node events)
total savings across every spot-modeled pool: 453.57
```

Against this run's actual `simulate` total for the same pool and meter
(917.53 — see `simulate`'s own report, not shown here), running every
node above the N+1 floor on spot would have saved 453.57 of that 917.53,
roughly 49%, for an estimated 2.34 forced re-homes across the whole
three-month window — one roughly every five to six weeks, of which about
40% (0.93) are attributed to the correlated-event term rather than
independent single-node reclaims.

`correlation` does what the model's own doc comment claims: raising it
from `0.0` to `1.0` with everything else held fixed leaves the expected
*count* of reclaims unchanged (it is still
`avg_spot_nodes * reclaim_rate_per_hour * hours`) and only moves where
that count sits on the independent/correlated split — i.e., how much of
it would hit several nodes in the same pool simultaneously rather than
spread out one at a time. That split is the number Open Question #4's
"overstates real redundancy" concern is actually about, not the total.

## What this does and does not close

**Closes:** the tool itself did not exist, so the gate could not be
checked at all. It can be now — `spot-report` takes an operator's own
cost model and recorded usage and returns savings and churn side by side,
which is what Phase 1 needs to actually decide the question instead of
assuming an answer.

**Does not close:** whether *this deployment's* real savings justify
driver work. That needs real recorded usage and a real operator's own
risk tolerance for forced re-homes — both outside what a synthetic
fixture can supply. The illustrative run above is not a recommendation to
build the driver; it is a demonstration that, for a plausible real-world
shape of the inputs, the answer is not obviously "marginal" either —
which is itself the reason this stays a documented follow-up
([#339](https://github.com/karst-net/karst/issues/339) tracks closing the
loop once an operator runs this against their own telemetry) rather than
a closed "no" on spot capacity.

## Reproducing

```sh
cargo run -p karst-scaler -- spot-report \
  docs/measurements/spot-capacity-evaluation-2026-10-15-cost-model.toml \
  docs/measurements/spot-capacity-evaluation-2026-10-15-usage.log
```
