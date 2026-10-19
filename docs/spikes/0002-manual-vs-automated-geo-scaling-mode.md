<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Spike 0002 — admin-switchable manual (RTT-suggested) vs. automated (SLA/budget-driven) geo-scaling mode

- **Status:** **Closed — design complete, no build.** Issue #356's own
  "what closes this issue" bar: a settings-table shape, admin API shape,
  suggestion-object shape, and the `drive_loop.rs` gating point, concrete
  enough for an implementer to pick up as follow-on issues.
- **Date:** 2026-10-19
- **Gates:** ADR-0045 §7 Phase 1/Phase 2 (Advisor vs. Reactive actuation);
  §4a (demand attribution), §4b (anchor-based region discovery)
- **Verdict:** buildable as four small, independently landable pieces (§5);
  no new ADR needed — this extends ADR-0045 §7's existing phase boundary
  into a runtime switch rather than proposing a new mechanism.

---

## 0. What problem this actually is

ADR-0045 §7 names two phases that already exist as code: **Phase 1
(Advisor)** computes a `Recommendation` and only prints it
(`bins/karst-scaler/src/advise_loop.rs`); **Phase 2 (Reactive actuation)**
runs the identical solver call and then reconciles it through a `Driver`
(`bins/karst-scaler/src/drive_loop.rs`). Today the choice between them is
"which binary an operator starts" — baked in at deploy time, not a setting
an admin can flip on a running deployment.

Issue #356 asks for that choice to become live and admin-switchable, and
flags that "manual mode, suggested by RTT" has no computed form today: the
latency signal only reaches a human as Prometheus gauges
(`karst_scaler_region_p95_rtt_ms` vs. `_region_latency_threshold_ms`), which
a human reads in Grafana and acts on by hand. There is no first-class
object for what the system is suggesting, the way `advise::Recommendation`
is a first-class object for what it costs.

This spike resolves the three things the issue named as genuinely open —
where the mode lives, what a suggestion object actually contains, and how
`drive_loop` gates on it — by pattern-matching two mechanisms already in
the tree that solve adjacent problems, rather than inventing a new shape.

## 1. Where the mode lives: a deployment-wide singleton row

**Decision: deployment-wide, not per-pool.** Issue #356's own framing is
"admins want to choose, per deployment" — not per pool — and nothing in
ADR-0045 §4 attributes demand or sizes pools independently enough that a
mixed automated/manual deployment would mean anything coherent: `advise`'s
own module doc already describes sizing as "each pool independently," but
*actuation* is a single `drive` process reconciling every pool in one tick
(`drive_loop::tick`); a per-pool mode would require splitting that loop's
single `Driver` call per pool for no signal #356 asked for.

**Decision: a singleton table row, server-owned, not a karst-scaler config
file.** `server/management/internals/karst/ephemeralanchor/ephemeralanchor.go`
already has the exact shape needed — `scheduleRow` is "the one
deployment-wide duty-cycle schedule... a fixed, always-present singleton
row (ID always 1, never created a second time)," set via `SetSchedule`/
read via `Schedule`, upserted with `clause.OnConflict`. A new package,
`server/management/internals/karst/scalingmode`, copies this shape exactly:

```go
// scalingmode.Mode — ADR-0045 §7's Phase 1/Phase 2 split as a live setting.
type Mode string

const (
	ModeAutomated Mode = "automated" // Phase 2: drive reconciles through a Driver.
	ModeManual    Mode = "manual"    // Phase 1 behavior from drive: compute, don't act.
)

type modeRow struct {
	ID   uint8  `gorm:"primaryKey"`
	Mode string `gorm:"size:16"`
}

func (modeRow) TableName() string { return "karst_scaling_mode" }

type Store struct{ db *gorm.DB }

func NewStore(db *gorm.DB) (*Store, error) // AutoMigrate(&modeRow{})
func (s *Store) SetMode(ctx context.Context, mode Mode) error
// Mode returns the current mode, defaulting to ModeAutomated when no row
// has ever been written -- see the "default" rationale below.
func (s *Store) Mode(ctx context.Context) (Mode, error)
```

**Decision: default is `automated`, not `manual`.** Every deployment
running `karst-scaler drive` today gets Phase 2's unconditional reconcile,
with no setting at all. Shipping this feature with a `manual` default would
silently stop actuating for every existing `drive` deployment the moment
they upgrade — the same "keep parsing/behavior unchanged for what already
exists" discipline `cost_model::PoolKind`'s own `Default` impl documents
for exactly this reason. `Store.Mode` returning `ModeAutomated` when the row
has never been written (the same `0, 0, nil`-before-first-`Reconcile`
posture `ephemeralanchor.Store.Schedule` already has) makes this the
no-row-yet case, not a separately-coded default.

## 2. Admin API shape: `GET`/`PUT /karst/v1/scaling/mode`

Mirrors `/ephemeral-anchors/schedule`'s existing GET/PUT singleton pair
(`server/management/internals/karst/api/nodes.go`:
`ephemeralAnchorsSchedule` / `ephemeralAnchorsScheduleSet`) exactly, not
`/regions`' list/create/delete shape — this is one value, not a
collection.

```go
type scalingMode struct {
	Mode string `json:"mode"` // "automated" | "manual"
}

// GET /karst/v1/scaling/mode -- any authenticated member reads it (the
// console's NOC view and karst-scaler's own tick both need this with no
// elevated role, the same posture demandRegions/scalerRecommendations
// already have via requireAdvisorRole, not an admin-only read).
func (h *handler) scalingModeGet(w http.ResponseWriter, r *http.Request)

// PUT /karst/v1/scaling/mode -- admin-only write, behind the same
// karstAuthorization admin-write gate regionsCreate/regionsDelete and
// ephemeralAnchorsScheduleSet already sit behind. Rejects any Mode value
// other than "automated"/"manual" with 400, the same fail-closed-on-typo
// posture regionallow.Parse's provider/region emptiness checks have.
func (h *handler) scalingModeSet(w http.ResponseWriter, r *http.Request)
```

`RegisterEndpoints` takes a `scalingModeReadWriter` interface (`Mode`,
`SetMode`), the same narrow-interface discipline `regionAllowReadWriter`/
`ephemeralAnchorReadWriter` already use — `*scalingmode.Store` satisfies it
without the handler ever seeing `gorm.DB`.

## 3. The suggestion object: two new types, not an extension of `advise::Recommendation`

Issue #356 asks this explicitly rather than letting it default: **does
manual mode reuse/extend `advise::Recommendation`, or does it need a
materially different type?** It needs a different type, for the same
reason `advise.rs`'s own module doc gives for why `Constraint::Residency`
and `Constraint::Latency` are never produced by `size_pool`: a
`PoolRecommendation` answers "how many nodes should this *already-existing*
pool have," a cost-driven question with a node-count answer. Neither of
manual mode's two real questions is that question:

1. **Is an existing pool's region currently breaching its latency SLA?**
   This is already computed every tick and thrown away — `advise_loop.rs`'s
   private `latency_breaches` function returns `Vec<(&str, f64, f64)>`
   purely to feed `print_latency_breaches`'s `println!`s. Promoting it to a
   named, serializable type costs nothing new to compute:

   ```rust
   #[derive(Debug, Clone, serde::Serialize)]
   pub struct LatencyBreach {
       pub region: String,
       pub p95_rtt_ms: f64,
       pub threshold_ms: f64,
   }
   ```

2. **Is there a candidate *new* region worth a human standing up a pool
   in?** This is the gap `advise_loop::tick` already names out loud:
   `"anchors: {} rows, {anchor_total} total observations (candidate-region
   promotion not implemented)"`. This is genuinely new work, not a
   promotion of an existing private helper — it needs to rank
   `AnchorHistogramRow`'s `(provider, region, bucket, count)` rows by
   observed RTT bucket the same way `region_p95_rtt_ms` already estimates
   p95 from a histogram, but for *regions with no pool at all* rather than
   an existing pool's demand:

   ```rust
   #[derive(Debug, Clone, serde::Serialize)]
   pub struct RegionCandidate {
       pub provider: String,
       pub region: String,
       pub estimated_p95_rtt_ms: f64,
       pub observations: i64,
   }
   ```

   Both signals are RTT-derived, which is what makes them "manual mode's
   suggested-by-RTT output" as a pair, not because they share a type.

Both are exposed the same way `Recommendation` already is — added as two
new fields on `metrics_http::Snapshot` (`latency_breaches:
Vec<LatencyBreach>`, `region_candidates: Vec<RegionCandidate>`), computed
every tick regardless of mode (so switching *into* manual mode has
immediate content, not an empty first tick), and proxied to the console the
same way `karst-control`'s existing `scalerRecommendations` handler already
proxies `GET {scalerAdvisorURL}/recommendations` — a sibling
`GET {scalerAdvisorURL}/suggestions` proxied by a new `scalerSuggestions`
handler, same `requireAdvisorRole` gate, same server-to-server-GET-because-
the-browser-cannot-reach-the-loopback-listener reasoning
`metrics_http.rs`'s own module doc already gives for `/recommendations`.

## 4. The `drive_loop.rs` gating point

`drive_loop::tick` (`bins/karst-scaler/src/drive_loop.rs:53`) already
separates "compute" (`advise_loop::tick_recommendation`, line 60) from
"act" (the `reconcile` call per pool, lines 76–78). The gate is a single
early decision between those two steps, not a restructuring:

```rust
fn tick(
    doc: &Document,
    positions: &mut HashMap<String, Position>,
    config: &Config,
    agent: &ureq::Agent,
    driver: &mut dyn Driver,
) -> Result<(), String> {
    let outcome = advise_loop::tick_recommendation(doc, positions, config, agent)?;
    let mode = fetch_scaling_mode(agent, config)?; // GET {control_api_base}/scaling/mode

    // ...existing println!s for recommendation / residency / latency
    // breaches, unconditional in both modes, so an operator watching
    // stdout/the console sees identical content either way...

    if mode == ScalingMode::Manual {
        println!("  mode=manual: not actuating (recommendation computed and stored above)");
        return Ok(());
    }
    for pool in &outcome.recommendation.pools {
        reconcile(driver, &pool.pool_id, pool.desired_nodes)?;
    }
    Ok(())
}
```

`fetch_scaling_mode` is one more `GET` against `config.control_api_base`,
the same `ureq::Agent` and PAT `advise_loop::fetch` already uses for
`/demand/regions` and `/demand/anchors` — no new transport, no new
credential.

**Decision: fail closed on a fetch error, not fail open to "last known
mode."** If this tick's mode fetch fails (a transient control-server
hiccup — the same category `advise_loop::run`'s own doc comment already
says "should not kill a long-lived process"), `tick` returns `Err` the
normal way, `run`'s existing loop logs it and sleeps for the next tick
(`drive_loop.rs:44-49`, already written, unchanged) — the tick simply does
not actuate this time, rather than guessing a stale mode. For an
actuation gate specifically, that is the safer failure direction: a missed
tick of automated scaling self-heals next tick; actuating in automated mode
on stale confirmation of a kill-switch is the failure ADR-0045 §6's circuit
breaker exists to avoid elsewhere. No new state (no cached "last known
mode") needs to exist for this — it falls out of the loop's existing
retry-next-tick behavior for free.

`advise_loop.rs` itself needs no gate at all: `advise` never actuates in
either mode, so the mode setting is simply irrelevant to it. It does,
however, gain the same two new `Snapshot` fields from §3 — an operator
running only `advise` (never `drive`) still gets manual-mode-shaped
suggestions, which is the issue's own "stays the stopping point for an
operator who never wants auto-actuation" framing (ADR-0045 §7's own line)
working correctly with no special case.

## 5. Landing this as follow-on issues

Four pieces, each independently buildable and testable, in dependency
order. Filed as #379-#382:

1. **#379 — `scalingmode` package + migration + `Store` tests** — no API,
   no consumer. Mirrors `ephemeralanchor.go`'s singleton `scheduleRow`/
   `SetSchedule`/`Schedule` shape (not `regionallow`'s multi-row
   `AddRegion`/`RemoveRegion` shape, which has no singleton Set/Get):
   round-trip `SetMode`/`Mode`, default-when-no-row, idempotent re-set.
2. **#380 — Admin API** (`GET`/`PUT /karst/v1/scaling/mode`) wired into
   `RegisterEndpoints`. Depends on #379. Console-side settings toggle is
   explicitly out of scope for #380 — API only, per §"Explicitly still
   open" below.
3. **#381 — `LatencyBreach`/`RegionCandidate` types + `Snapshot` fields +
   `/suggestions` metrics-HTTP route + `scalerSuggestions` control-server
   proxy handler.** Independent of #379/#380 — this is pure signal
   promotion, buildable and demoable before the mode switch exists at all.
4. **#382 — `drive_loop` gating** (§4) — depends on #379 and #380; depends
   on nothing from #381 (the unconditional `println!`s already exist;
   only the suggestion *objects* depend on #381, and `drive_loop` does not
   need them to gate correctly).

None of these touch `advise.rs`'s cost solver, any `Driver` implementation,
or add a new ADR — this is wiring ADR-0045 §7's already-decided phase
boundary into something an admin can flip, using two settings-storage
patterns (`regionallow`, `ephemeralanchor`) and one proxy pattern
(`scalerRecommendations`) the tree already has three working copies of.

## Explicitly still open (not this spike's job to resolve)

- **Console UI** for the mode toggle and suggestion display — out of
  scope per the issue; (2) above lands the API only, (3) lands the data
  only.
- **`RegionCandidate`'s ranking formula** — "rank by estimated p95 like
  `region_p95_rtt_ms` already does" is this spike's recommendation, not a
  verified formula; whoever builds (3) should treat the exact ranking the
  same "crude stand-in, good enough to be sanity-checkable, not a claim it
  is the right formula" way `advise_loop.rs`'s own module doc already
  treats `PLACEHOLDER_SESSIONS_PER_NODE`.
- **Per-pool mode** was considered and rejected (§1) on the signal
  available today; revisit only if a real deployment reports wanting
  automated actuation in some pools while reviewing others by hand, which
  no issue has asked for yet.
