<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-0047: NOC view — telemetry time-series store, delivery, and Phase 1 data scope

- **Status:** Proposed
- **Date:** 2026-10-07
- **Deciders:** TBD
- **Related:** #241 (NOC view, this ADR's tracking issue — Phase 0), ADR-0021
  (relay telemetry — latest-snapshot-only, no history: the gap this ADR
  closes for the NOC view specifically), ADR-0038 (per-aquifer relay
  capacity budget — what a utilization panel compares against), ADR-0039
  (air-gapped scope — no external tiles, fonts, or CDN scripts), ADR-0045
  (cost-aware geographic scaling — Proposed, not yet Accepted: this ADR
  decides what the NOC may show about cost before that lands), ADR-0046
  (NOC location and visibility policy — the companion Phase 0 ADR this one
  does not duplicate), `docs/observability.md`

---

## Context

#241 Phase 1 asks for "time-series with selectable ranges, not just the
latest snapshot" and per-relay utilization against ADR-0038's capacity
budget. ADR-0021 is explicit that this does not exist today: a relay's
telemetry report is a replace, not an append ("Historical trending... this
reports only the most recent snapshot; there is no time series" — listed
as an explicit non-goal). #241 names three more open questions this ADR
resolves before Phase 1 implementation starts:

- **Where does the time series live** — a new control-plane store, or an
  operator's own TSDB (#241 OQ2)?
- **Refresh model** — polling, SSE, or websocket, and the load each puts on
  the control server at fleet scale (#241 OQ6)?
- **Interim cost model** before ADR-0045 is accepted, or hold the cost
  panels (#241 OQ4)?
- **Basemap sourcing** given ADR-0039's no-CDN, no-external-lookup bar for
  air-gapped deployments (#241 OQ5)?

Checked against the tree: Karst already ships real Prometheus metrics and
OTel traces for `karst-control`, `karstd`, and `karst-relay`
(`docs/observability.md`), and `karst-relay` already runs its own local,
opt-in Prometheus endpoint. A time-series store and query engine already
exists, in the form of Prometheus, in every deployment that has already
stood one up to scrape those endpoints — which is the deployment that
would most want NOC history in the first place.

## Decision

**The control plane does not become a time-series store. It re-exports
accepted telemetry as Prometheus metrics; the NOC's history panels query
the operator's own Prometheus (or any Prometheus-API-compatible store)
through a server-side, account-scoped proxy.**

### 1. Time series lives in the operator's own TSDB (resolves OQ2)

Every accepted relay telemetry report (ADR-0021) is re-exported as a
Prometheus metric (`karst_relay_telemetry_*`, labeled by `relay_id`,
`region`, and `account_id`) at the moment it is accepted, alongside the
latest-snapshot behavior ADR-0021 already defined — this is additive, not
a replacement of the existing push path. The control plane itself keeps
storing only ADR-0021's latest-snapshot-per-relay; it never accumulates its
own history.

The NOC's time-series panels query Prometheus's HTTP API through a new
server-side proxy endpoint that injects the account's own scoping (the
same `account_id` label every other NOC endpoint already scopes by) into
every query, so a tenant's NOC view cannot issue an arbitrary PromQL query
against another tenant's series, and cannot reach the underlying
Prometheus directly. The proxy's query surface is a fixed set of
parameterized queries (rate over range, current value, utilization against
an ADR-0038 budget), not an open PromQL passthrough — the same
"documented, not generic" posture `docs/admin-console.md` already applies
to the policy schema's own validation.

### 2. Retention is the operator's Prometheus retention

No new Karst-specific retention policy is introduced. A deployment that
already scrapes `docs/observability.md`'s endpoints keeps whatever
retention it has configured there; the NOC simply reads it. A deployment
with no Prometheus configured gets the NOC's live/current-snapshot panels
(ADR-0021's existing data, unchanged) and an explicit "no history
available — configure Prometheus scraping" state on every time-series
panel — a real, visible gap, never a silently empty chart.

### 3. Delivery: polling, not push, for Phase 1 (resolves OQ6)

The NOC view polls its own endpoints (the current-snapshot API and the
Prometheus proxy above) on a client-configurable interval, default 30
seconds — matching Prometheus's own typical scrape cadence and the
existing poll-based pattern every other console page already uses. SSE or
websocket push is explicitly deferred: no fleet-scale load measurement
exists yet to size a push mechanism against, and the existing poll pattern
has known operational behavior at whatever scale current deployments
already run console pages at.

### 4. Cost panels wait for ADR-0045 (resolves OQ4)

#241's Phase 1 acceptance criteria (declared locations, map, health,
current throughput, utilization, with history) do not require cost data.
No interim, NOC-specific cost model is built. The cost panels in #241 §3
are Phase 2 work, gated on ADR-0045 reaching **Accepted**, and consume
ADR-0045's cost model directly rather than a placeholder that would need
migrating (and would make any screenshot, export, or saved dashboard built
against it wrong in a way that quietly changes later).

### 5. Basemap: bundled, low-detail, no runtime network dependency (resolves OQ5)

A self-hosted vector tile set, bundled as a static asset in the console
build, at a fixed low zoom-detail level — country/region/city centroids,
no street-level data — is used for every deployment, air-gapped or not.
No third-party tile server, font CDN, or GeoIP service is reachable from
the NOC view at runtime, meeting ADR-0039's bar unconditionally rather than
as an air-gapped-only special case. Component markers plot against this
basemap using the declared coordinates ADR-0046 introduces.

### Alternatives rejected

- **A dedicated time-series store inside the control plane** (a new table,
  a retention job, a query API). Rejected: duplicates Prometheus, which
  already exists in every deployment likely to want this feature, for no
  capability Prometheus doesn't already have — and reopens the retention,
  cardinality, and per-aquifer-scoping questions #241's own "Data gaps"
  section named as unresolved, which a general-purpose TSDB has already
  solved.
- **SSE or websocket push for Phase 1.** Rejected: no fleet-scale load data
  exists yet to size it against, and building a new push mechanism before
  the simpler poll-based one is shown to be a real problem is solving a
  problem this project hasn't measured yet (see Reconsider if).
- **An interim, Karst-specific cost model, migrated once ADR-0045 lands.**
  Rejected: migrating displayed numbers — and anything built against them,
  a saved dashboard, an export, a screenshot in a report — once ADR-0045's
  real model lands is a worse outcome for an operator than a panel that is
  visibly absent until then. A wrong number presented as data is worse
  than an honest gap.
- **A third-party or CDN-hosted basemap with an offline fallback for
  air-gapped deployments.** Rejected: a fallback path exercised only in
  air-gapped deployments is exactly the kind of code that silently rots
  between the times it's actually run — ADR-0039's own framing for why it
  declined a separate air-gapped product variant elsewhere. One bundled
  basemap, exercised by every deployment, is simpler and better-tested by
  simple virtue of always being the path taken.

---

## Consequences

### Positive

- No new store to build, secure, or operate — the control plane's
  responsibility stays exactly what ADR-0021 already defined, plus a
  metrics re-export that is additive and low-risk.
- Cost panels never show a number that needs re-explaining or migrating
  once ADR-0045 lands.
- The basemap has zero outbound dependency unconditionally, satisfying
  ADR-0039 without a special case to maintain.
- Retention policy has exactly one owner (the operator's own Prometheus
  configuration), not a second Karst-specific knob to keep in sync with it.

### Negative

- **A deployment with no Prometheus scraping configured gets no historical
  trending in Phase 1 at all.** The NOC's value is materially smaller for
  an operator who hasn't already stood up observability, and this ADR
  builds no fallback for that case — named here as a real, accepted gap,
  not an oversight.
- **Cost panels (#241 §3) now have no committed date** — they are blocked
  on ADR-0045 reaching Accepted, and ADR-0045 itself is still Proposed with
  its own open questions. An operator who wants cost visibility from the
  NOC specifically is waiting on a dependency this ADR does not control.
- The Prometheus-proxy's fixed query surface (not open PromQL) means a
  NOC user cannot write an ad hoc query through the NOC view itself — they
  still need direct Prometheus/Grafana access for anything the proxy's
  parameterized set doesn't cover. This is a deliberate scoping boundary,
  not a missing feature to backfill quietly later.
- The bundled basemap's fixed low-detail level means the map cannot show
  street-level or building-level placement even where an operator might
  want it — unlikely to matter at relay/exit-node granularity, but a real
  ceiling, not a temporary one.

### Reconsider if

- A deployment's real poll load against the proxy endpoint becomes a
  measured operational problem — revisit SSE/websocket delivery with that
  measurement in hand, rather than guessing now.
- ADR-0045 is accepted — build the Phase 2 cost panels against its model
  at that point, not before.
- Operators with no Prometheus configured turn out to be a large enough
  segment that the lack of a built-in retention fallback is a recurring
  complaint, not a rare edge case — that is new, separately scoped work
  against real demand, not something to have guessed at here.
