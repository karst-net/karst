<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Admin console: scope and intentionally deferred capabilities

Reference for what `web/console` does and does not do. Issue #128's fourth
acceptance criterion asks for intentionally deferred capabilities to be
documented explicitly rather than left implicit — most of what follows
already exists as inline copy inside the console itself (a paragraph in
Settings, a row's disabled-state explanation in Groups); this page collects
it in one place an operator can read without hunting through the UI first,
and is the place to update when a deferral is later picked up.

## Access policy

The agreed [mesh domain and access model](mesh-domains.md) defines an explicit,
root named `karst` for new accounts, delegated administration, and resource
access conditioned on device compliance. The root is visible in domain and
machine controls. Domains also provides an account-authorized root rename
preview, explicit no-alias confirmation, and rollback through another preview.
The console distinguishes committed configuration from unobserved client
convergence. Machine names and invitation/move previews include the root suffix,
including in delegated subtree views. See the [acceptance record](mesh-domain-validation.md).
Compliance-conditioned access remains a follow-up capability.

- **Schema-aware autocomplete and inline JSON-syntax lint exist**
  (`GET /policy/schema`, `web/console/src/policy-editor.tsx`, a CodeMirror 6
  editor). Autocomplete offers the document's top-level keys, a rule's
  `action`/`src`/`dst` fields, `"accept"` for `action`, and any `group:`/`tag:`
  selector already defined elsewhere in the document.
- **Deferred: full JSON Schema validation client-side.** The schema names
  shape (which keys exist, that `action` is a constant) but not
  cross-references — "an acl's `src` group must be defined in `groups`" is a
  rule [`Document.Validate`](../server/management/internals/karst/policy/policy.go)
  enforces server-side and no generic schema validator expresses. A document
  that passes the editor's live lint can still be rejected by
  `POST /policy/validate`; the "Validate policy" button remains the
  authoritative check before saving.

## Groups and access-rule cross-references

- **The "Access rules" column on the Groups page is a name match, not a
  foreign key.** The access policy document has its own, independent
  `"groups"` map (`"group:name"` → a list of user identifiers), defined
  inside the JSON document itself. It is unrelated storage from the fork's
  own group records this page manages — the two line up only when an admin
  names them the same way. Renaming a group here never edits the policy
  document; the console says so in the rename dialog.
- **Deferred: a real cross-reference.** Making group renames propagate into
  the policy document (or the policy document look up group membership from
  the fork's own store instead of its own literal user list) is a design
  change to how `Document.Groups` works, not a console feature — tracked as
  a possible future policy-format change, not started.

## SIEM / audit sinks

- **List and delete exist** alongside create (`GET`/`POST`/`DELETE
  /audit/sinks`). A configured sink can be seen and removed from the Audit
  page without direct database access.
- **Deferred: sink health.** The console shows what is configured, not
  whether deliveries are currently succeeding. `audit.Delivery` tracks
  attempts and the last error per sink server-side; surfacing that in the
  console (a "last successful delivery" column, a way to see `LastError`) is
  a reasonable follow-up, not implemented.

## Organization / SSO / SCIM / webhooks

- **Organization ID, domain, and creation date are shown** (read-only) on the
  Settings page, from the fork's own `GET /api/accounts`.
- **Deferred, deliberately: SSO, SCIM provisioning, and webhook
  configuration.** These are server startup configuration
  (`management.json`), not console-owned settings — the console states this
  directly rather than offering a control it cannot back with anything real.
  See the getting-started guide for how to configure them.

## Per-node throughput

- **Both path and throughput are shown.** Path: which peer, direct or
  relayed, the relay id and endpoint if relayed, and when it was last
  observed. Throughput: bytes sent/received per peer, a running total for
  the session rather than a rate (`GET /nodes/{handle}/paths`, the Paths
  dialog on the Machines page).
- `karstd` already tracked `tx_bytes`/`rx_bytes` per peer internally (surfaced
  in `karst bugreport`); the gap closed here was purely plumbing — a proto
  field (`KarstSessionObservation.tx_bytes`/`rx_bytes`,
  `server/shared/management/proto/karst_control.proto`), a storage column
  (`node.SessionObservation`), and an API field, none of it new
  instrumentation.
- **Deferred: a live rate**, as opposed to a cumulative total. Would need the
  control plane to keep more than the latest report per peer (today's
  `ReplaceSessionObservations` is a full replace, not an append), to compute
  a delta over time — a real feature, not a plumbing gap like the total was.
- **Deferred, smaller: `relay_id` and `since` on a path observation.** Both
  fields exist on the API contract and are already read by the console, but
  the server has never populated either — `relay_id` because a session
  observation does not yet say *which* relay a relayed path used (its own
  proto-field-sized gap, not yet scoped), and `since` because the
  full-replace storage above has nowhere to keep "when did this path
  configuration start" across reports.

## Per-route throughput

- **Issue #281: aggregate egress bytes/packets per exit-node/subnet-router
  route, for NOC visibility only** — never a planner or scaling input
  (settled out of scope by #282). Self-reported by whichever node is
  currently a route's authenticated gateway, read back from that route's
  own nftables forward-accept counter (`bins/karstd/src/gateway.rs`'s
  `karst_routes` table already tags it with the route's id), over the same
  control-channel session `KarstSessionObservation` already uses — not a
  second, relay-telemetry-style signed endpoint, since a node already has
  a live session here and ADR-0021's relay channel has no concept of
  "route" at all to report this through.
- **Both egress and ingress, each attributed per route.** Issue #371 split
  `karst_routes`'s previously shared, uncommented return-leg accept rule
  into one comment-tagged rule per route (ordered most-specific-destination
  first, the same way the forward-leg rules already were, so an exit route
  and a subnet route together on one gateway still attribute correctly
  rather than one claiming the other's reply traffic). Never a
  *destination* breakdown, though — only per-route.
- **Surfaced on the NOC map's `"route"` component** (`GET
  /noc/components`) as `bytes`/`packets` (egress) and
  `ingress_bytes`/`ingress_packets` (ingress), each summed across every
  route a gateway group serves — absent, not zero, until some gateway for
  the group has self-reported at least once. There is no per-route (as
  opposed to per-group) drill-down endpoint yet; the group-level sum is
  what this issue lands, and a finer drill-down is left for whenever the
  NOC view (#241) actually wants one.
- Latest snapshot only, the same posture relay telemetry (ADR-0021) and
  per-node throughput above both already have — no history, no rate, just
  the current total.

## Relay health and onboarding

- **Both are done.** Relay onboarding (add/remove with client-side address
  validation) predates this page; relay health now reflects a relay's own
  signed, periodic self-report to the control plane (ADR-0021, issue #147)
  rather than a permanent `"unknown"` placeholder.

## NOC view

- **Phase 1a is done: declared relay locations, a map, health, and current
  snapshot.** An operator declares a relay's position (`location.lat`/`lon`/
  `label`, optional) through the same add-relay form/API the Relays page
  already uses (ADR-0046 §1 — never GeoIP, never inferred from `address`).
  The NOC page (`GET /karst/v1/noc/components`, `GET
  /karst/v1/noc/relays/{id}`) plots every relay with a declared location on
  a map, color-coded by the same health states the Relays page shows, and
  lists relays with no declared location separately rather than hiding
  them. A new read-only `noc` role (ADR-0046 §6) can reach these two
  endpoints and nothing that writes; every view load and drill-down is
  audit-logged (`karst.noc.view`, `karst.noc.drilldown`) explicitly in the
  handler, since `auditMutations` only fires on a non-GET.
- **Deferred: history, current rate, and utilization against capacity**
  (ADR-0047). These need the Prometheus re-export and account-scoped query
  proxy ADR-0047 describes, which is separately scoped Phase 1b work, not
  part of this page yet. A relay's current snapshot today is still the
  same cumulative total the Relays page already shows (`health.bytes`), not
  a rate.
- **Deferred: non-relay components and client aggregates.** Exit nodes,
  subnet routers, TURN, Bedrock, and the control plane itself (#241's own
  Phase 3) and client per-region/per-aquifer aggregates (ADR-0046 §2, #241's
  Phase 4) are not on this page yet — it shows relays only.
- **Done: the basemap is now Natural Earth's 1:110m admin-0 country
  boundaries**, not the original hand-authored placeholder. Converted from
  the `world-atlas` npm package's TopoJSON (ISC-licensed packaging of
  public-domain Natural Earth data — no attribution required) to GeoJSON
  with `topojson-client` at build time, trimmed to `{name, geometry}` and
  rounded to 3 decimal places; still a bundled static asset fetched from
  nowhere but the console's own origin, per ADR-0047 §5.
  `public/noc-world-outline.geojson` grew from ~1.3 KB to ~190 KB
  accordingly (~64 KB gzipped) — Caddy does not currently compress
  responses (no `encode` directive), so that's the real wire cost today.
  The map now uses MapLibre's globe projection and adds worldwide Natural
  Earth admin-1 state/province borders as thinner dashed lines beneath solid
  national outlines, with both styles identified in the legend. The new
  simplified boundary asset adds about 2.9 MB uncompressed. Provenance and
  regeneration instructions are in `web/console/public/noc-boundaries.md`.
  **Known trade-off: MapLibre GL adds real bundle weight.** Adding it —
  this console's first mapping dependency and first library over
  ~500 KB gzipped — pushed
  the main bundle past Vite's default chunk-size warning; this console has
  no code-splitting convention today (every other dependency, including
  CodeMirror, ships in the one main bundle), so the NOC page is not
  lazy-loaded either, consistent with that, but is the first page where the
  cost of that convention is visible.

## Scaler Advisor view

- **Phase 1 is done: a read-only table of the Advisor's latest
  recommendation per pool.** ADR-0045 §7 Phase 1 ("the planner and
  constraint set... running continuously, publishing 'recommended vs
  actual' as metrics and a console view"). `GET
  /karst/v1/scaler/recommendations` proxies, unchanged, whatever
  `karst-scaler advise`'s own loopback `/recommendations` endpoint last
  returned — `karst-control` dials it server-to-server at an
  operator-configured address (`KARST_SCALER_ADVISOR_URL`); the browser
  never reaches `karst-scaler` directly. Requires the `advisor` role, the
  same as the demand-side endpoints this page's data ultimately derives
  from. No mutation actions: there is nothing to mutate in Phase 1 — no
  driver exists yet to act on a recommendation (that is Phase 2).
- **Configured-not-actual, labeled as such.** The "Configured" column is
  each pool's own `min_nodes` floor from its cost-model file, not an
  introspected live running count — `karst-scaler`'s own advise.rs module
  doc explains why (no driver interface exists yet to ask a provider
  directly). A fleet that has drifted from that file reads as if it
  hadn't; this is a known, documented gap, not an implied guarantee.
- **Deferred: everything Phase 2+ would add.** No live polling (the page
  loads once per visit, unlike the NOC page's 30s refresh — Phase 1's data
  changes on `karst-scaler advise`'s own poll interval, typically minutes,
  not seconds), no per-pool drill-down, and no way to act on a
  recommendation from here. If `KARST_SCALER_ADVISOR_URL` is not
  configured for a deployment, every request to this page's endpoint
  answers precondition-failed — metrics (`karst_scaler_*`, see
  `docs/observability.md`) still ship standalone and are directly
  scrapeable regardless, so this page being unconfigured loses a UI, not
  the underlying capability.
- **API-only, no console rendering yet: `GET /karst/v1/scaler/suggestions`**
  (issue #381) — manual mode's own "suggested by RTT" signal, proxied the
  same way `/scaler/recommendations` is, from `karst-scaler advise`'s own
  loopback `/suggestions` endpoint. Two RTT-derived lists: `latency_breaches`
  (an existing pool's region currently exceeding its configured p95
  threshold) and `region_candidates` (a region with anchor-RTT observations
  but no pool at all today, ranked by estimated p95 — a crude stand-in
  ranking, not a verified formula). Same `advisor` role gate as
  `/scaler/recommendations`, computed every tick regardless of the §7
  Phase 1/2 mode. No console page renders this yet — a separate, later
  concern, same posture as this page's own missing per-pool drill-down
  above.
- **API-only, no console toggle yet: `GET`/`PUT /karst/v1/scaling/mode`**
  (issues #356, #379, #380, #382) — ADR-0045 §7's Phase 1 (manual, compute
  and report)/Phase 2 (automated, compute and reconcile) choice as a live,
  deployment-wide setting, defaulting to `automated` so every existing
  `karst-scaler drive` deployment keeps today's behavior on upgrade. `GET`
  needs no elevated role beyond the blanket module-Read gate every
  read-capable console role already has; `PUT` is admin-only through that
  same gate's Update check. `karst-scaler drive` fetches it fresh every
  tick and fails that tick closed (logs and retries next tick, actuating
  neither mode) if the fetch fails or the value is unrecognized, rather
  than guessing a stale mode. No console settings UI for this yet — a
  separate, later concern, same posture as this page's own missing
  per-pool drill-down above.
