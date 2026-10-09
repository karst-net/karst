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
- **Known trade-off: the basemap is a coarse, hand-authored placeholder, and
  MapLibre GL adds real bundle weight.** `public/noc-world-outline.geojson`
  is a handful of deliberately schematic continent silhouettes, not a real
  geographic dataset — chosen over fetching a third-party dataset of unknown
  license. Swapping in a properly licensed, simplified dataset (e.g. a
  trimmed Natural Earth 1:110m extract, license-checked first) is a
  follow-up, not done here. Separately, adding MapLibre GL — this console's
  first mapping dependency and first library over ~500 KB gzipped — pushed
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
