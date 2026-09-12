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
