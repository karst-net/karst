<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# `karst_node_identities` snapshots, in order

Raw `sqlite3` queries against the isolated `karst496` deployment's
`state/netbird/store.db` on `turing`, redacted of nothing sensitive (`handle`
is a node's public key, not a secret). Two enrolled nodes throughout:

- `Y40WfcyWwhki9qX5bkqRHs2lxVcChz2Gq2I5zwuw0/U=` — the "baseline" node,
  first enrolled on the `e67b50c` build (SWV-01).
- `9741pyvyIVOix7XxiN5mxsWWQrtyI1eJUNAgWYNaSXw=` — the "preschema" node,
  first enrolled on the pre-`843e714` build that reports no
  `relay_lifecycle_schema`/`gateway_ingress_schema` field at all (SWV-04).

## 1. After baseline enrollment (SWV-01)

```json
{"handle":"Y40WfcyWwhki9qX5bkqRHs2lxVcChz2Gq2I5zwuw0/U=","relay_lifecycle_schema":1,
 "software_version":"0.0.0+git.e67b50c575ede1c2d713ab62c3707a50f0f790c4",
 "software_revision":"e67b50c575ede1c2d713ab62c3707a50f0f790c4",
 "software_artifact_id":"sha256:315796b64d21be3c76f331302072925533c514610841e55df3c31d476f64f7fa",
 "software_observed_at":"2026-11-05 01:30:25.766211362+00:00",
 "control_check_status":"accepted","control_check_required_schema":0,"control_check_reported_schema":0,
 "control_check_observed_at":"2026-11-05 01:30:25.777554095+00:00"}
```

Release, source revision, and the Linux `sha256:<digest>` artifact identity
all populated during ordinary control sync, with compliance collection left
disabled for this deployment throughout. (SWV-01: **Pass**.)

## 2. After preschema enrollment, before any policy grant (SWV-02 "unknown" case)

```json
{"handle":"9741pyvyIVOix7XxiN5mxsWWQrtyI1eJUNAgWYNaSXw=","relay_lifecycle_schema":0,
 "software_version":"","software_revision":"","software_artifact_id":"",
 "software_observed_at":null,
 "control_check_status":"accepted","control_check_required_schema":0,"control_check_reported_schema":0}
```

A build that predates software-identity reporting entirely leaves every
`software_*` field unset (shown by the console as "unknown"), not inherited
from any other node. `relay_lifecycle_schema` is genuinely `0` because that
build never sends the field (proto default), distinct from a node that sends
`0` on purpose.

## 3. After adding the `gateway_ingress_schema` grant and restarting the preschema node (SWV-04 rejection)

```json
{"handle":"9741pyvyIVOix7XxiN5mxsWWQrtyI1eJUNAgWYNaSXw=",
 "control_check_status":"incompatible","control_check_capability":"gateway_ingress_schema",
 "control_check_required_schema":1,"control_check_reported_schema":0,
 "control_check_observed_at":"2026-11-05 01:38:23.475502789+00:00"}
```

Matching client-side log line (`docker logs issue496-preschema`):

```
WARN karstd::run: netmap refresh failed; session held open, retrying
  error=server: server returned The system is not in a state required for the
  operation's execution: Gateway destination-scoped ingress requires
  gateway_ingress_schema 1; upgrade the agent retry_in=8s
```

Rejection names the exact capability and required/reported schema, with
actionable upgrade guidance, and is visible without SSH or log parsing (the
console's Machines → Status view surfaces these same `control_check_*`
columns — see `docs/operations/software-versions.md`; this isolated
deployment has no OIDC provider wired up to actually render that console, so
this record cites the underlying API-visible fields the console reads
instead). (SWV-04 rejection half: **Pass**.)

## 4. After upgrading the preschema node in place to the HEAD build (SWV-02 non-inheritance, SWV-04 recovery)

```json
{"handle":"9741pyvyIVOix7XxiN5mxsWWQrtyI1eJUNAgWYNaSXw=","relay_lifecycle_schema":1,
 "software_version":"0.0.0+git.3abe96e8d7e35d200c33f9ca89b344d25c3aa3e7",
 "software_revision":"3abe96e8d7e35d200c33f9ca89b344d25c3aa3e7",
 "software_artifact_id":"sha256:c712de7b51396d40a4acd7ccf909a2690bb846cfec1e95a706dc384bf5f939ae",
 "software_observed_at":"2026-11-05 01:39:26.846501613+00:00",
 "control_check_status":"accepted","control_check_required_schema":0,"control_check_reported_schema":0,
 "control_check_observed_at":"2026-11-05 01:39:26.865357897+00:00"}
```

The previously-unset identity is now fully populated by the new build's own
values — no field carries over from "unknown," and the rejection clears to
`accepted` once the agent reports `gateway_ingress_schema: 1`. (SWV-02 and
the SWV-04 recovery half: **Pass**.)

## 5. After also upgrading the baseline node in place (artifact identity actually changes, not just appears)

```json
{"handle":"Y40WfcyWwhki9qX5bkqRHs2lxVcChz2Gq2I5zwuw0/U=","software_version":"0.0.0+git.3abe96e8d7e35d200c33f9ca89b344d25c3aa3e7",
 "software_revision":"3abe96e8d7e35d200c33f9ca89b344d25c3aa3e7",
 "software_artifact_id":"sha256:c712de7b51396d40a4acd7ccf909a2690bb846cfec1e95a706dc384bf5f939ae",
 "control_check_status":"accepted"}
```

The artifact identity changed from `sha256:315796b6…` (the `e67b50c` build)
to `sha256:c712de7b…` (the HEAD build) — a real hash change from a real
binary replacement, not a stale or merged value. Both nodes now share the
same hash because they are running byte-identical copies of the same HEAD
build, which is the expected and correct outcome.
