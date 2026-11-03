<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-0066: Admin-tracked component rollout plans (v1: track and gate, operator executes)

- **Status:** Accepted
- **Date:** 2026-11-03
- **Deciders:** Project owner (issue #484)
- **Related:** [#484](https://github.com/karst-net/karst/issues/484), ADR-0063, ADR-0062, ADR-0057, ADR-0058

---

## Context

#484 asks for an administrative workflow to update deployed control/console/
relay/gateway components with verified artifacts, compatibility checks,
sequencing, progress reporting, and rollback. It is motivated by a real
incident on Shannon: updating control alone left the gateway daemon on an
older, incompatible release, causing invitation failures and an unavailable
exit gateway.

Today, rollout is manual and almost entirely undocumented:

- `deploy/nomad/prod/karst.nomad.hcl` pins `console_image_digest` with an HCL
  validation block enforcing a `sha256:...` shape — the only mechanically
  enforced digest pin anywhere in the repo. `control_image_digest`/
  `relay_image_digest` are job variables with no such check.
  `deploy/nomad/prod/README.md` documents a fully manual, console-only
  procedure: `cosign verify` the digest by hand, edit `deployment.vars.hcl`,
  `nomad job plan`/`run`/`status`, smoke-check. Rollback is "restore the
  previous verified digest and repeat." Control and relay have no documented
  procedure at all.
- Compose (`deploy/compose/prod`, `deploy/compose/ha`) and Kubernetes
  (`deploy/kubernetes`) have no digest pinning or update tooling whatsoever.
- `scripts/compose-versions.py` → `components.json` →
  `GET /versions` (`server/management/internals/karst/api/versions.go`) is a
  manually-run, read-only snapshot. Nothing today acts on it.
- Compatibility checking exists, but only in one direction: `node.ControlCheck`
  (`server/management/internals/karst/node/control_check.go`) and the two
  inline evaluations in `NetmapHandler.Handle`
  (`server/management/internals/karst/control/netmap.go`) compare *one
  reporting agent's* declared schema against a *hardcoded constant* baked
  into the currently-running control binary. There is no model anywhere for
  "does component A's target release require something component B's
  current fleet does not have" — the actual gap the Shannon incident
  exposed. `GatewayIngressSchema` in particular is checked on the wire but
  never persisted, so there is no way to query current fleet state for it
  outside a live netmap call.
- The established pattern for an admin-triggered, multi-step, durable record
  in this codebase is ADR-0063's relay allocation
  (`server/management/internals/karst/relayalloc/store.go`): a GORM store
  with an explicit state-machine allow-list, compare-and-set transitions, and
  an append-only history table. There is no generic job/workflow framework;
  billing (`billing/payment_state.go`) and relayalloc each hand-rolled the
  same shape independently. ADR-0063 itself set the precedent of narrowing
  v1 scope explicitly in the ADR (AWS driver only, deferring Kubernetes/LXD)
  rather than building everything a feature request could imply. ADR-0062
  deliberately chose **no automatic rollback** for the one existing
  admin-triggered update-adjacent workflow ("a failed restart can require
  local Docker diagnosis") even though automating it was feasible.

CONTRIBUTING.md requires an ADR for significant changes.

## Decision

Add a new `rollout` package tracking a durable, sequenced **rollout plan**
covering the single production Nomad job's `control`, `console`, and
`relay` task groups. A plan records, per component: a target digest, an
operator attestation that they ran `cosign verify` against it (per the
existing README procedure), an apply sequence, and — on `control` — the
schema requirements its target release introduces. Before a plan starts, and
again on every read, the server computes a live **fleet compatibility
preview**: it counts enrolled Karst agents whose persisted
`relay_lifecycle_schema`/`gateway_ingress_schema` fall below what the target
declares, reusing the exact counting-query shape
`node.Store.CheckRelayLifecycle` already uses in production, parameterized
instead of hardcoded. This directly answers the Shannon incident's root
cause: a sequencing/compatibility question is now asked and shown *before*
anything is touched, not discovered after the fact.

**karst-control does not gain the ability to call Nomad, a container
registry, or `cosign` in v1.** Even when ADR-0063 had a far stronger case
for full automation — an existing `Driver` trait, an existing
reconciliation-loop pattern, multi-minute external calls — it still kept
every external-mutating call out of `karst-control` itself, in a separate
Rust process with its own narrowly-scoped role and PAT. Control has never
held infrastructure-mutating credentials. This workflow's own operations
(digest-shape validation, DB reads/writes, a fleet-counting query already
proven fast enough to run inline in `netmap.go`'s hot path) do not need any.
The operator still runs `cosign verify`, edits `deployment.vars.hcl`, and
runs `nomad job plan`/`run`/`status` exactly as the existing README
documents — now informed by a verified, compatibility-checked plan instead
of an eyeballed diff — and then tells control which component was applied.
Control reconciles that claim, non-blockingly, against the next
`components.json`/`GET /versions` snapshot.

**No async Rust reconciliation loop.** Unlike relay allocation's
multi-minute cloud provisioning, nothing in this workflow is slow or
external: everything runs synchronously inline in the Go HTTP handler.
Adding a second process here would be complexity with no slow step to
reconcile against.

A prerequisite, symmetric persistence gap is closed alongside this: `Identity`
gains a `GatewayIngressSchema` column (mirroring the existing
`RelayLifecycleSchema` one), populated unconditionally on every netmap
request, so fleet state for that capability is queryable the same way.

### Alternatives rejected

- **Have karst-control call Nomad/a registry/`cosign` directly to execute
  the rollout.** Rejected per the trust-boundary reasoning above: this is a
  strictly larger blast-radius increase (Nomad-mutating credentials inside
  the system-of-record for identities/ACLs/billing) than anything shipped so
  far, for a workflow that is a handful of operator-driven CLI steps, not a
  multi-minute provisioning operation the way relay allocation's cloud
  driver call is.
- **An async Rust reconciliation loop, mirroring relay allocation's.**
  Rejected: there is no slow external step anywhere in this design to
  reconcile against. Digest-shape validation, DB transactions, and a fleet
  count all complete inline.
- **Infer a release's required schema from a version string.** Rejected: no
  machine-readable per-release compatibility manifest exists in the release
  pipeline (`deliverables.yml`), and the required schema is a compile-time
  literal baked into whichever control binary happens to be running — it
  cannot introspect a not-yet-deployed binary's own requirements. The
  operator enters the two required-schema integers by hand, the same
  knowledge ADR-0057 already expects them to have for manual version-skew
  handling.
- **Extend tracking to Compose, Kubernetes, or systemd in v1.** Rejected:
  none of them has any digest-pinning discipline today (only the Nomad job's
  `console_image_digest` does); building that groundwork is separate,
  prerequisite work.
- **Automatic rollback execution.** Rejected for v1, matching ADR-0062's own
  precedent: control only records that a rollback happened. The operator
  restores the previous verified digest and reruns `nomad job plan`/`run`
  by hand.

---

## Consequences

### Positive

- An auditable, sequenced record replaces tribal knowledge for every
  component rollout, not just console's already-documented one.
- Fleet compatibility is checked and shown *before* a rollout starts,
  directly addressing the Shannon incident's root cause.
- Symmetric `GatewayIngressSchema` persistence closes a real existing gap:
  fleet-wide Gateway-ingress compatibility can now be queried without a live
  netmap round trip.
- No new trust boundary, no new process, no new dependency (cosign/sigstore)
  inside `karst-control`.

### Negative

- v1 is attestation-based, not verification-based: a wrong or dishonest
  `VerificationRef` is not caught by control. This mirrors every other
  claim an operator already enters during the existing manual procedure, but
  it is worth stating plainly: the server does not re-verify the signature.
- Sequencing is only enforced across separate `nomad job run` invocations,
  one component at a time; it says nothing about ordering within one job
  apply that touches multiple task groups at once.
- Fleet-compatibility scoping, in the absence of a role taxonomy on
  `Identity`, falls back to "every enrolled Karst peer" unless the operator
  picks a narrower group — coarser than a true relay/gateway-only check.
- The operator must still correctly run the real `nomad`/`cosign` commands
  by hand; this workflow tracks and gates that work, it does not remove the
  chance of operator error during execution itself.

### Reconsider if

A structured, machine-readable compatibility manifest is published per
release; a generic durable job/workflow system appears elsewhere in this
codebase (the same trigger ADR-0063 already names); enrolled identities gain
a real role taxonomy; or operational experience with this manual loop
justifies giving control a narrowly-scoped, plan-only (never-run) Nomad
token for an automated dry-run diff — strictly short of `nomad job run`
rights.
