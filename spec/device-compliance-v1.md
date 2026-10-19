<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Device compliance v1 — proposed implementation contract

**Status:** Proposed; not an implemented API or operational guarantee.
**Related:** [ADR-0055](../docs/adr/0055-device-compliance-and-resource-access.md),
[#363](https://github.com/karst-net/karst/issues/363).

## Evidence and requirements

A report contains a schema version, server-issued single-use challenge, enrolled
device identity, collector version, typed observations and collection errors.
The authenticated control session determines tenant and device; payload IDs
cannot override them. Challenges expire after 60 seconds and are consumed
atomically across replicas. Replays, cross-device and cross-tenant submissions
are rejected. Device replacement/key rotation invalidates outstanding challenges.
The collector must gather observations after receiving the challenge. The server
timestamps receipt and rejects expired challenges; it cannot independently prove
collection time for self-reported values. Client timestamps are diagnostic only
and cannot extend freshness.
A compromised client can still lie about collecting a self-reported observation.

Collect on challenge, startup/reconnect and relevant local changes, and refresh
at least every 60 seconds while connected. Evidence expires 180 seconds after
server receipt. Provider evidence has a separately validated observation time
and no longer freshness limit; a provider outage cannot renew old evidence.

A requirement names a supported typed check, parameters and accepted provenance.
A requirement set is a conjunction. Only `compliant` satisfies a requirement.

| State | Meaning |
| --- | --- |
| compliant | Fresh accepted evidence passes all required comparisons. |
| noncompliant | Fresh accepted evidence fails a required comparison. |
| unknown | No applicable evidence or required value is missing. |
| unsupported | Collector/platform/provenance cannot supply the required check. |
| stale | Previously accepted evidence is beyond its freshness deadline. |
| evaluation-error | Collection, decoding or evaluation failed. |

Store per-check states and reasons, rather than hiding failures behind one
aggregate boolean. Any nonpassing check denies the protected resource; the UI
shows all reasons and evidence age. An evaluation failure must not renew a prior
passing decision. Missing/deleted requirement references reject policy changes;
unresolved persisted references deny affected resources.

## Initial capability matrix

This is the delivery target, not a statement of current collector support.

| Check | Linux | macOS | Windows | Trust |
| --- | --- | --- | --- | --- |
| Minimum Karst client version | Planned | Planned | Planned | Authenticated self-report |
| Minimum OS release | Planned, distribution ID + release; unknown distributions unsupported | Planned, product release | Planned, OS build | Authenticated self-report |
| Disk encryption / screen lock | Unsupported | Unsupported | Unsupported | No collector committed |
| Managed device / endpoint security | Unsupported | Unsupported | Unsupported | Requires separate collector/provider design |

Other platforms are unsupported initially. Define and test release ordering for
each supported distribution/product; do not compare arbitrary version strings
lexically or equate a Linux kernel version with a distribution release. Product
UI must show the self-reported trust level. Provider-verified checks are a later
capability, not an alias for these initial checks.

## Authorization and expiry

Resource guardrails constrain destination selectors, transport/ports and routed
CIDRs after identity grant resolution. All matching requirements apply to every
source device. Source wildcards must resolve into device-specific decisions;
they cannot retain an unconditional bypass. CIDR/port intersections and selector
changes are reevaluated. Policy preview shows effective requirements and grant
provenance for each affected flow, including remediation conflicts.

The wire design must carry a versioned compliance capability and resource-scoped
permits bound to tenant, device, policy revision and evidence generation.
Permits are authenticated by control and cannot be transferred between devices.
Do not rely on a peer's assertion of its own compliance: distribute the result
to the receiving endpoint or routed gateway as well as the originating client.
A client lacking the mandatory enforcement capability cannot receive protected
access; capable receivers/gateways must deny it. Activating a guardrail requires
capable receiving enforcers for every matching resource, including routed paths.

Proposed maximum permit lifetime is **120 seconds**, capped by the evidence's
remaining lifetime. Refresh every **30 seconds**; invalidate and publish affected
decisions immediately on accepted failure, evidence expiry, policy change,
identity revocation or device removal. Target online delivery is 30 seconds;
the security bound is **120 seconds after the last permit issuance**, even if
notifications or control connectivity fail. A newly observed failure must stop
permit issuance atomically with storing its evaluation. These are acceptance
targets to test, not guarantees of the current polling implementation.

The receiver enforces remaining lifetime using suspend-aware elapsed time and
never restarts a lease from a cached response. Restarted clients must obtain
fresh permits; encrypted offline caches preserve only unprotected grants.
Wall-clock rollback, sleep/resume, unchanged-netmap replies and reconnect must
not extend validity. A response must be bound to a fresh client request with a
locally tracked deadline; transit/retry delays consume its validity budget.
Old policy revisions cannot renew permits after revocation. Multiple replicas
must read authoritative evaluation/policy state when issuing a permit.

Enforce on every protected packet, before established-flow/reply or SSH-admission
caches can allow it. On denial clear affected cached permissions and stop
forwarding established direct, relayed, SSH and routed traffic in both directions;
no new handshake is required to revoke access. Merely hiding peers, DNS records
or UI actions is insufficient. Retain only independent explicit unprotected
grants during disconnection. Fresh passing evidence restores existing grants
without reenrollment, domain moves or identity privilege expansion.

## Operations, privacy and acceptance

Requirement/policy editing is account-scoped authorization; evidence ingest is
restricted to the authenticated device or its configured provider. Status and
explanations follow existing device visibility/delegation, with no sibling-domain
or cross-tenant disclosure. Evidence is not an arbitrary executable/script API.
Store only required typed values, provenance, timestamps and failure codes; no
process lists, file contents or provider credentials in device status or audit.
Proposed retention: latest evidence until device deletion or 24 hours after
expiry, and decision-change audit events for the deployment's configured audit
retention. Provider secrets require separate secret storage. Audit records
include actor, device, requirement/policy revision, state transition and affected
resource identifiers; avoid logging every unchanged refresh.

Deliver in reviewable stages; keep #363 open until all stages pass:

1. Typed requirement/evaluation model with deterministic time inputs, version
   comparators and tests for every nonpassing state and provenance mismatch.
2. Authenticated challenge/report persistence, replica-safe replay protection,
   expiry scheduling and platform collectors; publish actual capability matrix.
3. Resource guardrails, overlap validation, policy preview and device-specific
   ingress/egress/routed compilation, independently composed with SSH.
4. Versioned permits, compatibility handling and local packet-path expiry;
   prove established-session and offline bounds before enabling policy writes.
5. Scoped console status, remediation explanations, audit and operator guidance.
6. Real Go-control/Rust-datapath tests: two same-user devices, explicit remediation,
   failure/expiry/recovery, replay/spoofing, tenant/delegation isolation, overlapping
   grants, CIDRs, direct/relay/SSH/routed established flows, restart, suspend,
   clock changes, delayed responses and control loss/reconnect. Measure the
   120-second bound; a mocked policy verdict alone is insufficient evidence.
