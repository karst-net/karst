<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Device compliance v1 — proposed implementation contract

**Status:** Proposed; not an implemented API or operational guarantee.
**Related:** [ADR-0055](../docs/adr/0055-device-compliance-and-resource-access.md),
[#363](https://github.com/karst-net/karst/issues/363).

## Implementation status

The internal Go package `server/management/internals/karst/compliance` implements
stage 1's typed requirements, deterministic evaluation and version comparison.
The authenticated control channel now accepts challenge/report ingestion (request
kind 5) into a tenant/device/identity-bound SQL row. It is not connected to policy
writes, netmaps or packet enforcement.
There are no supported client collectors yet. The capability matrix below remains
a delivery target; #363 remains open.

`Evaluate` accepts an explicit server evaluation time and authenticated subject.
Its evidence input must come from trusted ingestion: identity, receipt time and
provenance are not client-controlled claims. Invalid requirements, duplicate IDs,
empty sets, incomplete subjects and missing evaluation time return an error and
an unsatisfied result. Callers must deny on error. Nonpassing evidence retains a
state and fixed reason code for every requirement without returning raw values
or collection error messages. A passing evaluation carries the evidence deadline;
it is a snapshot, not an access grant, and must be reevaluated before reuse.

Initial comparison rules:

- Client versions require full SemVer (optional `v` prefix). Prereleases sort
  below their final release; build metadata does not affect ordering. CI's
  `0.0.0+git.SHA` is a version, while local `dev` is an evaluation error.
- macOS uses numeric product `major.minor[.patch]`; Windows uses numeric
  `major.minor.build[.revision]`, not marketing names.
- Linux initially recognizes only distribution ID `ubuntu` with a two-component
  numeric release, and `debian` with one or two numeric components. Kernel
  versions and other distributions are not substituted for product releases.
- OS components compare numerically with omitted trailing components treated as
  zero. Ubuntu's zero-padded components are accepted. Invalid or overflowing
  components fail evaluation. Each OS requirement names one platform and, for
  Linux, distribution; other platforms/distributions are unsupported for that
  requirement. Multiple requirements are AND, not alternative platform branches.

Fresh evidence expires exactly at server receipt plus 180 seconds. A future or
missing server receipt time is an evaluation error. Evaluation checks subject,
server time, expiry, provenance, platform and observation validity in that order;
only a fresh accepted observation can reach the version comparison. An unknown
observation status or a value attached to a non-collected status is malformed.
No error path falls back to an earlier passing observation.

Validation: `cd server && go test -race -count=1 ./management/internals/karst/compliance/`.
Tests cover all six states, precise expiry boundaries, trust/identity mismatch,
malformed observations, platform/version ordering, conjunctive results,
independent devices, new collection errors and recovery.

## Implemented ingestion protocol

Schema 1 uses `KarstComplianceRequest` / `KarstComplianceResponse` inside the
existing authenticated encrypted control channel, request kind **5**. A request
must select one operation: `challenge: true`, or a report. The complete protobuf
payload is limited to 4096 bytes. Existing login, netmap, Bedrock and push kinds
are unchanged. An old server can reject kind 5; this must never be interpreted
as evidence acceptance or an enforcement capability.

The challenge response contains 32 random bytes and `valid_for_seconds: 60`.
Only its SHA-256 hash is stored. A new challenge invalidates the previous one;
it does not refresh existing evidence. Receipt exactly at expiry is rejected.
The duration starts when the server issues the challenge; client transit time
and retries do not extend it. Reconnect can submit an outstanding unexpired
challenge to any replica, or request a replacement.

A report includes that challenge, a nonempty collector version (up to 128
bytes), platform/distribution (up to 64 bytes each), and client/OS version
observations (up to 128 bytes per value). Observation statuses are missing,
collected, unsupported and collection error. Missing or malformed observations
are persisted as nonpassing evidence, rather than retaining an old pass. Invalid
schema, oversized fields or an invalid challenge reject the request; these do
not refresh evidence. An accepted response acknowledges persistence only, not a
compliance decision or resource grant. No timestamp, tenant, device, provenance
or aggregate compliant flag is accepted from the report.

The handler derives the identity handle from the verified control handshake,
looks up its enrollment, and obtains tenant/device IDs from that record. The
SQL transaction checks and locks the matching authoritative peer row, so stale
manager/cache entries cannot submit evidence after deletion or key replacement.
A different enrollment ID cannot use a previous enrollment's challenge, even
with the same identity key. Cross-tenant/device/identity submissions fail. All
ingested observations are explicitly self-reported.

Challenge consumption, latest-evidence replacement and the evidence generation
increment share one conditional database update. Two replicas cannot consume
the same challenge. A database failure rolls back consumption. The store keeps
only the latest report, never report history; callers must evaluate it against
the current policy and time. Expiry is computed by the evaluator on read; an
active expiry scheduler and invalidation of permissions remain unimplemented.

Evidence becomes unavailable to the store's readers 24 hours after its
180-second freshness deadline. New challenge issuance clears evidence past
that retention deadline; challenge refresh cannot retain old observations.
Startup and hourly pruning physically remove expired records and records whose
enrollment was deleted or replaced, and clear expired evidence even when a
challenge is still active. Physical cleanup can lag the deadline by one worker
interval; authentication/read checks take effect immediately. No provider
credentials, process lists or arbitrary collector error text are stored.

Validation includes race-enabled SQLite tests over independent database pools,
a real authenticated Go gRPC session, Go/Rust protobuf vectors, and PostgreSQL
replica-consumption/enrollment-lock tests. PostgreSQL tests run when
`KARST_TEST_POSTGRES_DSN` is set, including the existing Go CI job. Collectors,
reporting cadence, policy evaluation persistence, expiry notifications and all
permission/datapath work are still pending.

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
