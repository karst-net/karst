<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Device compliance v1 — proposed implementation contract

**Status:** Partially implemented: evaluation, ingestion, version collection,
invalidation scheduling, internal guardrail preview/gate compilation, and a
real permit wire contract issued by the server and enforced on the datapath,
proven end to end against a real Go control server and measured at the
120-second revocation bound.
No persisted admin policy-write API exists yet for compliance guardrails, so
every snapshot issued in production today still carries zero gates: the wiring
is live, but nothing an operator configures reaches it.
**Related:** [ADR-0055](../docs/adr/0055-device-compliance-and-resource-access.md),
[#363](https://github.com/karst-net/karst/issues/363).

## Implementation status

The internal Go package `server/management/internals/karst/compliance` implements
stage 1's typed requirements, deterministic evaluation and version comparison.
The authenticated control channel now accepts challenge/report ingestion (request
kind 5) into a tenant/device/identity-bound SQL row. It is not connected to policy
writes, netmaps or packet enforcement.
`karstd` now collects self-reported client versions and supported native OS
releases, with bounded challenge/report attempts on live supporting servers.
Evidence change/expiry invalidations now use a durable retry queue and the peer
notification path. The policy package also provides an internal draft guardrail
validator, diagnostic evaluator and device-specific mandatory gate compiler.
Policy activation and netmap distribution of a real, operator-configured
guardrail remain pending (no persisted admin policy-write API exists yet for
compliance drafts); #363 remains open.
Permit messages, Go structural validation and Go/Rust wire vectors are now live
on the wire: `KindCompliancePermit` (request kind 6) is issued by `PermitHandler`,
which compiles a tenant's compliance draft via `policy.CompileCompliance`, and
support is advertised through the `compliance_permit_schema` netmap capability
field. `karstd`'s control client requests and validates a fresh snapshot on the
existing 30-second refresh cadence, and `Engine::permit` enforces the result on
every protected packet, uncached, alongside the general ACL and the independent
SSH gate. Because no production caller supplies a non-nil `Draft` yet, every
issued snapshot still has zero gates — a real, structurally valid wire round
trip with zero enforcement effect until policy writes are enabled.

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

Challenge consumption, latest-evidence replacement, evidence generation and
invalidation state share one database transaction with conditional updates. Two replicas cannot consume
the same challenge. A database failure rolls back consumption. The store keeps
only the latest report, never report history; callers must evaluate it against
the current policy and time. Expiry is computed by the evaluator on read and actively scheduled for
invalidation. Invalidation of actual permissions remains unimplemented.

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
`KARST_TEST_POSTGRES_DSN` is set, including the existing Go CI job. Platform
coverage beyond the matrix, policy evaluation persistence and all
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

Version collectors are implemented below. They are self-reports, not proof of
host integrity; no resource enforcement is enabled. Native smoke tests run on
the repository's Linux, macOS and Windows CI jobs. macOS daemon collection uses
a bounded system-command invocation; sandboxed Network Extension/App Store
execution has not been validated. A denied invocation reports collection error.

| Check | Linux | macOS | Windows | Trust |
| --- | --- | --- | --- | --- |
| Minimum Karst client version | Implemented | Implemented | Implemented | Authenticated self-report |
| Minimum OS release | Ubuntu/Debian distribution ID + release; others unsupported | Product release | Major/minor/build; no UBR revision | Authenticated self-report |
| Disk encryption / screen lock | Unsupported | Unsupported | Unsupported | No collector committed |
| Managed device / endpoint security | Unsupported | Unsupported | Unsupported | Requires separate collector/provider design |

Other platforms are unsupported initially. Define and test release ordering for
each supported distribution/product; do not compare arbitrary version strings
lexically or equate a Linux kernel version with a distribution release. Product
UI must show the self-reported trust level. Provider-verified checks are a later
capability, not an alias for these initial checks.

## Implemented client collection and cadence

`KarstNetmapResponse.compliance_ingestion_schema` advertises ingestion support
on the authenticated live channel, including unchanged responses. Only schema 1
triggers kind-5 requests. Zero or unknown versions trigger no probe. The field
is excluded from the policy content hash, never restored as an advertisement
from the offline cache, and reset on reconnect. It is not an enforcement
capability or a compliance verdict.

On first live sync and ordinary reconnect the client requests a fresh challenge,
then collects and submits observations. Supporting servers use a 30-second
netmap/report poll, with reporting throttled across extra push-driven syncs.
The cadence samples version changes within a poll; native OS change-event
subscriptions are not implemented. Legacy servers retain their 60-second poll.
A report attempt is bounded to five seconds; asynchronous file/command collection
has a two-second timeout. Timeouts/refusals discard the stream so late replies
cannot be interpreted as the next netmap. A failed report preserves the valid
netmap and requests reconnection after one second to restore push reception;
that reconnect retains the report retry interval so repeated report failures
cannot continually close the push stream. No passing status or old observation
is substituted for a failed collection or unconfirmed submission.

Sources and limitations:

- Client and collector versions use the embedded `KARST_VERSION`. A local `dev`
  build reports that literal value; it does not fabricate a SemVer version and
  cannot satisfy a minimum-client-version comparison.
- Linux reads bounded `ID` and `VERSION_ID` from `/etc/os-release`, falling back
  to `/usr/lib/os-release` only when the former is missing. It never executes
  shell expansions or substitutes `ID_LIKE`/kernel releases. Only Ubuntu and
  Debian use the initial numeric comparators. Missing versions report missing;
  malformed/unreadable data reports collection error; other distributions report
  unsupported. See the [os-release specification](https://www.freedesktop.org/software/systemd/man/latest/os-release.html).
- macOS runs `/usr/bin/sw_vers -productVersion` without a shell and with
  `SYSTEM_VERSION_COMPAT=0`, bounded output and kill-on-timeout. It reports product
  major/minor/patch rather than a Darwin kernel version. Apple documents the
  system version source and `sw_vers` in its [version reference](https://developer.apple.com/documentation/installer_js/system/1812284-version).
- Windows uses Microsoft's safe `windows-version` wrapper for the native
  major/minor/build, with zero/invalid results treated as collection error.
  It does not collect UBR patch revisions; a four-component requirement compares
  the omitted revision as zero. See Microsoft's [wrapper implementation](https://github.com/microsoft/windows-rs/blob/master/crates/libs/version/src/lib.rs).

Validation includes collector/parser/freshness-cadence unit tests, native smoke
tests, live capability advertisement/withdrawal tests, and real Rust-client to
Go-store tests for ingestion, unchanged-sync throttling, fresh reconnect reports,
offline caches, legacy compatibility, refused reports and timed-out streams.
Run the wire tests with `cargo test -p karstd --test control compliance_ -- --ignored --test-threads=1`
with the repository's Go toolchain on `PATH`. These tests use isolated fixture
listeners and do not configure host networking.

## Implemented change and expiry invalidations

Accepting evidence atomically persists its freshness deadline and queues an
invalidation when typed observations or collector version change, or evidence
recovers after expiry. Identical fresh refreshes extend the deadline without
creating a new push. A failed evidence write rolls back the pending invalidation
as well as challenge consumption; invalid/replayed reports create no new event.
No observations, challenge tokens or compliance verdicts travel in notifications.

A server worker starts during control bootstrap and checks every five seconds.
It marks each expired generation once and delivers lightweight re-fetch hints
through the existing peer-update manager. All selected source changes in one
tenant share one fanout to that tenant's current peers, including the reporting
device. Tenant-wide fanout is deliberately conservative until resource guardrails
provide an affected-resource dependency graph. Other tenants are not notified.

The pending marker and notification revision survive process restarts. Publication
failures retain pending work; PostgreSQL HA publication errors propagate to the
worker so they can be retried. An acknowledgment clears only the selected
revision and row incarnation, preventing an older delivery from erasing a
concurrent failure/recovery or acknowledging a pruned-and-recreated row. Successful publication is not proof that every client received or
applied the hint. Duplicate delivery and coalescing across replicas are allowed;
clients must fetch authoritative current state, never infer a verdict from a hint.
The existing HA listener reconnect resync and client polling remain fallbacks.

Each pass selects up to 100 pending source records, ordered by last attempt so
failed/hot tenants do not permanently occupy the first batch. New observations
on an already-pending record preserve its attempt position. A pass has a
20-second work deadline. Backfill also handles up to 100 legacy records per pass,
deriving deadlines from their original server receipt, not startup time. A
concurrent new generation cannot be overwritten by the migration or expired by
an older scan. Malformed legacy evidence schedules a re-fetch and still fails
closed when read/evaluated. Complete a rolling server upgrade before relying on
the new scheduling behavior; old writers do not maintain the new queue fields.

Retention cleanup clears fingerprints/deadline metadata together with expired
raw evidence, so challenge refresh cannot preserve an observation fingerprint
past evidence retention. Identity deletion/key replacement still denies reads
and ingestion immediately; ordinary peer-removal invalidations remain independent.

These are advisory state-change signals, not traffic revocation. They do not
change the current compiled packet filter or add policy conditions. Queue depth,
tenant size and publisher availability affect delivery latency; the five-second
scan is not a revocation bound. Future resource permissions must evaluate
current evidence in their issuance transaction and enforce local expiry even
when every notification is delayed or lost.

Tests cover exact expiry, repeated scans, unchanged refreshes, recovery and
collection failure, tenant isolation/coalescing, retry/restart, failed-write
rollback, a newer change during acknowledgment, hot-tenant fairness, row recreation and legacy
backfill. A real authenticated gRPC test confirms expiry pushes an already-held
control stream without a new client report or poll. PostgreSQL CI additionally exercises expiry versus concurrent refresh
and acknowledgment versus a newer failure across independent connection pools.

## Authorization and expiry

### Implemented internal guardrail preview

`policy.ComplianceDraft` contains a tenant ID, named conjunctive requirement
sets, destination guardrails and explicitly designated remediation resources.
It is a Go-only preview input: it is absent from the policy JSON document/schema,
and the policy parser rejects attempts to activate it. There is no persistence,
management API, netmap projection or permission issuance for this model yet.

Each resource names a node selector (handle, user, group or tag), explicit IPv4
or IPv6 CIDR, or `*`; it also names TCP, UDP or either transport and an inclusive
port range. Resource ports are separate from selectors. CIDRs match the actual
packet destination. Node selectors refer to the destination node, never a
forwarding gateway; `*` includes both node and routed destinations. The preview
resolves destination handles against the supplied inventory and checks address
ownership. Routed destinations carry no destination-node handle.

`Document.PreviewCompliance` takes trusted, tenant-scoped inventory/evidence,
an authenticated subject, explicit evaluation time and decisions from the
independent identity and SSH gates. These are internal caller inputs, not
client-provided claims or an authenticated public API. It does not calculate
identity grant provenance. Every matching guardrail contributes its requirement
sets with AND; a shared set is evaluated once and all check results are retained.
The preview reports matching guardrail IDs, set results and the independent
gate decisions in deterministic order. Missing/nonpassing evidence denies
protected traffic even when identity or SSH permits it. Passing evidence cannot
override either independent denial. SSH admission applies to TCP/22 only.
Unprotected traffic still requires the corresponding identity/SSH grants.

Validation rejects empty/duplicate objects, invalid requirements, missing set
references, undefined groups, malformed CIDRs, invalid transports/ranges and
remediation intersections. Conflict detection includes port/transport overlaps,
wildcards, intersecting CIDRs, and node selectors that match the same inventory
node or intersect its owned addresses. Unresolved node selectors can describe
future inventory, so callers must supply the complete current tenant roster and
revalidate after address, ownership, tag or group changes. Gateway route prefixes
are not node-owned addresses. Each preview validates the whole draft; an invalid
draft or invalid flow returns an error with a denied result. This is conservative
draft validation, not the final persisted-policy recovery behavior.

A passing preview's `ValidUntil` is only the evidence deadline. It is zero on
denial and for unprotected traffic; it is not a renewable authorization lease.
Tests cover device-specific evidence, failure/expiry/recovery, independent gates,
overlapping guardrails, remediation conflicts, IPv4/IPv6 routed destinations,
port boundaries and invalid subjects/references. Live policy preview APIs and
the following enforcement contract remain unimplemented.

### Implemented internal gate compilation

`Document.CompileCompliance` takes the draft, a complete tenant-scoped roster of
enrolled device identities with latest trusted evidence, a target handle, current
gateway-owned route prefixes for that target, and explicit evaluation time.
It validates the draft and enrollment bindings before returning a separate
mandatory gate snapshot. Missing reports and malformed, wrong-subject or
nonpassing evidence omit that device from a gate's passing sources; they never
remove the destination guardrail. Empty/duplicate/wildcard handles, invalid or
duplicate tenant enrollments, missing/invalid owned addresses, invalid routes,
unknown targets and missing evaluation time fail compilation with no snapshot.
The compiler is an internal function, not an enrollment or route-authority API;
its caller remains responsible for authoritative reads and tenant isolation.

Ingress gates contain only protected intersections with the target's own
addresses and the routed prefixes it currently gateways. CIDR intersections
work for IPv4, IPv6 and default routes. A node selector protects that node's
own addresses, not its forwarded LAN. Wildcards protect both. A standby that
does not currently gateway a protected prefix receives no gate for that prefix.
Egress gates resolve node selectors to owned destination addresses and retain
explicit CIDRs as resource constraints, independent of currently available
routes. They contain only the target device's own source decision.

Every matching gate is mandatory, so passing one overlapping guardrail cannot
bypass another. Passing source lists always name concrete enrolled handles;
they cannot contain a source wildcard. Receiver/gateway decisions carry handles
and evidence deadlines, without raw observations, versions or failure reasons.
Guardrails, destination prefixes and source handles have deterministic ordering,
and repeated prefixes are deduplicated. The identity and SSH filters remain
separate; a passing compliance gate grants no identity or SSH permission.

`IngressSatisfied` and `EgressSatisfied` are reference evaluators of this gate
alone. They deny protected traffic for unknown/nonpassing sources and at the
exact evidence deadline. Zero snapshots, invalid flow inputs and evaluation
times before compilation fail closed. Unprotected traffic is unconstrained by
compliance, while still requiring the independent grants. Recompilation derives
deadlines from the original server receipt rather than restarting freshness.
Snapshots must be rebuilt on evidence, policy, enrollment, selector or gateway
ownership changes. Already compiled snapshots are not mutated by later reports.

These are diagnostic Go snapshots with explicit wall-clock time, not wire permits,
an atomic policy/evidence read protocol, or a packet-path implementation. They
have no enforcement capability advertisement or policy activation path. The
120-second lease bound, replay binding, suspend-aware elapsed time, revocation of
cached flows and compatibility handling below remain unimplemented. Tests compare
compiled decisions with the draft preview and cover same-user devices under
overlapping unconditional identity grants, remediation, nonpassing evidence,
expiry/recovery, overlapping guardrails, routed intersections and determinism.

### Implemented permit wire contract

`KarstCompliancePermitRequest`, `KarstCompliancePermitSnapshot`,
`KarstCompliancePermitGate` and `KarstComplianceSourcePermit` define a versioned
protobuf contract with Go/Rust agreement vectors in
`spec/vectors/device-compliance-permits-v1.json`. These messages are attached to
a real request kind (`KindCompliancePermit`, 6), advertised via the
`compliance_permit_schema` netmap capability field, and issued by `PermitHandler`
from a tenant's compiled compliance draft. A running `karstd` client installs
and enforces the result on the datapath (see "Rust permit receiver and
datapath enforcement" and "Authorization and enforcement contract" below).
Because no persisted admin policy-write API exists yet for compliance drafts,
every draft compiled in production today is empty, so every issued snapshot
still has zero
gates. Ingestion schema 1 continues to mean evidence ingestion only.

A schema-1 request carries a fresh 32-byte nonce. The response echoes it and
binds tenant, enforcing enrollment ID, canonical base64 identity handle and
policy revision. Every passing source names its own concrete handle, enrollment
ID and positive evidence generation. Handles/enrollments/generations must be
consistent across the whole snapshot. Egress sources may name only the enforcing
device. This binds the response structure; an authenticated control transaction
and authoritative enrollment/policy/evidence reads must establish its provenance.
The validator does not prove that the server used current evidence.

Snapshots have a positive validity budget of at most 120,000 milliseconds. Each
source budget must be positive and no greater than the snapshot budget. A future
issuer must additionally cap it by that source's remaining evidence freshness,
rounding down, and omit sources with no remaining budget. A future receiver must
measure budgets from its locally recorded request start using suspend-aware
elapsed time: transit, retries and sleep consume validity. Receipt, reconnect,
cached replies and unchanged netmaps must never restart a budget. A timed-out,
consumed or replaced request nonce cannot install another snapshot. The current
Go structural validator checks equality and size, not nonce freshness/consumption,
evidence freshness or elapsed-time enforcement.

Gates specify a nonempty guardrail ID, canonical IPv4/IPv6 destination CIDRs,
TCP/UDP/either transport, an inclusive 0..65535 port range and passing sources.
Zero/unknown protocols, malformed/noncanonical/mapped CIDRs, duplicate guardrails
within a direction, duplicate prefixes/sources and inconsistent source bindings
are rejected. All matching gates compose with AND. An empty passing-source list
is a valid mandatory denial; it must not cause a gate to be dropped. A present,
valid snapshot with no gates is distinct from a missing/unsupported snapshot.
It does not grant identity or SSH access.

`compliance.ValidatePermitRequest` and `ValidatePermitSnapshot` implement Go
structural and trusted-context binding checks. The latter validates the whole
candidate before installation; an error must not partially apply it or renew
old leases. Trusted context includes the current request nonce, enrollment and
policy revision from the same authenticated transaction. Semantics that require
new mandatory interpretation need a new schema version. Future capability
negotiation must reject unknown versions for protected access.

Tests cover binding substitution, validity bounds, unknown enums, invalid ports,
CIDRs and references, wildcard/duplicate sources, inconsistent evidence
generations and deny-all snapshots. `PermitHandler` (request kind 6) now issues
real snapshots from these validators, and a real Go-control/Rust-karstd
end-to-end test has measured the 120-second datapath bound at ~30.09s. Atomic
snapshot reads and capability negotiation beyond the single schema version 1
remain pending.

### Rust permit receiver and datapath enforcement

`karst-control-client::compliance` accepts the Go-produced snapshots.
`PendingPermitRequest` holds trusted tenant/enrollment/policy context, a caller's
fresh 32-byte nonce and the local request-start timestamp. Its `accept` method
consumes the pending value even on error. It validates every gate/source before
returning a `PermitSnapshot`; malformed or substituted candidates cannot be
partially installed. Request and installed types are neither cloneable nor
serializable. The caller must supply a fresh CSPRNG nonce for each request,
drop replaced/timed-out requests, and drop requests/snapshots on reconnect,
restart or a change in trusted policy/enrollment context. The helper does not
generate randomness or maintain a history of caller-supplied nonces.

Structural checks mirror the Go validator: schema, bindings, validity budgets,
canonical handles/CIDRs, protocols, port ranges, duplicate resources/sources,
consistent enrollment/generation bindings and egress ownership. Parsed private
gates contain concrete passing handles and request-relative deadlines. Transit
time consumes validity. Arriving exactly at global snapshot expiry is rejected;
a source already expired within an otherwise valid snapshot cannot satisfy its
gate. A missing snapshot has no construction path to a passing result.

`PermitSnapshot::ingress_satisfied` and `egress_satisfied` are reference
compliance-only verdicts. All matching gates apply with AND, exact source expiry
denies protected traffic, and unmatched traffic remains unconstrained only while
the global snapshot is valid. Global expiry denies all reference verdicts,
including for unmatched resources. Identity/SSH checks still apply independently;
remediation during control loss needs an explicit integration policy, not an
expired snapshot. A backwards clock sample permanently invalidates that snapshot,
and moving time forward again cannot restore it.

All timestamps are caller-supplied `Duration` values from one suspend-aware
elapsed clock with a stable origin. This module reads no wall clock or platform
clock; `std::time::Instant` does not provide portable suspend accounting. Tests
inject transit, sleep-sized elapsed jumps, rollback, exact expiry and arithmetic
overflow, and consume the Go wire vectors. `karstd::Client::sync` now issues live
requests on the existing 30-second refresh cadence and installs the result via
`Engine::set_compliance_permit`; `Engine::permit` enforces it on every protected
packet, uncached, alongside the general ACL and the independent SSH gate — proven
against a real Go control server. Capability negotiation beyond schema version 1
and cached-flow revocation of a *configured* guardrail (none exists in production
yet) remain pending. These tests, together with the end-to-end test described
under "Proposed authorization and enforcement contract" below, establish a
measured bound on real devices, not just reference behavior.

### Authorization and enforcement contract

The permit issuance, refresh and datapath-enforcement mechanics below are now
implemented and proven end to end (PR1–PR3 of #363's stage 4/6 roadmap) against
a real Go control server and a real `Engine`. What remains proposed is the
operator-facing half: a persisted admin policy-write API for compliance
guardrails, and the policy preview it would drive. Until that API exists, every
compiled draft is empty and this contract has zero effect in production.

Resource guardrails constrain destination selectors, transport/ports and routed
CIDRs after identity grant resolution. All matching requirements apply to every
source device. Source wildcards must resolve into device-specific decisions;
they cannot retain an unconditional bypass. CIDR/port intersections and selector
changes are reevaluated. Policy preview shows effective requirements and grant
provenance for each affected flow, including remediation conflicts. **(Policy
preview itself remains proposed — not yet built.)**

The wire design must carry a versioned compliance capability and resource-scoped
permits bound to tenant, device, policy revision and evidence generation.
Permits are authenticated by control and cannot be transferred between devices.
Do not rely on a peer's assertion of its own compliance: distribute the result
to the receiving endpoint or routed gateway as well as the originating client.
A client lacking the mandatory enforcement capability cannot receive protected
access; capable receivers/gateways must deny it. Activating a guardrail requires
capable receiving enforcers for every matching resource, including routed paths.

Maximum permit lifetime is **120 seconds**, capped by the evidence's remaining
lifetime. Refresh every **30 seconds**; invalidate and publish affected
decisions immediately on accepted failure, evidence expiry, policy change,
identity revocation or device removal. Target online delivery is 30 seconds;
the security bound is **120 seconds after the last permit issuance**, even if
notifications or control connectivity fail. A newly observed failure must stop
permit issuance atomically with storing its evaluation. A real Go-control/
Rust-karstd end-to-end test (#473) has measured this bound at ~30.09s across
repeated runs against the 120-second target, including recovery without
reenrollment and enforcement that survives loss of control-plane connectivity.
Multi-replica authoritative reads, capability negotiation beyond schema version
1 and the configuration surface that would make a guardrail reach production
remain untested or unbuilt.

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

1. **Done.** Typed requirement/evaluation model with deterministic time inputs,
   version comparators and tests for every nonpassing state and provenance
   mismatch.
2. **Done.** Authenticated challenge/report persistence, replica-safe replay
   protection, expiry scheduling and platform collectors; publish actual
   capability matrix.
3. **Partially done.** Resource guardrails, overlap validation and
   device-specific ingress/egress/routed compilation exist as an internal
   draft validator/compiler, independently composed with SSH. Policy preview
   and a persisted admin policy-write API to reach them remain pending.
4. **Done.** Versioned permits, compatibility handling and local packet-path
   expiry are live (`KindCompliancePermit`, `Engine::permit`); the
   established-session and offline bounds are proven (stage 6). Policy writes
   remain disabled pending stage 3's write API.
5. **Done.** Scoped console status (`GET /nodes/{handle}/compliance` and the
   Machines → Status "Compliance" dialog). No pass/fail verdict or
   remediation/audit guidance is rendered yet — there is nothing to evaluate
   until stage 3 ships configurable guardrails.
6. **Done, scoped.** Real Go-control/Rust-datapath test: two same-tenant
   devices, explicit remediation, failure/expiry/recovery, and control-loss/
   reconnect, measuring the 120-second bound at ~30.09s. Replay/spoofing,
   tenant/delegation isolation, overlapping grants and CIDRs are covered at
   the unit level in both languages rather than end to end, since CI cannot
   meaningfully simulate suspend or clock skew.
