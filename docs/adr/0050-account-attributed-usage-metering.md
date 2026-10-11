<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-0050: Account-attributed device and managed relay usage metering

- **Status:** Accepted (merged in #276 on 2026-10-09)
- **Date:** 2026-10-09
- **Deciders:** adriananderson (merged #276)
- **Related:** #275 (active design and implementation tracker), #232,
  ADR-0049 (scope), ADR-0033 (account/aquifer mapping), ADR-0035 (audit),
  ADR-0021 and ADR-0047 (operational telemetry), ADR-0038 (relay fairness),
  ADR-0007 (licensing)

---

## Context

#275 records the product inputs: support managed hosting and self-hosted
installations with optional paid support; charge managed hosting by enrolled,
non-revoked devices using graduated tiers and time proration; charge managed
relay traffic separately, pooled by organization. Offline devices remain
eligible. Direct traffic and internal relay hops incur no relay charge.
Usage alerts are the default product behavior, with optional customer-selected
relay spending caps and explicit acknowledgment of possible interruption.

The control plane owns plans, totals, and spending policy; relays apply local
limits; a payment provider must not become a live networking dependency.
ADR-0049 requires metering to ship independently of enforcement and preserves
existing behavior when plans are not configured.

The current code does not provide a billing ledger:

- `server/management/internals/karst/roster/roster.go` joins node identities
  to account-owned peers and derives aquifers from account IDs and an optional
  prefix. Aquifer strings are routing identities, not a new billing account.
- `server/management/internals/karst/api/nodes.go` removes peers and node
  identities on revocation. A snapshot of remaining devices cannot reconstruct
  historical enrollment intervals.
- `bins/karst-relay/src/hub.rs` applies ADR-0038 capacity accounting before
  delivery, including mesh forwarding. That counter is not destination egress
  and must not be reused as billable traffic.
- `bins/karst-relay/src/server.rs::flush` writes queued encoded frames to
  client or mesh streams. Queueing a frame does not establish a successful
  write, and a successful write does not prove endpoint receipt.
- ADR-0021 reports advisory relay-wide totals with timestamp freshness checks.
  It cannot attribute tenants or reliably replay an accounting backlog.

## Decision

Use a separate, opt-in usage ledger in the existing control-plane database,
with durable device lifecycle records and authenticated, replayable managed
relay reports. The first release exposes usage and completeness only. It does
not calculate invoices, configure rates, collect money, send billing alerts,
apply spending caps, or reject traffic because metering is unavailable.
Acceptance selects the accounting semantics below. Rates, billing periods,
payment integration, and enforcement remain separate decisions under #275.

### 1. Account identity and rollout

The existing account ID is the organization billing boundary. Record a stable
deployment identifier alongside source identities to prevent collisions when
relays serve multiple deployments. Maintain explicit, historically versioned
mappings from admitted aquifers to accounts; do not infer an account by parsing
an arbitrary prefix or trust an account ID supplied without authorization.
Roster publication must retain the mapping needed to resolve delayed reports.
Unmapped or ambiguous usage is quarantined and makes coverage incomplete; it
must never be silently assigned to another account.

Collection is explicitly enabled by the operator and has a recorded start
boundary. At activation, snapshot existing eligible devices consistently with
concurrent lifecycle mutations. Their intervals begin at activation, not at an
invented historical enrollment time. No retroactive charges are inferred from
current snapshots. Disabling collection closes coverage, not device enrollment;
re-enabling starts another coverage interval and reconciles current state.
Unconfigured deployments need no relay spool or billing configuration.

### 2. Durable device lifecycle

Persist an immutable enrollment-generation identifier, account ID, effective
UTC timestamp, and event kind for enrollment and revocation/deletion. The
lifecycle event and authoritative membership mutation must commit atomically
(or through an outbox in that same transaction); an HTTP-handler audit call
after a mutation is insufficient. Inventory all mutation paths, including
administrator/self-service deletion and account deletion, before enabling this
meter. If the current stores cannot provide that boundary, resolving it is a
prerequisite, not a best-effort fallback.

Eligibility is the half-open interval `[enrolled_at, revoked_at)`, intersected
with collection coverage and the requested reporting window. An offline state,
key rotation, reconnect, or idempotent enrollment retry does not open another
interval. A genuine re-enrollment after revocation opens a new generation;
replacement devices overlap if both remain enrolled. Account moves, if supported,
close the old account interval and open a new one at the same effective time.
Use transactional ordering and reject negative intervals despite clock changes.

Retain lifecycle boundaries after live rows disappear. Reconcile the ledger
against authoritative membership, recording discrepancies and explicit
corrections without rewriting original events. Never fabricate a precise
missing boundary from a later snapshot. Return eligible device-time and the
count-change timeline, not only average device count: graduated pricing is
nonlinear, so an average alone cannot reproduce a future pricing decision.
Tier rates, billing periods, integration rules, and money rounding remain #275
inputs; this ADR does not settle them.

### 3. Relay byte boundary

Propose counting the opaque payload length of each `RecvPacket` whose complete
encoded frame is successfully written to a destination client stream on a
managed relay. Capture attribution and payload length as internal queue
metadata, then account at successful write completion, without re-reading a
possibly changed roster. Both local-client delivery and mesh-originated delivery
use this same boundary. A `Forward` written to a mesh peer is never charged.
Each traffic direction contributes its destination egress to the account total.

Exclude Ponor framing, TLS/QUIC/IP overhead, transport-level retransmissions,
control frames, queue drops, rejected destinations, and partial/failed frame
writes. The opaque payload includes whatever encrypted protocol content it
carries; the relay does not inspect it. A newly submitted duplicate payload is
another forwarding operation and counts again; no plaintext inspection or
cross-relay packet deduplication is introduced. Successful writes measure
transport acceptance, not proven delivery. Document that distinction in usage
reports and later customer billing terms.

Only explicitly authorized managed relay sources contribute to this meter.
Self-hosted/third-party relays and TURN traffic are not implicitly included;
any additional managed transport needs an equivalent reviewed counting boundary
before it can produce this usage unit.

### 4. Durable reports, retries, and uncertainty

Aggregate by deployment, account mapping version, relay identity, producer epoch,
and bounded UTC time bucket, without source/destination device pairs. Seal
immutable batches in a local persistent spool before transmission. Identify
batches by `(deployment, relay, epoch, sequence)` and include a content digest,
meter version, bucket boundaries, counters, mapping references, and coverage
state. A fresh epoch distinguishes counter resets and new spool histories;
restarts replay previously sealed batches unchanged.

The control plane acknowledges only after durable insertion. Insert each batch
and update derived totals transactionally with a uniqueness constraint on its
identity. Same identity and same content is an idempotent retry; same identity
with different content is rejected and investigated. Out-of-order batches may
be stored, but sequence gaps remain visible. Spool entries can be removed only
after acknowledgment. Reconciliation uses retained batch identities and totals,
not a second additive import of the same bytes.

There is no atomic transaction between a network write and a disk write.
A crash after delivery but before persistence can lose usage; a pre-write charge
would instead risk charging failed delivery. Prefer the former and explicitly
report incomplete coverage following unclean shutdown or spool loss. Require
periodic coverage heartbeats even for zero traffic, an inventory of expected
managed producers, and clean epoch termination records. Missing producers,
clock anomalies, late batches, disk exhaustion, or unresolved mappings must not
look like zero usage. Spool bounds, flush cadence, bucket duration, and clock
skew tolerance must be specified and failure-tested in the implementation.

Metering failures do not block forwarding. This means the first slice cannot
promise lossless accounting or a hard spending limit. Report durable observed
usage separately from coverage uncertainty; never estimate missing bytes into
customer totals. Late data may revise provisional reports. Billing-period
finalization and treatment of unresolved gaps require a later pricing decision.

### 5. Authentication and access

Use the existing relay signing identity with a separate versioned accounting
signature context and canonical encoding, independent of advisory telemetry.
Bind the deployment, batch identity, attribution, time bounds, and counters into
the signed message. Authenticate uploads against operator-controlled managed
relay authorization and allowed mapping scope. A tenant registering a relay
must not gain permission to submit managed billing usage. Authenticate fresh
upload envelopes independently from historical batch timestamps so legitimate
backlog replay does not weaken transport replay checks.

Validate integer bounds, batch sizes, bucket durations, mapping scope, and epoch
transitions before aggregation. Revoke compromised producer credentials and
quarantine affected data for reconciliation. Signatures prove provenance, not
truthful measurement by a compromised relay; this remains a billing-integrity
risk requiring operational review, not a claim of cryptographic proof of bytes.

Customer reads derive account scope from authenticated authorization and expose
only that account's aggregate usage, coverage start, freshness, gaps, and
provisional status. Operator cross-account access follows ADR-0037 and is
audited. No packet content, destinations, device-pair traffic histories, or
public per-account Prometheus labels are introduced. Device generation IDs are
internal lifecycle evidence, not per-device traffic statistics. This adds
account-level volume history beyond ADR-0021's relay-only telemetry; retention
and access therefore require explicit review before managed rollout.

### Alternatives rejected

- **Invoice from operational telemetry or fairness counters.** Wrong attribution,
  forwarding boundary, reset handling, and delivery guarantees.
- **Poll current devices or online sessions.** Loses deleted-device history and
  contradicts the agreed billing treatment of offline devices.
- **Store only device-hours.** Insufficient to evaluate nonlinear graduated rates
  as eligible device counts change.
- **Synchronously contact the control plane for each forwarded packet.** Makes
  networking depend on accounting availability and adds per-packet latency.
- **Claim exactly-once network accounting from batch deduplication.** Deduplication
  prevents replayed reports from inflating totals; it cannot close the local
  network-write/durable-record crash window.
- **Implement caps with ADR-0038 alone.** Local fairness limits do not coordinate
  an organization-wide monetary allowance across relays.

## Delivery and acceptance

#275 remains open after this ADR merges. Implement in reviewable slices:

1. Lifecycle schema, transactional mutation hooks, activation snapshot, and
   reconciliation; prove retry, revoke, re-enroll, concurrent activation, account
   deletion, and offline-device behavior.
2. Relay queue attribution and successful-write metering for TCP and QUIC;
   prove local and cross-relay bidirectional accounting, handover, mesh-hop
   exclusion, queue rejection, partial writes, and transport retry behavior.
3. Persistent spool and authenticated ingestion with shared Rust/Go signing
   vectors; prove duplicate/conflicting batches, reordered and late arrivals,
   restarts, disk failures, epoch changes, missing heartbeats, overflow rejection,
   revoked sources, and cross-account spoofing protection.
4. Authorized aggregate reporting and reconciliation tools; prove tenant
   isolation, visible gaps, reproducible interval totals, and unchanged behavior
   when collection is disabled. Document deployment and rollback procedures.

Before managed rollout, specify retention/deletion and backup recovery policy,
resource bounds, coverage alerting, and the threat-model additions for producer
trust and account-volume history. Before charging, settle #275's rates, periods,
proration arithmetic, rounding, finalization, and unresolved-data policy.
Alerts, global spending caps, payment integration, and customer support terms
remain separate work under #275 with their own mechanism decisions as needed.

---

## Consequences

### Positive

Usage can be inspected and reconciled before money or enforcement depends on it.
Durable lifecycle records support offline-device billing without retaining
traffic histories. Replay-safe ingestion permits outages without duplicate
charges, and explicit coverage prevents missing reports from masquerading as
zero usage.

### Negative

Relays need disk-backed accounting state, queue metadata, and producer lifecycle
management. The control plane gains historical data, transaction requirements,
and reconciliation operations. Nonblocking forwarding permits unrecoverable
usage gaps. Account-volume history increases metadata sensitivity. Once usage
is used for invoices, changing the meter boundary requires versioning and
customer-facing migration; it is no longer a cheap internal refactor.

### Reconsider if

- Required loss bounds cannot be met without blocking the datapath.
- Managed transport expands beyond Ponor or account/aquifer ownership changes.
- A hard global spending guarantee requires reserving budgets before forwarding.
- Retention or privacy requirements cannot support the proposed evidence trail.
