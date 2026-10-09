<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Device lifecycle ledger and collection coverage

Implements device lifecycle accounting under ADR-0050 for
[#275](https://github.com/karst-net/karst/issues/275). Bootstrap installs hooks in
the SQL membership store. Collection defaults off, and this slice exposes only
internal Go configuration/reconciliation methods. Account owners and admins can
read coverage-aware reports; no public configuration endpoint is provided.
The implementation tracker remains open for activation, relay metering, pricing,
alerts, spending caps, and payments.

`Migrate` creates additive ledger, collection, coverage, and discrepancy tables.
`Append` requires an existing GORM SQL
transaction and a stable account-scoped event ID. The membership operation and
append must use that same transaction, and the caller must propagate errors.
Repeating identical content is safe; changing an existing event's content or
reusing a revoked enrollment generation fails. A per-account stream serializes
writers and rejects regressing effective timestamps. Retry database serialization
or deadlock errors by retrying the entire membership transaction.

The immutable event table records enrollment and revocation boundaries, at UTC
microsecond precision. Re-enrollment uses a fresh generation. Reconnect and key
rotation are not events. Ledger rows have no cascading relationship to live
account or peer records. Retention/deletion policy remains a rollout decision.

`Timeline` returns half-open constant-count intervals from recorded events. It
preserves the changes needed for a later graduated-pricing calculation and does
not multiply nanosecond durations into a potentially overflowing integer total.
It is an internal evidence query with no authorization or collection-coverage
claim. An empty timeline's zero count is not proof of zero billable usage. The
internal query reads account history and is not exposed by the API. The public
reporter uses the bounded queries described below; a checkpoint strategy remains
necessary before retained history becomes large.

## Authorized usage reports

`GET /api/karst/v1/usage/devices?start=<RFC3339>&end=<RFC3339>` returns an
account-scoped report to owners/admins. It derives account scope from the existing
authenticated context, checks control-plane read permission and role, audits each
read, and returns `Cache-Control: no-store`. Operator-granted cross-account
access follows the outer API authorization and is audited under the selected
account. No request field can select an arbitrary account inside this handler.
The legacy `billing_admin` enum has no implemented role grant and is not enabled
by this endpoint.

The requested interval is half-open, in the past, and no longer than 93 days;
timestamps have microsecond precision. At most 10,000 changes/coverage periods
are fetched per query and at most 10,000 report segments returned. Dense windows
are rejected with a request to narrow the interval, never silently truncated.
Historical opening counts are aggregated in SQL using an account/time index.
Coverage and events share a repeatable-read snapshot, with a ten-second API
deadline. Large retained histories still need a verified checkpoint strategy.

Each segment is `complete`, `incomplete`, or `uncollected`. Only complete segments
carry a device count; others carry `null`, including a never-enabled account.
`device_microseconds` is an exact decimal string summed over complete segments
only, avoiding floating-point rounding and integer overflow for large fleets.
A zero total with `complete: false` does not prove zero usage. No amount, rate,
invoice, or payment state is inferred. Existing reports can change if later
reconciliation marks their coverage incomplete; this is not invoice finalization.

## Membership integration

The SQL store wraps semantic membership mutations in `Collector.Track` inside
their existing transaction (or a new transaction for standalone peer writes).
Before/after snapshots use the persisted account-owned peer ID as enrollment
identity; account, peer, coverage, and lifecycle writes commit or roll back
together. Collector hooks propagate through `SqlStore.withTx`.

| Path | Accounting treatment |
| --- | --- |
| `server/peer.go`: `AddPeer` → `store.AddPeerToAccount` | Enrollment is observed at membership commit, once per generation. |
| `karst/control/login.go`: `LoginPeer` followed by `Nodes.Register` | Membership is already committed if identity registration fails; repairing that identity does not add another enrollment. This slice measures membership, not successful connection or key-registration time. |
| `server/peer.go`: administrative and own-peer deletion → `deletePeers` | Revocation commits atomically with peer removal. |
| `internals/modules/peers/manager.go`: bulk `DeletePeers` | Each `store.DeletePeer` call carries the same guarantee, including automated callers. |
| `store/sql_store.go`: `DeleteAccount` | Closes active generations and collection coverage while retaining ledger evidence. |
| `store/sql_store.go`: `SaveAccount` | Compares authoritative before/after peer IDs, so deleting and recreating unchanged associations produces no lifecycle events. |

Paths above are relative to `server/management/`, except `karst/`, which is
relative to `server/management/internals/`.

`SavePeer`, status updates, reconnects, approval changes, and key changes retain
the same enrollment ID. A new enrollment requires a fresh peer ID. Direct SQL
imports or account reassignment that bypass these semantic methods are not
supported during collection. No provider, plan, or enforcement depends on it.

## Coverage and recovery

The internal `SqlStore.SetDeviceUsageCollection` method enables/disables one
account. Its caller must authorize the operation; it is not a public endpoint.
Activation and membership changes lock the same per-account collection row.
The activation snapshot starts eligible intervals at observation time, never at
an inferred historical date. Repeated enable/disable calls are idempotent.

Disabling closes coverage without revoking devices. While disabled, membership
changes do not create usage events. Re-enabling compares current membership with
the last observed state at the new boundary; the disabled gap remains uncovered.
An open coverage interval must be capped at the report snapshot, not extrapolated
into the future. Do not expose `Timeline` alone as a billing report.

A mismatch between the ledger and authoritative pre-mutation membership aborts
that transaction. `SqlStore.ReconcileDeviceUsage` explicitly records the mismatch,
marks the affected coverage period incomplete, and starts a new period with
current membership. It retains the original events and never fabricates the
precise time of a missed change. A change made and undone entirely through
uninstrumented writers cannot be detected by snapshots.

Clock regression aborts the transaction instead of introducing negative time.
Ledger write failures roll membership changes back; they do not disconnect live
traffic. Database deadlocks/serialization failures require retrying the whole
business transaction, not only the accounting append.

## Rollout prerequisites

- All writers/replicas must run the instrumented SQL store before collection is
  enabled. Mixed-version writers cannot establish complete coverage.
- Add an authorized operator configuration surface and audit configuration
  changes before offering runtime activation. No environment variable enables
  collection in this slice.
- Review the membership-based eligibility boundary for any service-generated
  peers before managed billing launch; this primitive counts persisted peer IDs.
- Support account reassignment explicitly if it is exposed; do not move metered
  peers through raw SQL or cross-account imports.
- Define retention policy and a verified checkpoint strategy for large histories.
- Validate MySQL behavior before enabling collection on that backend.
- Before downgrading to code without hooks, disable every collecting account and
  retain the ledger tables. Upgrading again requires new activation snapshots;
  no historical coverage should span an uninstrumented deployment.

## Validation

From `server/`, run `go test -race ./management/internals/karst/usage`.
Tests cover lifecycle boundaries, retries, rollback, collection activation,
disabled gaps, and explicit reconciliation. The real SQL integration suite is
`go test -race -run TestDeviceUsage ./management/server/store`. It covers
account association replacement, enrollment/deletion, outer transaction failure,
ledger write failure, reactivation, and reconciliation. Set
`KARST_TEST_POSTGRES_DSN` to also test activation racing with enrollment and
nested rollback on PostgreSQL; CI provides that service. Each PostgreSQL test
uses an isolated temporary schema. These tests do not cover pricing arithmetic.
Report tests additionally cover gaps, zero versus unknown, large exact totals,
dense-window rejection, half-open boundaries, and concurrent collection changes
between database reads. API tests cover roles, authenticated account scoping,
audit failure, malformed windows, and coexistence with the broader Karst router.
