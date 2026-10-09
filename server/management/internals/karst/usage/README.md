<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Device lifecycle ledger foundation

Implements the transaction-bound ledger portion of proposed ADR-0050 for
[#275](https://github.com/karst-net/karst/issues/275). This package is intentionally
not imported by bootstrap or any production mutation handler. No collection is
enabled, no public reporting endpoint is provided, and the implementation tracker
must remain open.

`Migrate` creates two additive tables. `Append` requires an existing GORM SQL
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
initial query reads account history; production reporting needs bounded windows
and a verified checkpoint strategy before history becomes large.

## Integration work required before enabling collection

The repository's membership mutations need semantic hooks inside their existing
transactions; neither HTTP hooks nor generic SQL create/delete callbacks suffice.
The inventory below is a starting point for that integration, not a claim that
all mutation paths are covered by this package.

| Path | Required accounting treatment |
| --- | --- |
| `server/peer.go`: `AddPeer` → `store.AddPeerToAccount` | Append enrollment in the existing membership transaction, once per generation. |
| `karst/control/login.go`: `LoginPeer` followed by `Nodes.Register` | The identity write is after the peer commit and may fail independently. Decide activation readiness explicitly; never append an enrollment on each key registration or retry. |
| `server/peer.go`: administrative and own-peer deletion → `deletePeers` | Append revocation in the same transaction as peer removal. |
| `internals/modules/peers/manager.go`: bulk `DeletePeers` | Same guarantee for each removed generation, including automated callers. |
| `store/sql_store.go`: `DeleteAccount` | Close every active generation atomically while retaining ledger evidence. |
| `store/sql_store.go`: `SaveAccount` | This deletes and recreates associations; storage churn is not a semantic revoke/re-enroll. Compare authoritative before/after membership or avoid this path for metered membership. |

Paths above are relative to `server/management/`, except `karst/`, which is
relative to `server/management/internals/`.

The next integration slice must also implement:

- An explicit collection switch and durable coverage intervals, default off.
- An activation snapshot serialized with concurrent membership mutations; existing
  devices start at activation, without backdating from current rows.
- Disable/re-enable handling, reconciliation, and explicit discrepancy records.
- Stable generation and retry-key derivation at every mutation entry point.
- A decision for the peer-commit/identity-write gap noted above, including repair.
- Coverage for account deletion, replacements, ephemeral cleanup, imports, and any
  supported account reassignment; absence of online activity never closes an
  enrollment interval.
- Account-authorized reports that intersect ledger intervals with coverage and
  expose incompleteness, rather than exposing `Timeline` directly.
- Transaction/concurrency tests on supported managed database engines. Current
  executable tests use SQLite; PostgreSQL/MySQL behavior is not yet validated.

## Validation

From `server/`, run `go test -race ./management/internals/karst/usage`.
Tests cover half-open windows, overlapping enrollment, offline eligibility,
re-enrollment, duplicate/conflicting retries, timestamp regression, account
isolation, durable reopen, concurrent appends, and rollback with a membership
fixture in the same SQL transaction. They do not claim production membership
integration or pricing arithmetic coverage.
