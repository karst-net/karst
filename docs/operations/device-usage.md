<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Operating optional device usage collection

Device collection defaults off. Enabling it measures persisted account-owned
peer membership, including offline peers. It does not set prices, invoice a
customer, or enforce a traffic limit. Review service-generated peer eligibility
before using these measurements for managed billing.

The `karst-control admin usage devices` commands use the existing server
configuration and database credentials. Run them only from a trusted operator
environment. `--actor` is an audit label supplied by that operator, not a login
or proof of identity. Restrict operating-system and database access accordingly.
The customer HTTP API cannot change collection configuration.

## Activation

Upgrade every control-plane replica and membership writer to code containing the
collection hooks. Start the updated control plane once to install the schema.
Do not enable collection while older writers remain. SQLite and PostgreSQL have
integration coverage; MySQL requires backend validation before activation.

Substitute your existing configuration path and account ID:

```sh
karst-control --config /path/to/config.json admin usage devices status --account-id ACCOUNT
karst-control --config /path/to/config.json admin usage devices enable --account-id ACCOUNT --actor OPERATOR --all-writers-instrumented
```

The acknowledgment flag asserts that every writer is instrumented; the command
cannot discover other replicas. Configuration is stored in the database and
survives process restarts. Enabling snapshots current membership, with coverage
starting now. It does not backfill earlier usage. Repeated enable calls retain
the current coverage period. JSON output includes `enabled`, `account_id`, and,
when present, the last coverage period and configuration timestamp.

## Disable and downgrade

```sh
karst-control --config /path/to/config.json admin usage devices disable --account-id ACCOUNT --actor OPERATOR
```

Disable every collecting account before downgrading to an uninstrumented
release. Retain the ledger tables in database backups. Disabling closes coverage
without removing peers or interrupting their traffic. Re-enabling starts a new
snapshot and leaves the disabled interval uncollected. An uncollected interval
is unknown usage, not zero usage.

## Reconciliation

Normal membership writes and ledger writes share one transaction. A mismatch
between current membership and recorded membership rejects the write. Investigate
uninstrumented writers or unsupported direct database changes before reconciling:

```sh
karst-control --config /path/to/config.json admin usage devices reconcile --account-id ACCOUNT --actor OPERATOR
```

Reconciliation preserves original evidence, marks affected coverage incomplete,
and starts a new period from current membership. It cannot determine when missed
changes happened or detect changes that were entirely undone between snapshots.
Do not use raw SQL imports or account reassignment while collection is enabled.

Configuration changes and `karst.usage.collection.enable`, `.disable`, or
`.reconcile` audit records commit together. Audit failures roll the change back.
Retry a database serialization/deadlock failure by rerunning the whole command.
Successful repeated configuration commands remain audited. The status command
does not mutate configuration. Ledger failures can reject membership changes;
they do not disconnect established network traffic.

Account owners/admins can read coverage-aware device reports using
`GET /api/karst/v1/usage/devices?start=<RFC3339>&end=<RFC3339>`.
Only complete intervals contribute to the exact device-microsecond total.
Reports are metering evidence, not finalized invoices; reconciliation can change
historical coverage. Collection periods are not financial billing periods.
Price calculation and invoice finalization are implemented for explicitly
assigned UTC billing periods with complete device and relay reports; see the
[managed billing pilot guide](managed-billing-pilot.md). Raw lifecycle events
are retained until their invoice is finalized and for thirteen months after
that UTC billing period ends. The billing retention worker verifies the
immutable invoice snapshot before it asks the usage ledger to checkpoint and
prune that month. Periods without a finalized invoice are not pruned. Before
deletion, the checkpoint records the boundary device count, event sequence, and
a chained SHA-256 digest over canonical source-ledger rows; the checkpoint and
event deletion commit atomically. Finalized invoice evidence and payment/audit
state remain seven years, while normalized webhook events remain thirteen
months. Raw webhook bodies are not persisted after signature verification.
