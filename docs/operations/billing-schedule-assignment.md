<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Assigning a pilot billing schedule

Rate schedules are not assigned automatically. An account with no explicit
schedule assignment has no billing effect. The pilot assignment command records
which immutable schedule applies to one account over one exact period; it does
not create an invoice, collect payment, or enforce a usage limit.

Run the command from a trusted operator environment with the management
configuration and database credentials. Restrict access to both. The `--actor`
value is an audit label supplied by the operator, not authentication or proof of
identity.

```sh
karst-control --config /path/to/config.json admin billing assign-pilot \
  --account-id ACCOUNT_ID \
  --actor OPERATOR \
  --period-start 2026-10-01T00:00:00Z \
  --period-end 2026-11-01T00:00:00Z
```

Both period endpoints are required RFC3339 timestamps. The start must precede
the end, and both timestamps must have microsecond-or-coarser precision. The
command assigns the approved pilot rate snapshot for exactly that interval; it
does not infer calendar months, prorate usage, choose a period, or backfill
historical usage. Confirm the account ID and period before running it. Existing
overlapping assignments are rejected. Repeating an identical assignment is
accepted and writes another audit event.

On success, the command prints JSON containing the account ID, exact period
boundaries, and schedule version. Schedule persistence, assignment, and the
`karst.billing.schedule.assign` audit record are committed together; an audit
failure rolls the operation back. The command requires a SQL-backed management
store. Its schema migration is additive and does not assign schedules to other
accounts.

The assignment only makes the immutable rate snapshot available to the
calculator for that account and exact period. It is not proof that usage
coverage is complete or chargeable. After both device and managed-relay reports
are complete for the UTC month, an operator can finalize the immutable invoice
inputs:

```sh
karst-control --config /path/to/config.json admin billing finalize-invoice \
  --account-id ACCOUNT_ID \
  --actor OPERATOR \
  --period-start 2026-10-01T00:00:00Z \
  --period-end 2026-11-01T00:00:00Z
```

Finalization refuses incomplete reports, requires the existing explicit
assignment, truncates each line down to minor units, and commits the immutable
invoice snapshot with its audit record. An incomplete period remains open for
later reporting; it is never estimated. The command does not create a Paddle
transaction or collect payment. Its JSON output is the invoice-input snapshot,
not proof that a customer was charged. See [#275](https://github.com/karst-net/karst/issues/275)
for the broader payment and launch gates.
