<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Managed billing pilot readiness

This page is an operator entry point for collecting shadow usage and preparing
for a managed billing pilot. Metering and reporting exist, but collection is
opt-in and billing is not yet live: a usage report does not finalize an invoice,
charge customers, or enforce relay limits. Do not describe a usage report or
assigned schedule as a bill.

For approved customer-facing terms and current availability limits, see the
[managed billing customer guide](managed-billing-customer-guide.md).
For rollout, backup, and rollback guidance, see the
[billing upgrade and migration guide](billing-upgrade-migration.md).

## Approved pilot rates and meter boundaries

The approved pilot model uses graduated monthly device rates: $2.50 per device
for devices 1–10, $1.50 for devices 11–50, and $0.75 for each device above 50.
Enrolled, non-revoked devices count whether online or offline. Managed relay
traffic is pooled by organization and billed separately: the first 10 decimal
GB per organization-month are included, then usage is $0.20 per decimal GB.
Relay metering counts customer payload bytes after a complete successful write
to the destination transport; it excludes framing overhead, failed writes,
queue drops, direct peer traffic, and internal relay-to-relay hops.

Billing uses UTC calendar months and exact eligible-time device proration.
Incomplete usage stays open and unbilled; final invoice lines truncate down to
currency minor units, including USD cents. Relay alerts are persisted at 75%,
90%, and 100% of allowance or cap, with a coverage warning when data is
incomplete; customers read them through the audited in-app feed. Invoice
finalization requires complete device and relay reports. The approved relay
measurement boundary is not a guarantee that every byte was received by the
destination endpoint. See
the [device collection guide](device-usage.md) and [relay usage guide](relay-usage.md)
for full coverage and failure semantics.

## Prepare a shadow-usage window

Before enabling collection, choose a representative pilot account and confirm
that its operator and billing contacts understand this is measurement only.
Back up the management database and upgrade every management replica and
membership writer. Do not enable device collection while an older or
uninstrumented writer can still change membership; the device ledger cannot
reconstruct earlier usage. Relay attribution also depends on the management
deployment/account mapping published to the relay.

Enable device collection explicitly with the audited operator command described
in the [device collection guide](device-usage.md). Configure relay collection
with an explicit `usage.spool_dir`; configure `usage.upload_url` only when
control-plane delivery is intended. Authorize each producer and mapping in
management before expecting batches to be accepted. Missing, late, or
incomplete intervals remain unknown usage and must not be replaced with an
estimate.

Observe 30–90 days of reports before proposing a billing launch. Keep customer
billable relay payload bytes separate from cloud-provider egress measurements:
the meters have different boundaries, and the egress cost varies by provider,
region, route, and account-level allowance. Record coverage and freshness next
to every comparison. The cost scenarios and public list-price references in
[#275](https://github.com/karst-net/karst/issues/275) are sensitivity cases,
not a margin forecast or evidence of representative customer demand.

### Record comparable shadow usage

Use one record per account alias, deployment alias, and UTC calendar month.
Keep the source reports and provider exports in the deployment's restricted
operations store; use aliases here rather than customer names or provider
credentials. Capture the report `as_of` values and the provider export's own
period and generation time so late data is visible.

For devices, record `complete`, `device_microseconds`, and the durations of
`complete`, `incomplete`, and `uncollected` segments. For relay usage, record
`coverage`, `history_complete`, `complete`, `reported_bytes`,
`expected_windows`, `missing_windows`, `unexpected_windows`, the sum of daily
`gap_windows`, and `last_received_at`. Keep each coverage state beside its
value; incomplete or absent data is unknown, not zero. These names match the
account-scoped usage APIs. A report is still metering evidence, not an invoice.

For cloud egress, record provider, project/account alias, region, service,
egress class or route, measured bytes, billed amount and currency, any free
allowance or credits, and the exact export or billing-line reference. Note
whether the source isolates the managed relay process and traffic direction.
If the provider only exposes deployment-wide egress, label its cost
unallocated; do not split it across accounts or infer it from Karst payload
bytes. Leave unavailable values explicitly unavailable; do not encode missing
exports or unallocatable cost as zero. Compare matching UTC periods and state
the scope of each measure. Karst
counts customer payload bytes after a complete successful destination write;
provider egress can also include framing, retries, control traffic, and other
services. Those differences are expected and must remain explicit.

A copyable CSV header for a restricted worksheet is:

```text
account_alias,deployment_alias,period_start_utc,period_end_utc,collected_at_utc,device_as_of_utc,device_complete,device_microseconds,device_complete_duration_us,device_incomplete_duration_us,device_uncollected_duration_us,relay_as_of_utc,relay_coverage,relay_history_complete,relay_complete,relay_reported_bytes,relay_expected_windows,relay_missing_windows,relay_unexpected_windows,relay_gap_windows,relay_last_received_at_utc,provider,provider_project_alias,provider_region,provider_service,provider_egress_class,provider_period_start_utc,provider_period_end_utc,provider_generated_at_utc,provider_egress_bytes,provider_billed_amount,provider_currency,provider_allowance_or_credits,provider_export_reference,provider_scope_notes
```

Do not use provider egress as billable relay usage or use shadow records to
finalize an invoice. Do not turn on a spending cap solely to collect shadow
data. Validate grant exhaustion, surrender, restart, and recovery separately
on an explicitly designated non-production deployment. Report observed ranges
and sample coverage; do not present a small or incomplete pilot as a forecast
for the wider customer base.

## Billing and enforcement gates

Only assign a rate schedule explicitly for an account and exact period using
the [pilot assignment procedure](billing-schedule-assignment.md). An account
with no assignment remains unconfigured. The assignment makes the immutable
rate snapshot available to the calculator; it does not finalize usage or
authorize a charge.

Invoice input finalization requires complete device and relay reports and an
explicit account-period schedule assignment; it does not collect payment. The
operator can finalize only once the period is complete using the
[assignment and finalization procedure](billing-schedule-assignment.md).

The implementation provides an audited in-app alert feed and an optional
organization-wide managed-relay cap, with grants reserved across relays and
forwarding paused when a capped relay has no credits. Owners/admins configure
the cap for an assigned UTC month through `PUT /karst/v1/billing/relay-cap`;
they must acknowledge that capped relay traffic can stall at the limit. An
unset cap leaves that month uncapped. Current-period decreases take effect
only after every outstanding grant is safely returned and consumed bytes fit
under the new cap. Clean shutdown returns unused credits through a signed,
idempotent request after detaching the forwarding gate. An unclean shutdown,
unreachable relay, or failed request leaves that grant reserved through period
end. Relay grant balances are currently in memory; after restart, a fresh
generation obtains new credits and never reuses the previous generation's
grant. The cap still bounds spend, but stranded credits can reduce availability
after an unclean restart.
Review usage coverage alongside alerts because incomplete reports are lower
bounds. Keep enforcement opt-in until this implementation has shipped and its
behavior has been validated in a pilot, including reservation sizing against
shadow usage.

The pilot uses Paddle as merchant of record, with pre-tax USD rates and
applicable tax shown separately at checkout. The approved payment-failure
policy retries on days 1, 3, 7, and 12, provides in-app notices to billing
admins, and keeps service active after day 14 while an invoice is past due.
Paddle business/domain onboarding and SaaS tax-category approval remain gates
before live collection. Self-hosted support terms remain open in
[#275](https://github.com/karst-net/karst/issues/275). The current payment
integration provides opt-in checkout and durable in-app failure notices;
automated retries remain unimplemented while their execution model is pending
in #275. No billing configuration is required for deployments that do not opt
in; relay forwarding and device membership behavior remain available without
usage collection.

Paddle API collection is disabled unless `KARST_PADDLE_ENABLED=true` and a
server-side `KARST_PADDLE_API_KEY` is supplied through the deployment's secret
store. Enabled collection defaults to Paddle sandbox. Production API access
requires both `KARST_PADDLE_SANDBOX=false` and the separate operator approval
`KARST_PADDLE_LIVE_APPROVED=true`; keep live mode off until Paddle onboarding,
launch markets, and tax configuration are approved. Configure an account's
Paddle customer and approved product IDs explicitly with the audited
`admin billing configure-paddle` command only after the account has opted in.
The global credentials alone do not enroll or charge any account. The command
does not itself create a payment; a finalized invoice must separately enter
the payment outbox.

To stop device collection, disable it using the audited command before
downgrading to a release without collection hooks. Coordinate ledger and spool
retention with the deployment's existing data-governance rules. Retain
finalized invoices and payment/audit state for seven years and normalized
webhook events for thirteen months; never persist raw webhook bodies after
signature verification.
