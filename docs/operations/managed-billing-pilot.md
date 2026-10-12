<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Managed billing pilot readiness

This page is an operator entry point for collecting shadow usage and preparing
for a managed billing pilot. The metering and reporting paths exist, but usage
collection is opt-in and billing is not yet live: collection does not create
invoices, charge customers, or enforce relay limits. Do not describe a usage
report or assigned schedule as a bill.

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
currency minor units. Relay alerts are set for 75%, 90%, and 100% of allowance
or cap once per threshold and period to billing administrators, with a coverage
warning when data is incomplete. The alert delivery channel remains to be
selected. The approved relay measurement boundary is not a guarantee that every
byte was received by the destination endpoint. See
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

## Billing and enforcement gates

Only assign a rate schedule explicitly for an account and exact period using
the [pilot assignment procedure](billing-schedule-assignment.md). An account
with no assignment remains unconfigured. The assignment makes the immutable
rate snapshot available to the calculator; it does not finalize usage or
authorize a charge.

Invoice input finalization requires complete device and relay reports and an
explicit account-period schedule assignment; it does not collect payment.
Before broad customer rollout, select an alert delivery channel, seller and tax
responsibilities, payment provider, self-hosted support terms, and retention
period, and validate cap reservation sizing from shadow data. Keep alerts,
spending-cap enforcement, and payment collection out of customer operation
until their implementations and operational checks are complete. No billing
configuration is required for deployments that do not opt in; relay forwarding
and device membership behavior remain available without usage collection.

To stop device collection, disable it using the audited command before
downgrading to a release without collection hooks. Coordinate ledger and spool
retention with the deployment's existing data-governance rules. A billing-
specific retention and deletion policy remains undecided and must be set before
broad rollout.
