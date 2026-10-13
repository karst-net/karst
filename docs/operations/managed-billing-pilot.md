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

This implementation provides an audited in-app alert feed and an optional
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

Paddle is the selected merchant of record and pilot provider. Rates are
pre-tax USD; Paddle adds applicable tax and shows it separately. Retain
finalized invoices and payment/audit state for seven years and normalized
webhook events for thirteen months; never persist raw webhook bodies after
signature verification. Live collection still requires Paddle account/domain
approval, supported-market confirmation, and SaaS tax-category configuration.
The approved pilot uses a 14-day grace, retries on days 1, 3, 7, and 12, and
in-app billing-admin notices. After day 14, keep service active and mark the
invoice past due for customer/operator resolution. The transaction model for
retries remains pending a #275 decision; automated retry execution is not
implemented. Payment failure does not suspend networking. Paid self-hosted
support terms remain pending. The relay cap remains unset unless an
organization explicitly opts in; use shadow-usage data to tune reservations
before enabling it. Payment collection stays disabled by default and uses
sandbox mode when explicitly enabled; live collection requires a separate
operator approval and explicit account mapping. No billing configuration is
required for deployments that do not opt in; relay forwarding and device
membership behavior remain available without usage collection.

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
retention with the deployment's existing data-governance rules.
