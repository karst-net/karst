<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Managed billing pilot: customer guide

This guide describes the approved managed-billing pilot terms. It is not a
notice that billing is generally available. Collection and relay spending caps
remain unavailable until the service is launched and an organization
explicitly opts in.

## What is measured

Managed billing uses UTC calendar months. An enrolled device counts while it
is online or offline, from enrollment until revocation. Its monthly charge is
prorated for the exact eligible time in that month. Rates are graduated, so
each band is charged at its own rate:

| Devices in an organization | Monthly rate per device |
| --- | ---: |
| 1–10 | $2.50 |
| 11–50 | $1.50 |
| 51 and above | $0.75 |

Managed relay traffic is pooled across the organization's managed relays and
is a separate line from device charges. The first 10 decimal GB (10,000,000,000
bytes) per UTC month are included; additional traffic costs $0.20 per decimal
GB. The meter counts customer payload bytes after the relay completes a
destination transport write. It excludes transport framing, failed or partial
writes, queue drops, direct peer-to-peer traffic, and internal relay-to-relay
hops. A completed transport write means the transport accepted the data; it
does not prove that the destination application received it.

## Reports and invoices

Usage reports show coverage and their most recent accounting time. Missing or
late reports mean the displayed usage is a lower bound. Incomplete usage is
not estimated, charged, or finalized; the period stays open until required
reports are complete. Final invoice lines are calculated from the immutable
rate schedule assigned to that organization and period. Exact eligible time is
used for device proration, and each finalized line is truncated down to cents.

An account is not billed just because it has usage. A schedule must be
explicitly assigned to that account and exact period, and an operator must
finalize the period after device and managed-relay coverage is complete. A
finalized invoice is a billing record; it does not itself confirm payment.

## Alerts and optional relay caps

For an organization with an assigned schedule, the pilot records managed-relay
alerts at 75%, 90%, and 100% of the included allowance or optional cap. Alerts
appear in the audited in-app feed for billing administrators, once per
threshold and period. An alert includes a coverage warning when reports are
incomplete.

An organization may opt into a monthly managed-relay spending cap. The cap
applies only to managed-relay overage, requires an administrator to
acknowledge that relayed connections can be interrupted when it is reached,
and does not cap device charges. An unset cap leaves relay forwarding
uncapped. Reaching an enabled cap can stop capped relay forwarding for the
rest of the period; it does not stop direct peer-to-peer traffic.

## Payment and service availability

Paddle is the selected merchant of record for the pilot. Invoice prices are in
USD before tax; Paddle calculates applicable tax and shows it separately. When
collection is enabled for an account, an owner or billing administrator can
request a checkout link and inspect payment status. The current checkout flow
is opt-in and does not charge an account solely because an invoice was
finalized.

The approved payment policy is to retry on days 1, 3, 7, and 12 after a failed
payment, notify billing administrators in-app, and keep the service active
after day 14 while the invoice remains past due. Payment failure never
suspends networking. The billing page shows persisted in-app notices for
distinct failed-payment events, including later failed attempts. Automated
retry execution remains under implementation; the one-time invoice versus
subscription/dunning choice remains open. Live collection also requires
provider onboarding, supported-market confirmation, and tax-category
configuration.

## Self-hosted deployments

Managed usage billing is not enabled by default. A self-hosted installation
with no explicit billing configuration continues to use its existing device
and networking behavior, and no provider collection occurs. Paid support for
self-hosted deployments has been selected in principle, but its proposed price
and coverage have not yet been approved. Software licensing is unchanged.
