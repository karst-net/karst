<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-0051: Versioned billing rates and usage alerts

- **Status:** Proposed
- **Date:** 2026-10-12
- **Deciders:** Pending
- **Related:** #275, ADR-0049, ADR-0050

---

## Context

ADR-0050 provides durable account-attributed device intervals and managed
relay-byte reports. Its customer report distinguishes received bytes from
coverage uncertainty and does not estimate missing usage. The product decisions
in #275 require graduated per-device charges, a separately pooled managed-relay
charge, and usage alerts by default. Rates and invoice behavior must be
reproducible after prices change, and an unconfigured account must continue to
have no billing behavior.

The pilot rate amounts are approved for modeling and explicit schedule
assignment: $2.50 per device per month for devices 1–10, $1.50 for devices
11–50, and $0.75 for each device above 50; managed relay traffic includes 10
decimal GB per organization per month, then costs $0.20 per additional decimal
GB. Billing-cycle boundaries, currency rounding, alert thresholds and delivery,
and finalization of periods with incomplete reports remain unsettled. The
repository has no production customer usage sample. Any sample counts below
are explicit sensitivity scenarios, not forecasts.

Cloud egress is only one variable cost. Published North America/Europe list
rates currently indicate about $0.087–$0.09 per decimal GB for Azure/AWS after
account allowances; Google Cloud lists $0.12 per GiB after its smaller account
allowance. Provider allowances are shared at the account level. These figures
exclude compute, inter-zone traffic, redundancy, observability, support, and
payment costs. Sources: [AWS EC2 data transfer pricing](https://aws.amazon.com/ec2/pricing/on-demand-backup/),
[Azure bandwidth pricing](https://azure.microsoft.com/en-us/pricing/details/bandwidth/),
[Google Cloud network pricing](https://cloud.google.com/vpc/network-pricing).

## Decision

Use an opt-in, versioned rate schedule and an alert evaluator. The pilot rates
below are approved for explicit schedule assignment. Do not enable charges
merely because this ADR is accepted; an account must have an explicitly
assigned schedule. Usage alerts are on by default for scheduled accounts, as
required by #275. The notification channel and recipient selection must be
decided before alert delivery ships. Unconfigured accounts and self-hosted
installations without an explicitly configured support schedule retain current
behavior.

### Rate schedule and effective dates

- Store each schedule as an immutable version with currency, device bands,
  relay allowance/rate, and effective billing period. A correction or price
  change creates a new version; it never mutates rates already used for a
  period.
- Assign one schedule version to an organization for a billing period and
  retain that version with every preview and charge record. Rate changes take
  effect at a period boundary; retroactive repricing is not allowed.
- Represent money using integer currency minor units and exact rational
  arithmetic. Do not use binary floating point. The invoice-boundary rounding
  rule remains undecided; no rounded invoice amount is produced until that rule
  is approved.

### Graduated device charge

- Apply each tier's rate only to devices in that band. Crossing a threshold
  does not reprice earlier bands.
- Intersect the eligible device intervals from ADR-0050 with the account's
  billing period. Offline time remains eligible; time before enrollment or at
  and after revocation is excluded.
- Calculate each segment from the eligible-device count and exact covered
  duration. Prorate each device's monthly rate by its fraction of the period,
  sum the exact values across all segments, and round once at invoice creation.
- The approved pilot device rates are $2.50 per device per month for devices
  1–10, $1.50 per device per month for devices 11–50, and $0.75 per device per
  month above 50. These are graduated bands: crossing a threshold does not
  reprice earlier devices.
- Apply these as monthly rates, prorated by exact eligible duration within the
  eventual billing period. The billing-cycle boundaries and proration calendar
  convention still need approval; the calculator therefore accepts explicit
  report periods and does not choose invoice boundaries.

### Pooled managed-relay charge

- Pool the already-defined managed relay destination-write bytes across all
  relays belonging to the organization for the billing period. Both traffic
  directions count. Direct peer-to-peer traffic and relay-to-relay hops remain
  excluded.
- Use decimal GB (1 GB = 1,000,000,000 bytes) for customer pricing so the
  allowance and rate map directly to the byte counter. Keep stored usage in
  exact integer bytes and compute overage as exact rational money.
- The approved pilot relay schedule includes 10 decimal GB per organization per
  month, then charges $0.20 per additional decimal GB. This applies to both
  traffic directions and remains separate from device charges. Shadow usage
  and fully loaded relay costs should be reviewed before wider publication.

### Alerts and incomplete usage

- Evaluate alerts from period-to-date device and relay usage against the
  account's assigned schedule and alert preferences. Deduplicate on account,
  period, schedule version, meter, and threshold so retries do not send repeats.
- Enable alerts by default for accounts with a billing schedule. A customer may
  adjust supported preferences after an alert channel and recipient model are
  selected.
- Proposed relay thresholds are 75%, 90%, and 100% of the included allowance
  or optional customer relay cap. These are starting hypotheses, not approved
  defaults. Alert channels, device-charge alert semantics, and customer
  preferences require a separate product decision.
- Include the report's `as_of` time and completeness state in every usage
  notification. When coverage is incomplete, describe received usage as a
  lower bound and do not present it as a final amount.
- Do not finalize charges from incomplete reports until #275 selects a
  late-data/grace policy. This ADR does not decide whether a period is held open,
  provisionally charged, or corrected on a later invoice.

### Illustrative sensitivity scenarios

The following uses the approved pilot rates above and assumes the metered
destination-write bytes are approximately the provider's
internet egress bytes. This is a scenario model, not observed customer use or
a margin promise. Shared provider allowances can reduce marginal egress cost
but cannot be allocated to a specific customer.

| Devices | Assumed relay usage | Device charge | Relay charge | Total pilot estimate | Approx. variable egress after listed allowances |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 10 | 10 GB | $25 | $0 | $25 | $0–$1 |
| 50 | 100 GB | $85 | $18 | $103 | $0–$12 |
| 250 | 1,000 GB | $235 | $198 | $433 | $78–$112 |

The device counts and per-device usage assumptions are chosen solely to show
the arithmetic. Karst has no production distribution to support these as
representative customer cohorts. Record 30–90 days of shadow usage, then
compare per-account and per-device p50/p90/p99 usage with actual cloud and
operational costs before publishing rates.

### Explicit non-goals

- This mechanism does not collect payment, change subscription status, or make
  a payment provider a networking dependency.
- This mechanism does not enforce relay spending caps. A separate ADR must
  specify organization-wide reservations, relay crash behavior, overshoot bounds,
  interruption, and recovery.
- It does not price optional self-hosted support; support coverage and price
  remain a separate product decision.
- It does not bill estimated bytes or silently treat incomplete coverage as
  zero usage.

### Alternatives rejected

- **Edit a shared rate row in place.** Historical statements would change when
  rates are updated and could not be reproduced.
- **Use floating point or round per device/window.** Repeated rounding can make
  totals depend on segmentation, report arrival order, or device count.
- **Reprice earlier device bands when a threshold is crossed.** This contradicts
  the agreed graduated pricing behavior.
- **Treat missing relay reports as zero or estimate their bytes.** ADR-0050
  makes coverage uncertainty explicit and prohibits invented customer totals.
- **Block forwarding or contact a payment provider during packet handling.**
  Billing remains separate from networking; all enforcement is a separate,
  explicitly enabled mechanism.

---

## Consequences

### Positive

Rate versions make previews and future statements reproducible. Exact arithmetic
preserves the agreed graduated tiers and device-time proration. Alerts can be
retried without duplicate delivery and can communicate report uncertainty.

### Negative

No account can be billed until a schedule is assigned and the open commercial
inputs are resolved. Holding incomplete reports open delays final billing, while
charging them provisionally would require an approved correction policy. Alert
delivery depends on a separately selected channel and customer preference model.

### Reconsider if

- Production shadow data shows that monthly periods or the proposed tier model
  produce confusing or costly corrections.
- The selected payment provider or tax jurisdiction requires different currency
  or invoice-boundary semantics.
- Relay reports can support a stronger completeness/finalization guarantee
  than ADR-0050 currently provides.

