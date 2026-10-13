<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-0053: Payment-provider integration boundary

- **Status:** Accepted (pilot provider: Paddle; live collection remains gated)
- **Date:** 2026-10-12
- **Deciders:** Billing decisions recorded in #275
- **Related:** #275, ADR-0049, ADR-0050, ADR-0051 (proposed), ADR-0052 (proposed)

---

## Context

ADR-0049 brings billing into scope but requires metering and enforcement to stay
separate, unconfigured deployments to retain current behavior, and enforcement
to default off. ADR-0050 establishes the account-attributed device and managed
relay usage source. #275 assigns account plans and payment state to the control
plane and requires payment integration to stay outside live networking.

Issue #275 selects a merchant-of-record seller model and Paddle Billing for
the pilot. Checkout rates are pre-tax USD, with applicable tax added and shown
separately. Paddle business/domain approval, supported-market confirmation,
and SaaS tax-category configuration remain live-selling gates. Issue #275
approves a 14-day pilot grace period with retries on days 1, 3, 7, and 12,
in-app notices to billing admins, and continued service after day 14 while an
invoice remains past due for customer/operator resolution. Payment failure
does not suspend networking. Keep only provider references and minimum
auditable invoice/payment state; never store card credentials or raw relay
traffic. Retain finalized invoices and audit/payment state for seven years,
normalized webhook events for thirteen months, and no raw webhook body after
signature verification. Whether retries use Paddle subscriptions or scheduled
re-issuance of one-time invoice checkouts remains to be decided in #275.

## Decision

Use Paddle Billing for pilot collection through an asynchronous adapter owned
by the management control plane. The internal account billing ledger remains
the source of rates, billable usage, and invoice-line calculations. The
current adapter creates one one-time Paddle transaction for each finalized
monthly invoice and uses Paddle Checkout for customer payment. The retry
cadence is approved, but the mechanism is pending the #275 decision above;
never create another transaction while a prior attempt may have succeeded.
Paddle calculates applicable tax and reports collection status; it does not
calculate Karst usage or decide relay forwarding. The billing console presents
the returned checkout link and reads payment state from the webhook-backed
internal ledger.

The internal invoice currency is USD, matching the approved pilot rates. This
ADR does not select refund/chargeback handling or merchant payout currency.
Verify Paddle account eligibility, supported customer markets, SaaS
tax-category approval, seller terms, and tax configuration before live
collection.

### Separation from networking and rollout

- No provider configuration and no explicitly assigned account rate schedule
  means no billing-provider calls, charges, or subscription enforcement.
  Self-hosted deployments remain unchanged unless an operator explicitly
  configures a paid-support billing arrangement.
- Provider calls, webhooks, reconciliation, and retry workers run in the
  control plane. Relays and node packet paths never call a provider.
- A provider outage or slow webhook does not change live forwarding. The
  control plane retains its last durably committed account state and reconciles
  asynchronously after recovery.
- Payment status is not itself a traffic instruction. Any later entitlement
  or suspension behavior requires a separate, explicitly enabled plan policy;
  no failure state directly blocks packets under this ADR.

### Internal invoices and provider operations

- Generate one internal invoice from the immutable rate-schedule version and
  finalized metering period. Record currency, customer-facing line items,
  schedule version, usage-report references/completeness, amounts in integer
  minor units, and an immutable invoice identifier before requesting collection.
- Combine device and managed-relay items on the same billing-period invoice
  where the selected provider supports it. Never create one payment request per
  usage batch or packet.
- Use a durable outbox for Paddle transaction creation. Commit the internal
  command and stable Karst invoice ID before making a network request; perform
  the request outside database transactions. Paddle does not accept
  client-supplied idempotency keys for arbitrary API operations, so an
  ambiguous create timeout must be reconciled against Paddle transactions
  before another create is attempted. Include the stable invoice reference in
  transaction `custom_data`; list transactions for the Paddle customer over a
  bounded creation window and compare that field locally. If reconciliation is
  inconclusive, hold the operation for an operator instead of risking a
  duplicate charge. Record final Paddle IDs and status, and surface terminal
  failures to operators.
- Treat an external invoice as a collection artifact, not a replacement for
  Karst's internal pricing/usage calculation. Corrections create auditable
  adjustments or a new invoice; they do not rewrite finalized source records.

### Webhook and reconciliation handling

- Verify Paddle webhook signatures against the raw request body and enforce
  timestamp freshness before accepting an event. Persist a normalized event
  record with the Paddle event ID as a unique key before returning a 2xx
  response;
  acknowledge within Paddle's five-second window and process asynchronously.
  Repeated delivery is idempotent; the same event identity with conflicting
  content is rejected and audited. Events can arrive out of order, so use
  `occurred_at` and reconciliation rather than arrival order.
- Apply accepted events asynchronously from a durable inbox. Do not call
  provider APIs or hold a database transaction open while acknowledging an
  incoming webhook.
- Do not assume webhook delivery order. For ambiguous or stale subscription
  state, reconcile against the provider's current object using a bounded,
  retryable job, then commit the resulting state locally.
- Retain only fields needed for payment state, financial audit, and customer
  support. Do not store card numbers, CVCs, raw payment credentials, or relay
  traffic metadata. Keep provider API secrets in deployment secret storage,
  unavailable to relays and customers. Retain finalized invoices and payment
  state seven years and normalized webhook events thirteen months; never
  persist raw webhook bodies after signature verification.

### Provider choice and seller responsibility

Paddle is selected for the pilot. Its published pay-as-you-go price is 5% plus
$0.50 per Checkout transaction, and Paddle describes itself as the merchant of
record that handles transaction processing, indirect tax, and compliant buyer
invoices. Confirm eligibility and contractual scope with Paddle; retain the
USD Karst invoice as the source for usage and pre-tax line amounts. Paddle
Checkout adds applicable tax to pre-tax USD rates and displays it separately,
subject to the approved Paddle tax category and customer location. See
[Paddle pricing](https://www.paddle.com/pricing),
[merchant-of-record tax handling](https://www.paddle.com/help/sell/tax/how-paddle-handles-vat-on-your-behalf),
and [Paddle setup requirements](https://developer.paddle.com/build/set-up-checklist/).
Paddle documents that its API [does not accept client-supplied idempotency
keys](https://developer.paddle.com/sdks/libraries/), supports transaction
lookup by customer and creation time through its [transaction list
API](https://developer.paddle.com/api-reference/transactions/list-transactions/),
and requires [raw-body webhook signature verification](https://developer.paddle.com/webhooks/about/signature-verification/)
with [fast acknowledgment and duplicate/out-of-order handling](https://developer.paddle.com/webhooks/about/respond-to-webhooks/).

Paddle documents at-least-once, potentially out-of-order webhook delivery and
does not provide client-supplied idempotency keys for arbitrary API creates.
Use its official [Go SDK](https://github.com/PaddleHQ/paddle-go-sdk) for API
and webhook signature handling, while preserving the inbox/outbox and
reconciliation rules above. Do not promise provider swapping: a later change
requires an explicit seller/tax decision and reviewed customer/data migration.

### Payment failure and recovery

- A payment failure first changes local billing status and starts the selected
  retry/grace policy; it never calls the forwarding path.
- The approved pilot uses a 14-day grace, retries on days 1, 3, 7, and 12, and
  in-app billing-admin notices. After day 14, keep service active and mark the
  invoice past due for customer/operator resolution. The transaction model for
  retries remains pending a #275 decision.
- When payment succeeds, a verified event or reconciliation job updates local
  status idempotently. If collection still fails after the approved grace,
  keep service active and mark the invoice past due; payment state never
  becomes a forwarding dependency.
- Refunds, disputed payments, chargebacks, partial payments, cancellations,
  and correction invoices require explicit policies before production billing.

## Consequences

### Positive

The internal ledger remains reproducible when rates or providers change.
Idempotent inbox/outbox processing tolerates retries and provider outages.
Network forwarding remains independent of collection availability, and
unconfigured deployments keep existing behavior.

### Negative

The control plane must maintain durable invoice and payment-state records,
retry workers, webhook verification, and reconciliation. Provider choice affects
merchant-of-record, tax, invoice presentation, support, and migration duties;
a generic interface cannot erase those differences. No automatic suspension
policy can be implemented until a post-grace entitlement decision is approved.

### Reconsider if

- Paddle cannot approve Karst's business/domain, support the product's SaaS tax
  category, or serve required launch jurisdictions under acceptable terms.
- A provider's webhooks cannot be made safely idempotent and reconciled.
- A future entitlement policy is proposed that would make payment collection a
  live networking dependency; that would conflict with ADR-0049 and this ADR.
