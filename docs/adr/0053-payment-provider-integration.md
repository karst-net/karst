<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-0053: Payment-provider integration boundary

- **Status:** Accepted
- **Date:** 2026-10-12
- **Deciders:** #275
- **Related:** #275, ADR-0049, ADR-0050, ADR-0051 (proposed), ADR-0052 (proposed)

---

## Context

ADR-0049 brings billing into scope but requires metering and enforcement to stay
separate, unconfigured deployments to retain current behavior, and enforcement
to default off. ADR-0050 establishes the account-attributed device and managed
relay usage source. #275 assigns account plans and payment state to the control
plane and requires payment integration to stay outside live networking.

Paddle is selected as merchant of record and pilot provider. Checkout uses
pre-tax USD rates, with applicable tax calculated and shown separately by
Paddle. Live collection remains gated on business/domain approval, supported
launch markets, and SaaS tax-category configuration. Retain finalized invoices
and payment/audit state for seven years and normalized webhook events for
thirteen months; never persist raw webhook bodies after signature verification.
Issue #275 approves a 14-day pilot grace period: asynchronously retry on days
1, 3, 7, and 12 after failure; send in-app notices to billing admins; then keep
the service active after day 14 and mark the invoice past due for customer or
operator resolution. Payment failure does not suspend networking.

## Decision

Propose asynchronous payment integration owned by the management control plane.
The internal account billing ledger remains the source of rates, billable usage,
and invoice-line calculations. A provider collects payment and reports payment
status; it does not calculate Karst usage or decide relay forwarding.

Refund, chargeback, partial-payment, and cancellation policy remain undecided.
Payment-provider integration remains gated on Paddle onboarding and the
remaining launch checks above.

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
- Use an outbox for provider-side create/update/collect operations. Commit the
  internal command and its stable idempotency key before making a network
  request; perform the request outside database transactions. Retry safely,
  record final provider IDs/status, and surface terminal failures to operators.
- Treat an external invoice as a collection artifact, not a replacement for
  Karst's internal pricing/usage calculation. Corrections create auditable
  adjustments or a new invoice; they do not rewrite finalized source records.

### Webhook and reconciliation handling

- Verify provider webhook signatures and freshness before accepting an event.
  Persist a normalized event record with a unique provider name and provider
  event ID key before returning success. Repeated delivery is idempotent; the
  same event identity with conflicting content is rejected and audited.
- Apply accepted events asynchronously from a durable inbox. Do not call
  provider APIs or hold a database transaction open while acknowledging an
  incoming webhook.
- Do not assume webhook delivery order. For ambiguous or stale subscription
  state, reconcile against the provider's current object using a bounded,
  retryable job, then commit the resulting state locally.
- Retain only fields needed for payment state, financial audit, and customer
  support. Do not store card numbers, CVCs, raw payment credentials, or relay
  traffic metadata. Keep provider API secrets in deployment secret storage,
  unavailable to relays and customers. Exact retention and access controls
  require the data-handling decision in #275.

### Provider choice and seller responsibility

The provider adapter must make seller-of-record and tax responsibilities
explicit; they are not interchangeable configuration details.

- **Direct Stripe Billing:** candidate where Karst remains the seller and can
  handle applicable tax, refunds, disputes, and customer obligations. Stripe
  Billing provides subscription and collection operations, but direct Stripe
  processing does not make Stripe the merchant of record.
- **Stripe Managed Payments:** candidate where its supported merchant-of-record
  markets and service terms fit. It adds a transaction fee to standard payment
  processing and Billing fees.
- **Paddle:** candidate where its merchant-of-record model and supported
  markets fit and Karst wants the provider to assume specified indirect-tax
  responsibilities. Review its reseller, pricing, payout, and support terms.

Current published fee comparisons and conditional recommendations are tracked
in #275; verify vendor terms, business eligibility, and all-in fees before
selection. This ADR does not mandate or promise transparent provider swapping:
each adapter exposes only capabilities it can actually support, and changing
merchant-of-record model requires a reviewed customer/data migration.

### Payment failure and recovery

- A payment failure first changes local billing status and starts the selected
  retry/grace policy; it never calls the forwarding path.
- The approved pilot uses a 14-day grace, with retries on days 1, 3, 7, and 12
  after failure and in-app billing-admin notices. After day 14, keep service
  active and mark the invoice past due for customer/operator resolution.
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
a generic interface cannot erase those differences. Payment state must never
become a live forwarding dependency; the approved pilot keeps service active
after grace.

### Reconsider if

- The chosen provider cannot support the billing model, launch jurisdictions,
  invoice requirements, or required data-handling terms.
- A provider's webhooks cannot be made safely idempotent and reconciled.
- A future entitlement policy is proposed that would make payment collection a
  live networking dependency; that would conflict with ADR-0049 and this ADR.
