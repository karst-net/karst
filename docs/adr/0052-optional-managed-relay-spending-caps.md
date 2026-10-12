<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-0052: Optional managed-relay spending caps

- **Status:** Proposed
- **Date:** 2026-10-12
- **Deciders:** Pending
- **Related:** #275, ADR-0038, ADR-0049, ADR-0050, ADR-0051 (proposed)

---

## Context

ADR-0050 defines account-attributed managed-relay byte usage and durable reports,
but deliberately does not enforce charges or limits. #275 requires optional
customer-set relay spending caps, with explicit acknowledgment that reaching a
cap can interrupt relayed connections. The cap must cover an organization's
managed-relay spend across all its relays; device charges are excluded.

ADR-0038's opt-in per-aquifer rate limiter protects one relay's capacity. It is
not a money meter and cannot enforce an account-wide billing cap. Since usage
reports arrive asynchronously, a cap cannot safely rely on reports that have
not yet arrived or on a live control-plane request for every forwarded packet.

## Decision

Propose an opt-in byte-credit allocator. A cap remains disabled until a
customer sets one and acknowledges possible interruption of managed-relay
forwarding. No cap behavior applies to an unconfigured account or self-hosted
relay. Packet forwarding and credit renewal make no payment-provider calls.

The cap period is an approved UTC calendar month. The cap remains absent unless
an organization explicitly sets a USD relay-overage limit and acknowledges
possible interruption. #275 approves central byte-credit reservations, reserve
before forwarding, count ambiguous writes as consumed, and pause only capped
managed-relay forwarding at exhaustion. Grant sizing, expiry, accounting-delay
bounds, and clock-skew limits still require shadow data and operational
validation. This ADR selects no customer-facing cap amount.

### Cap budget

- The cap limits variable managed-relay charges for one organization and period.
  Device charges are excluded. The account's assigned immutable rate schedule
  and pooled included allowance determine how many bytes the cap permits.
- Store the cap, currency, rate-schedule version, effective period, enabled
  state, and customer acknowledgment as audited account settings. No assigned
  rate schedule means no cap enforcement.
- Convert the maximum relay charge to a whole-byte budget using exact integer
  bytes and rational rates. Apply the included allowance and invoice rounding
  rules, then truncate the permitted byte budget down so the billed relay charge
  cannot exceed the customer's cap.
- A setting change never rewrites prior periods. Increases may take effect
  once the new cap version and additional grants are durable. A decrease takes
  effect next period by default. An in-period decrease is possible only after
  every outstanding grant has been surrendered or safely expired and fenced,
  and only when already-consumed spend fits below the new cap. A registry flag
  alone cannot revoke credits cached on an unreachable relay; consumed spend
  cannot be undone by lowering a cap.

### Central reservation, local enforcement

- The control plane atomically reserves bytes from one organization-period
  budget when issuing a grant. It records a unique grant ID, organization,
  period, rate version, relay identity/generation, and byte limit. Retries are
  idempotent; they cannot mint credits twice.
- A grant is bound to one authenticated relay generation and period. The relay
  durably stores the grant before use and reserves destination-write bytes
  before forwarding. Completed writes become consumed. Failed writes release
  reservations only after durable state prevents later reuse. If a crash leaves
  a write ambiguous, treat its reserved bytes as consumed until reconciliation:
  this can stop traffic early, but cannot increase the cap.
- The relay requests grants asynchronously and forwards no more billable bytes
  than its durable, unspent credits. It makes no synchronous allocator or
  payment-provider call in the packet path.
- The account-period invariant is that consumed bytes plus outstanding grants
  plus unallocated bytes never exceeds the cap-derived byte budget. Do not
  reassign credits held by an unreachable relay. Return unused bytes only
  after the relay durably surrenders the grant and can no longer spend it. For
  an unreachable relay, a control-plane fence prevents new grants but does not
  revoke cached offline credits; those remain reserved until the grant expires
  under the trusted-time/skew rule. Reclaim them only after expiry and fencing,
  or after an independently verifiable mechanism makes the relay unable to
  spend them.
- Grant and debit state survives relay restart. If it cannot be recovered, the
  relay fails closed for capped forwarding until it obtains a new fenced
  generation and grant.

### At the cap and recovery

- When local credits are exhausted, stop new managed-relay destination writes
  for that organization. Relayed sessions may stall or disconnect; direct
  peer-to-peer traffic and other organizations' relays continue. The customer
  must acknowledge this behavior before enabling the cap.
- If the control plane is unavailable, a relay can spend only persisted grants.
  When these run out, managed-relay forwarding pauses locally for that
  organization. This bounds spend without making forwarding depend on an
  online billing service.
- Old-period grants are unusable after the period boundary. New-period grants
  require the new cap and rate-schedule versions. If a relay cannot establish
  grant validity within the configured clock-skew bound, it fails closed until
  it can obtain a valid grant. The skew bound must be tested before rollout.
- Cap increases restore traffic after the allocator durably issues more
  credits. At period reset, new-period credits can be granted. Payment-provider
  availability is not part of recovery.

### Meter reconciliation and reporting

- Credits decide whether local forwarding is allowed; ADR-0050's authenticated
  batches remain the billable usage record. Credits do not estimate missing
  usage or replace the durable meter.
- Reconcile consumed grants with accepted usage batches by organization, relay
  generation, period, and meter version. A mismatch marks the period
  incomplete, blocks finalization, and raises an operator-visible discrepancy.
  It never silently enlarges the cap or invents billable bytes.
- Show the customer the cap, reported usage, completeness/freshness, bytes
  reserved at each relay, and whether forwarding is paused. Incomplete usage is
  a lower bound; reservations are separate from confirmed use.
- Authenticate grants to current account mappings and reject revoked relay
  generations, stale mapping versions, cross-account reuse, wrong-period
  grants, and conflicting duplicate IDs. Audit cap changes, acknowledgments,
  grant issue/return/fencing, and corrections without retaining traffic data.

### Alternatives rejected

- **Use delayed aggregate reports to gate each packet.** Reports may be late,
  allowing overspend, and a live request would add a billing dependency to
  forwarding.
- **Give every relay the full cap.** Concurrent relays could each spend it.
- **Reuse ADR-0038's local limiter.** It is not organization-wide or monetary.
- **Reclaim credits from an unreachable relay after a timeout.** A partitioned
  relay may still spend them; safe return needs durable surrender or fencing.
- **Stop all account traffic.** Only capped managed-relay forwarding is affected.

---

## Consequences

### Positive

Central reservations prevent relays from spending the same budget twice.
Local enforcement is independent of control-plane and payment-provider
availability. Restart, partition, and reconciliation behavior are explicit;
unconfigured deployments retain existing behavior.

### Negative

An offline or failed relay may strand credits and cause forwarding to pause
before the nominal cap is used. Small grants reduce stranded balances but
increase allocator load. Clock validity, grant size and count, UI details, and
mismatch policy need operational tests before enforcement is enabled.

### Reconsider if

- Shadow usage or relay failure rates show that reservation balances strand
  unacceptable customer capacity.
- The product requires immediate cap decreases while a relay can be offline.
- Customers need other transports, such as TURN, covered by the cap; those
  transports first need an approved metering boundary.
