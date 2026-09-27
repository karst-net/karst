<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-0038: Relay per-aquifer capacity fairness

- **Status:** Accepted
- **Date:** 2026-09-27
- **Deciders:** TBD
- **Related:** #166 (multi-tenant SaaS, this ADR's tracking issue), `spec/ponor-v1.md`
  §7.4 (per-node rate limiting) and §13 #9 (the open item this ADR resolves),
  `bins/karst-relay/src/limits.rs` (the token-bucket primitive this ADR reuses),
  `bins/karst-relay/src/hub.rs` (the forwarding core this ADR changes),
  ADR-0033 (per-account aquifer scoping — the mechanism that makes "aquifer"
  the right unit to meter capacity by, rather than account or node)

---

## Context

#166 (multi-tenant SaaS scoping) listed "relay per-tenant capacity fairness"
as one of three items left after ADR-0033 (aquifer scoping), ADR-0035
(audit-log partitioning) and ADR-0037 (admin-console cross-tenant access)
shipped, describing it as "a `spec/ponor-v1.md` protocol change, not designed
here." `spec/ponor-v1.md` §13 #9 records the same gap directly:

> **Multi-aquifer relays are specified but not sized.** §5.4 scopes
> forwarding per aquifer; nothing says how a relay's capacity is divided
> between them, so one aquifer can consume a shared relay's entire budget
> within its per-node limits.

Checked directly against the tree before designing anything, because the
issue's own framing ("a protocol change") turned out not to hold.
`bins/karst-relay/src/limits.rs` already implements §7.4's per-node
token-bucket rate limiter (`Budget`/`Meter`), applied per-connection in
`hub.rs`'s `on_frame`. §7.4 itself is explicit that its numbers are "policy
rather than protocol": a relay operator is expected to tune them, and
nothing about the wire format encodes a rate. A relay with, say, a 25 Mbit/s
per-node budget and one aquifer holding 1,000 nodes can already have that
aquifer consume 25 Gbit/s of the relay's capacity, while a neighboring
aquifer with five nodes gets no larger a share per node but a much smaller
total — the resource-fairness gap #9 names. Nothing on the wire needs to
change to fix this: it is a relay-local admission decision, exactly like
§7.4's existing per-node check, just keyed by a different field the relay
already has on every admitted connection (`AquiferId`, from the roster).

Two things make the aquifer the right unit, not the account or the node:

- **Aquifer, not account, is the tenant-isolation primitive `ponor-v1.md`
  §5.4 already enforces at the relay.** ADR-0033 established that account
  and aquifer are usually 1:1 but are not the same concept; scoping capacity
  by whatever field forwarding is already scoped by avoids introducing a
  second tenant boundary the relay would have to reconcile against the
  first.
- **Node-level fairness already exists (§7.4) and does not need duplicating.**
  What is missing is specifically the *aggregate* — the case where many
  well-behaved nodes, each individually within budget, collectively starve
  another tenant.

## Decision

Add an optional, aggregate token-bucket budget per aquifer, checked in
addition to (not instead of) the existing per-node budget, on the relay's
forwarding path.

- **Config:** `bins/karst-relay/src/config.rs` gains an optional
  `[limits.aquifer]` table (`AquiferLimits`: `bytes_per_sec`, `byte_burst`,
  `frames_per_sec`, `frame_burst` — the same four fields `[limits]` already
  has for the per-node budget). Absent, the default: `hub::Config::aquifer_budget`
  is `None`, and forwarding behaves exactly as it did before this ADR — an
  aquifer's total share of a relay remains bounded only by its node count
  times the per-node budget. This is deliberately not a new default rate:
  guessing a "safe" default aggregate would be guessing at how many nodes a
  tenant has, which the relay has no basis to assume. Every field is
  required once the table is present at all — a partially-specified table
  would silently fall back to a guess for a number that matters, the same
  reasoning `[metrics]` and `[reflect]` already apply to their own
  all-or-nothing config tables.
- **Enforcement:** `Hub` gains one `Meter` per aquifer that has forwarded a
  frame (`aquifer_meters: HashMap<AquiferId, Meter>`), created lazily on
  first use so an aquifer nobody uses never allocates one. `forward_from_client`
  charges it, keyed by the sending node's aquifer, after the existing §5.4
  admission check succeeds (a frame rejected as `NOT_ADMITTED` never touches
  the shared budget) and before delivery. `deliver_from_mesh` charges the
  same meter, keyed by the destination's aquifer, so routing through a mesh
  peer is not a way to bypass a relay's local cap — the budget is about this
  relay's own capacity regardless of which connection a frame arrived on.
- **Failure behavior matches §7.4 exactly, deliberately.** Over the aquifer
  budget, the relay drops the frame silently — no `PeerGone`, no `Close` —
  and the sending connection is never closed for it. §7.4's own reasoning
  applies unchanged: a burst is what a relayed handshake looks like, and
  closing a connection over one would make the fairness mechanism itself a
  denial-of-service vector against a legitimate burst. A new
  `Dropped::AquiferRateLimited` and `ConnStats::dropped_aquifer_rate` exist
  so an operator can tell the two rate limiters apart in metrics
  (`karst_relay_dropped_aquifer_rate_total`), but neither changes what the
  peer observes.
- **No protocol change.** No new frame type, no new reason code, no version
  bump. This is enforced entirely relay-side, on data the relay already has
  (the roster's per-node `AquiferId`) — exactly the same category of change
  as tuning §7.4's own recommended defaults, which the spec already
  classifies as policy rather than protocol.

### Alternatives rejected

- **A wire-visible capacity-exceeded signal (a new reason code or frame).**
  §13 #6 already identifies the general problem with a relay-to-client
  congestion signal: it would itself be a channel a hostile relay could use
  to shape a peer's behavior, and it is unclear what a client could usefully
  do with "your aquifer, not you, is over budget" that is different from
  what it already does with an ordinary dropped frame. Deferred with #6,
  not solved here.
- **Scoping the aggregate budget by account instead of aquifer.** Rejected
  per the Context section above: aquifer is the boundary the relay already
  enforces, and account is a control-plane concept the relay does not
  otherwise need to know. Introducing it here would require either a new
  roster field or an assumption (one account per aquifer) that ADR-0033
  already declined to bake in structurally.
- **A required, non-zero built-in default aggregate.** Rejected because any
  number is a guess about tenant size that the relay cannot make correctly
  for every deployment — an operator running a five-node aquifer and one
  running a five-thousand-node aquifer need different numbers, and a wrong
  default that is silently too low is a support incident, while one that is
  silently too high does nothing. Opt-in avoids guessing either way.
- **Per-account admin-console configuration of the aquifer budget.** Out of
  scope for this pass — this ADR is the relay/protocol-level mechanism;
  whether and how an account admin sets their own aquifer's number through
  the console (versus an operator setting one relay-wide value covering
  every aquifer it serves) is a product surface question #166 leaves open,
  not an architecture question this ADR needs to answer to unblock the
  mechanism existing at all.

---

## Consequences

### Positive

- Closes `ponor-v1.md` §13 #9 and one of #166's three remaining sub-items
  (relay per-tenant capacity fairness), leaving only billing/plan
  enforcement — explicitly a product decision, not an architecture one —
  under that issue.
- Fully backward compatible and fully opt-in: an operator who does nothing
  sees no behavior change, no config-file break, and no wire change.
- Reuses the exact `Budget`/`Meter` primitive §7.4 already ships and already
  has full test coverage for (token-bucket correctness, burst handling, a
  backwards clock, a zero rate reading as prohibitive rather than
  unlimited) — no new rate-limiting logic to get subtly wrong a second way.

### Negative

- **One number, not a real allocation policy.** This is a hard cap per
  aquifer, not weighted fair queuing or a per-aquifer guaranteed minimum. An
  operator who wants proportional sharing (e.g., "aquifer A gets 2x aquifer
  B's share of whatever's left") gets nothing here beyond setting two static
  numbers.
- **Cross-relay fairness is still unaddressed.** This bounds one relay's own
  local capacity per aquifer; it says nothing about how a mesh (§8)
  balances load across relays, or about relay selection under a
  fairness-constrained relay. A large aquifer spread across many relays
  still sees each relay enforce its cap independently, which is coherent
  but not globally optimized.
- **No console/API surface.** An operator sets this in `karstd.toml`-shaped
  relay config today, restart-only (like every other `[limits]` field) — no
  hot reload, no per-account self-service knob. A future per-account
  self-service version would need its own design pass (roster-carried
  budget, or a relay-side config reload path `roster::Source` does not
  currently offer for non-roster settings).

### Reconsider if

- An operator needs proportional (not just capped) sharing between aquifers
  on a congested relay — this ADR's hard cap does not address that, and a
  weighted scheme would be a materially different mechanism.
- A real deployment needs this configurable per account through the admin
  console rather than per relay through static config — that is a new
  surface (roster-carried or a relay config hot-reload path), not an
  extension of what shipped here.
- Cross-relay/mesh capacity fairness becomes a real operational problem —
  this ADR explicitly does not touch that, and it would need its own design
  independent of this one.
