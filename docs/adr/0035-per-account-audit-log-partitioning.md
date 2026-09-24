<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-0035: Per-account partitioning of the audit log

- **Status:** Accepted
- **Date:** 2026-09-24
- **Deciders:** TBD
- **Related:** #172 (this ADR's tracking issue), ADR-0033 §"Scoping note
  (2026-09-22)" (found the gap, explicitly deferred designing the fix to its
  own ADR), ADR-0016 (Bedrock anchor authorities — what an `anchor` entry
  commits to), `server/management/internals/karst/audit/audit.go`,
  `server/management/internals/karst/api/nodes.go`

---

## Context

ADR-0033's scoping note found that `bootstrap.Karst.Audit` is one
append-only, hash-chained `*audit.Log` shared by the entire deployment.
`audit.Entry` carries no `AccountID` — just `Seq`, `Actor`, `Action`,
`Target`, `Detail`, and the hash-chain fields — and `Log.Head`/`Log.VerifyFrom`
take no account parameter. It named this "a materially bigger change...
out of scope for this pass" and deferred the design to its own ADR. This is
that ADR.

Checked directly against the tree, rather than re-assumed from ADR-0033's
framing, before deciding anything:

### The console's audit listing has no account filter at all — worse than ADR-0033 described

ADR-0033's scoping note only examined `EntriesSinceAnchor`, a *count* leak.
`api/nodes.go`'s `auditList` handler is the console's `GET /karst/v1/audit`
endpoint, gated only by `h.requireAudit` (checks the audit log is
configured, not which account is asking) and authentication (any account
member). It calls `h.audit.ListFiltered(r.Context(), actor, action, offset,
limit)` — no account argument exists to pass. In a deployment with more
than one `Account` row (confirmed reachable today per ADR-0033: any
deployment with `singleAccountMode` off, or multi-domain IdP grouping),
**every authenticated console user with audit-read access can list every
other tenant's `Actor`/`Action`/`Target`/`Detail` rows**, not merely see a
number climb. `streamAuditJSON`/`streamAuditCSV` (the `/audit/export`
handlers) have the same gap. This is a real cross-tenant confidentiality
leak of content, not just metadata — a step past what ADR-0033 flagged and
reason enough on its own to fix this now rather than continue deferring it.

### Exactly one production call site writes entries, and it already has the account

Searched every `Append` call site in `server/`. Test files aside, there is
**one**: `auditMutations` in `api/nodes.go`, a middleware that records every
successful console-API mutation. It already reads
`nbcontext.GetUserAuthFromContext(r.Context())`, and `auth.UserAuth` already
carries `AccountId` (`server/management/server/context/auth.go`). The
"deployment-level IdP sync, server startup/shutdown, config reloads" cases
ADR-0033's scoping note worried about as unattributable do not exist as
`Append` call sites today — there is nothing to design a sentinel account
for yet. Named here so the eventual addition of such a call site does not
silently regress into an unscoped entry (see Decision, and Reconsider if).

### `audit.Log` already has an account-scoped sibling to imitate

`AddSink`/`ListSinks`/`RemoveSink` in the same file already require an
account via `audit.WithAccount(ctx, accountID)` / `accountFromContext`, with
`ErrNoAccount` as a distinguishable sentinel error. Nothing about
per-account scoping is new to this package; only `Entry` itself, and the
methods that read and write it, are unscoped.

### The single shared hash chain is a feature ADR-0033 already argued for, not a bug to design away

ADR-0033's scoping note: "the shared chain is one hash-linked sequence, so
an account's anchor arguably *does* still prove 'everything up to this
point, across the whole shared log, is unmodified' — if anything, one
tenant enabling Bedrock enforcement incidentally strengthens
tamper-evidence for the whole shared log." That reasoning is sound and
independent of the confidentiality question above: whether the log is one
chain or many is orthogonal to whether account B can list account A's rows.
Nothing forces re-architecting the hash chain itself to fix the
confidentiality and metric leaks.

---

## Decision

### 1. `audit.Entry` gains an `AccountID` column, included in the hash

Every entry is tagged with the account it belongs to. `AccountID` is added
to `chainHash`'s inputs alongside the existing fields — an operator with
direct database access who reassigned an entry's `AccountID` after the fact
(to hide one tenant's action inside another's view, or vice versa) would
otherwise leave the chain hash unchanged; including it makes that
tampering exactly as detectable as editing `Actor` or `Target` already is.

`Append`'s signature does not grow a parameter. It reads `AccountID` from
context via the existing `accountFromContext` helper — the same mechanism
`AddSink`/`ListSinks` already use — so the one production call site changes
by wrapping its context: `audit.WithAccount(r.Context(), user.AccountId)`.
A caller with no account in context (today: only the package's own tests)
gets `AccountID = ""`, not an error — `Append` must not become a new way
for an audit-relevant mutation to fail. An empty-`AccountID` entry is
excluded from every per-account view added below; there is no current
production path that produces one, so no sentinel/placeholder account is
invented for a case that does not exist (see Reconsider if).

### 2. The chain itself stays one global, deployment-wide sequence

`Seq` keeps counting across every account, `PrevHash`/`Hash` keep chaining
across every account's entries in write order, and `Verify`/`VerifyFrom`
keep validating the whole chain. This is deliberately **not** re-architected
into independent per-account chains (see Alternatives rejected). Splitting
into independent chains was the "reconsider if" trigger ADR-0033's scoping
note already named for when per-tenant *tamper-evidence* framing is
actually required — not merely when per-tenant *reads* are required, which
is the problem actually in hand.

### 3. Every account-facing read gets an account-scoped counterpart

Added to `audit.Log`, alongside (not replacing) the existing unscoped
methods:

- `AccountHead(ctx, accountID) (seq uint64, hash string, err error)` — the
  newest entry belonging to `accountID`. Its `seq`/`hash` are still a
  position in the one global chain, not a separate counter starting at 1;
  callers must not assume contiguity.
- `ListFilteredForAccount(ctx, accountID, actor, action string, offset,
  limit int) ([]Entry, error)` and `ListBeforeForAccount(ctx, accountID
  string, before uint64, limit int) ([]Entry, error)` — the same queries as
  their unscoped counterparts, with `account_id = ?` added.
- `CountSince(ctx, accountID string, sinceSeq uint64) (uint64, error)` — how
  many of *this account's own* entries have `Seq > sinceSeq`. This replaces
  the `globalHead.Seq - anchorSeq` arithmetic `auditList` used for
  `entries_since_anchor`, which was exactly ADR-0033's named leak.

The existing unscoped `List`/`ListFiltered`/`ListBefore`/`Head` are left in
place, not deleted — `Verify`/`VerifyFrom` need the unscoped read to walk
the whole chain, and deleting working, tested methods with no caller left
to replace them would be unjustified churn. They are documented as
deployment-wide and, after this change, have no remaining console-facing
caller.

### 4. `bedrock.AuditHead` becomes account-scoped

`PrepareAnchor(ctx, accountID, audit AuditHead, at)` already receives the
account it is anchoring for for its own `bedrock.Log` — it was calling
`audit.Head(ctx)` (unscoped) only because `audit.Log` had nothing scoped to
offer. The interface's `Head(ctx) (uint64, string, error)` method becomes
`AccountHead(ctx, accountID string) (uint64, string, error)`; `PrepareAnchor`
calls `audit.AccountHead(ctx, accountID)`. `VerifyFrom` is untouched — it
already takes an explicit `(anchorSeq, anchorHash)` and checks the whole
chain still contains it, which is correct and unaffected by which account's
entries happen to sit at those positions.

The same swap fixes a second, previously unnoticed instance of the
ADR-0033 leak while implementing this: `bedrock.Scheduler.Tick`
(`scheduler.go`) itself called `s.Audit.Head(ctx)` to decide `AnchorDue` —
meaning the automated per-account anchor scheduler was deciding whether
*this* account's chain was due for anchoring based on the deployment-wide
audit sequence, so a busy account could trigger anchoring cadence for a
quiet one sharing the deployment. Moving that call to
`s.Audit.AccountHead(ctx, s.AccountID)` fixes it the same way.

### 5. Console handlers switch to the scoped reads

`auditList`, `auditHead`, `auditVerify`, and `bedrockAuditAnchorExport`
(`api/nodes.go`) switch their `ListFiltered`/`ListBefore`/`Head` calls to the
`*ForAccount`/`AccountHead` equivalents, scoped to
`nbcontext.GetUserAuthFromContext(ctx).AccountId`. `entries_since_anchor` is
computed via `CountSince(ctx, accountID, sinceSeq)` (`sinceSeq = 0` when
unanchored), a real per-account count rather than a subtraction over
deployment-wide sequence numbers. `Verify`/`auditVerify`'s "is the chain
intact" boolean and first-bad-sequence number stay whole-chain (see
Consequences — a small, accepted, named exception to per-account scoping).

### Alternatives rejected

- **Independent per-account hash chains** (composite `(AccountID, Seq)`
  primary key, `PrevHash` chaining only within one account's rows).
  Rejected for this pass: it is a larger, riskier rewrite of `Append`'s
  transaction and every existing chain invariant, for a property — isolated
  tamper-evidence per tenant — the actual problem in hand (a confidentiality
  leak in reads, and a leaked metric) does not need. ADR-0033 already
  reasoned that a single shared chain is *not* a security defect; nothing
  found while writing this ADR overturns that. Left as the documented
  escalation if that reasoning is ever rejected on review (see Reconsider
  if), matching ADR-0033's own deferral of exactly this question.
- **A sentinel/system `AccountID` for unattributable entries, designed
  now.** Rejected: no call site producing such an entry exists in the
  codebase today (checked, not assumed — see Context). Designing a
  placeholder for a case with zero current instances would be exactly the
  kind of speculative abstraction this project's engineering practice
  argues against elsewhere; the empty-string exclusion in Decision §1 is
  the smallest correct behavior until a real call site forces the
  question.
- **Require `AccountID` as an explicit `Append` parameter instead of reading
  it from context.** Rejected for consistency: `AddSink`/`ListSinks`/
  `RemoveSink` in the same file already use `accountFromContext`, and a
  second convention for the same package would be its own small
  inconsistency for no benefit.
- **Backfill existing rows' `AccountID` from `Actor` at migration time** (by
  looking up which account each historical `Actor` user ID belongs to).
  Rejected: `Actor` is documented as "a node handle, a user ID, or
  'system'" — not reliably a user ID at all, and a user's account
  membership can itself have changed since the entry was written, so the
  lookup would sometimes be wrong rather than merely incomplete. Simpler
  and more honest to leave pre-migration rows at `AccountID = ""` (excluded
  from every account's view, per Decision §1) and document it plainly (see
  Consequences) than to write a backfill that silently gets some rows
  wrong. Karst is pre-GA (issue #123 still open) with no shipped deployment
  whose audit history this decision discards.

---

## Consequences

### Positive

- Closes a real, live cross-tenant confidentiality leak: any deployment
  running more than one account today has zero account isolation on its
  audit listing/export endpoints. This is worse than ADR-0033's own framing
  ("a metadata leak... not a confidentiality... break") — the full entry
  content is exposed, not just a count — and this ADR treats it
  accordingly, ahead of and independent of any SaaS/billing milestone, the
  same priority ADR-0033 argued for its own aquifer fix.
  `entries_since_anchor` becomes an honest per-account number as a
  byproduct, closing the ADR-0033 gap.
- No change to the hash chain's cryptographic construction or existing
  verified invariants — `Verify`/`VerifyFrom`, and every existing anchor
  already committed by a live deployment, keep meaning exactly what they
  meant before.
- Additive at the type level: existing unscoped methods, tests, and callers
  keep compiling and passing unchanged; only the console-facing call sites
  move to the new scoped methods.

### Negative

- **`Verify`/`auditVerify` stay deliberately whole-chain**, so a console
  user who triggers a chain-verification failure elsewhere in the
  deployment can learn a bare sequence number (`first_bad_sequence`) that
  is not necessarily one of their own entries. This is a narrow, accepted
  exception: the alternative (scoping `Verify` itself per account) would
  reintroduce exactly the independent-chain rewrite rejected above, for a
  single integer's worth of cross-tenant signal that reveals no content.
- **Pre-migration rows have no `AccountID`** and, per Decision §1's
  exclusion rule, silently stop appearing in every account's scoped audit
  view on upgrade, with no backfill. Acceptable pre-GA (see Alternatives
  rejected) but this is the sentence a real upgrade runbook must say
  explicitly once one exists, not leave implicit.
- **`AccountHead`'s `seq` is not contiguous per account.** A caller that
  assumes two consecutive `AccountHead` calls differ by exactly the number
  of entries that account wrote in between would be wrong — the correct
  operation for that question is `CountSince`, not seq arithmetic. Worth a
  code comment at the call site, not a structural fix, since the whole
  point of keeping one global chain is that seq numbers are shared.

### Reconsider if

- A real call site needs to write an audit entry with no natural
  single-account owner (deployment-level IdP sync, startup/shutdown,
  cross-account config) — design its `AccountID` handling then, against
  the actual shape of that call site, rather than the placeholder rejected
  above.
- Independent per-tenant tamper-evidence (not just per-tenant reads) is
  ever a real requirement — e.g. a tenant that must be able to prove
  truncation of *only their own* history without relying on the shared
  chain's global guarantee. Design independent `(AccountID, Seq)` chains
  then; this ADR's Alternatives-rejected section is the starting point for
  that design, not a closed door.
- A pre-migration deployment's silently-dropped audit history (Consequences,
  above) becomes a real complaint from an operator upgrading a live
  deployment rather than a documented pre-GA gap — write the backfill this
  ADR declined to write, now against a real deployment's actual `Actor`
  data instead of a hypothetical one.
