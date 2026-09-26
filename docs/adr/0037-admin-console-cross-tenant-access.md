<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-0037: Operator-granted cross-tenant account access

- **Status:** Accepted
- **Date:** 2026-09-26
- **Deciders:** TBD
- **Related:** #166 (multi-tenant SaaS, this ADR's tracking issue — the last
  of its three deferred sub-items: relay aquifer scoping shipped as #171,
  Bedrock scheduler fleet as #173, audit-log partitioning as #172/ADR-0035),
  ADR-0033 §3 ("Admin-console cross-tenant surfaces... deferred to
  implementation/console work; nothing here blocks or requires a particular
  console shape" — this is that implementation work), ADR-0009/Spike 0001
  (fork-and-diverge, not fork-and-track — cited below since this decision
  turns on it directly)

---

## Context

#166's own scope list named two different things under one bullet:
"account switching, cross-tenant admin views." Checked directly against the
tree before designing anything, because they turned out to need different,
not-equally-sized answers.

### The schema is a hard 1:1 identity-to-account mapping, not a membership table

`server/management/server/types/user.go`: `User.Id` (the IdP-subject-derived
identity) is the sole GORM primary key, with one plain `AccountID` field —
not a composite key, not a join table. `DefaultAccountManager.GetAccountIDByUserID`
(`server/management/server/account.go:948`) resolves a JWT's `UserId` to
exactly one account, creating one if none exists. There is no
`memberships`/`user_accounts` table anywhere in the tree (grepped for it).
**One IdP identity cannot be a first-class member of more than one account
today.** Building that — the same person switching between two accounts
they both legitimately belong to — means changing what `User.Id` *is* (a
per-account row keyed by identity, not identity-as-primary-key), which
touches the primary authentication path (`auth_middleware.go`,
`GetAccountIDByUserID`, every handler that assumes "the caller's account" is
a single unambiguous fact). That is a materially bigger, more security-
sensitive change than a console feature, and is **out of scope here** — see
Alternatives rejected.

### A different, already-half-built mechanism exists for the other half: operator-granted viewing

`server/management/server/http/middleware/auth_middleware.go:127-131` (and
`:213-215`) already reads a client-supplied `?account=` query parameter and,
if `isValidChildAccount(ctx, userID, homeAccountID, requestedAccountID)`
returns true, overrides `userAuth.AccountId` for that request and sets
`IsChild = true`. This is upstream NetBird's own MSP-style parent/child-
account impersonation feature. In this fork it is wired but inert:
`server/management/internals/server/modules.go`'s `BaseServer.IsValidChildAccount`
unconditionally `return false`s, so the query parameter cannot be used to
reach any account other than the caller's own today — confirmed by reading
the one call site, not assumed from the parameter's existence.

This is the right shape for "cross-tenant admin views": an operator (or any
account's own user) with an explicit, separately-granted reason to look at
a *different* account, without becoming a first-class member of it and
without touching the User/Account primary-key model at all.

### Modifying `modules.go`/`account.go`-adjacent files is on-policy here, not a deviation from it

`bootstrap.go`'s and `karst-control/main.go`'s doc comments describe "no
forked file modified" for the *control-channel gRPC attachment*
specifically (ADR-0011) — the one integration Spike 0001 measured at 28%
upstream-commit overlap and picked fork-and-diverge over fork-and-track
partly to isolate. That is not a blanket rule: `server/management/server/account.go`,
`peer.go`, and every file under `server/management/server/permissions/roles/`
already carry `karst`-specific changes directly, unrelated to the gRPC
seam. ADR-0009's actual recommendation is "fork-and-diverge, not
fork-and-track" — accepting ongoing, deliberate divergence where a feature
needs it. `IsValidChildAccount`'s existing shape (an injected
`IsValidChildAccountFunc` parameter threaded from `NewAPIHandler` down to
`NewAuthMiddleware`, sourced today from one hardcoded stub method) reads
like exactly the extension point this ADR needs, not a file to route
around.

## Decision

Add a narrow, explicit, operator-controlled grant: a user may view a
different account only if a grant naming that exact (user, account) pair
exists. No self-service granting in this pass — see Alternatives rejected.

1. **New karst-owned store**, `server/management/internals/karst/tenancy`:
   one table (`karst_tenancy_grants`, composite key `user_id`+`account_id`),
   `HasAccess(ctx, userID, accountID) (bool, error)` and
   `AccessibleAccounts(ctx, userID) ([]string, error)`. Same shape and same
   package-per-concern convention as `turncred`/`relayreg`/`bedrock`.
2. **Grants are declarative, file-loaded, operator-only.** A new optional
   `KARST_TENANCY_GRANTS_FILE` (parsed the same way `loadRelays`/`loadTurn`
   already parse their own JSON documents, `DisallowUnknownFields` included)
   is loaded once at boot in `karst-control/main.go` and reconciled into the
   table on every start — added grants appear, removed ones are revoked,
   matching the declarative-config convention `KARST_AQUIFER`/the relay and
   TURN registries already use. No new file, no grants — fully inert by
   default, same as every other optional `KARST_*` knob. No new HTTP
   endpoint for creating a grant exists in this pass; an operator who wants
   self-service grant management gets that as its own, separate,
   deliberately smaller follow-up once this shape has seen real use.
3. **`BaseServer.IsValidChildAccount` is implemented for real** against this
   store (`server/management/internals/server/modules.go`), replacing the
   `return false` stub. This is the one, narrow, deliberate fork divergence
   this ADR makes — a two-method change to a file this project already
   diverges in elsewhere (see Context).
4. **A read-only karst API endpoint**, `GET /karst/v1/tenancy/accounts`,
   returns the calling identity's own granted account IDs (never anyone
   else's), so the console can decide whether to show a switcher at all
   without every user needing to know their own grants exist out of band.
5. **Console**: the header's already-present (but previously hardcoded
   "Karst") account line becomes a real account id, and — only when
   `GET /karst/v1/tenancy/accounts` returns at least one entry — a `<select>`
   that appends `?account=<id>` to every subsequent API call (both
   `/api/karst/v1` and the fork's own `/api`, since both ride the same
   shared auth middleware) by way of a client-side override, cleared to
   return to the caller's own account. The server, not the client, is what
   actually enforces which accounts a given override may reach — the
   client-side `?account=` value is exactly as trustworthy as the request's
   JWT, no more.

### Alternatives rejected

- **Design real multi-account membership now** (same identity holding
  first-class membership in more than one account, an actual switcher
  between "homes" rather than a granted look-elsewhere). Rejected for this
  pass: it requires changing what `User.Id`'s primary-key semantics mean
  across the entire auth path, which is a materially larger and more
  security-sensitive change than #166 asked for under this bullet, and
  nothing in #166 or ADR-0033 required solving it — the "cross-tenant admin
  views" half of the same bullet is satisfiable without it. Recorded as its
  own future ADR if a real business need for it (as opposed to an
  operator/support view) shows up — see Reconsider if.
- **A self-service grant-management UI/API in the same pass.** Rejected:
  deciding who is *allowed to grant* cross-tenant access is its own
  permission-model question (a platform-operator role? account-owner
  delegation? both?) that #166/ADR-0033 never scoped, and guessing at one
  here risks shipping the wrong shape before it has a real user. The
  file-loaded, operator-only mechanism above is deliberately the smallest
  thing that makes the enforcement path real and testable; a grant-
  management surface is a legitimate, separate follow-up once this shape
  has been used for real.
- **Resurrecting NetBird's own parent/child MSP semantics wholesale**
  (declared parent accounts, cascading child relationships). Rejected:
  that models a business relationship between accounts this project has no
  concept of; this ADR reuses only the mechanical shape of the existing
  `?account=`/`IsValidChildAccount` seam, not NetBird's MSP data model.
- **Billing/plan enforcement, relay per-tenant capacity fairness.**
  Unchanged from ADR-0033 §3 — still out of scope, still real, separately
  tracked.

---

## Consequences

### Positive

- Closes the last open item under #166 with a real, enforced mechanism —
  not a UI-only affordance — while leaving the harder, larger
  same-identity-multiple-accounts question untouched and honestly deferred.
- Reuses an upstream-provided seam (`IsValidChildAccountFunc`) exactly as
  its shape suggests, rather than inventing a parallel account-scoping
  mechanism alongside it.
- Fully inert with no configuration: no `KARST_TENANCY_GRANTS_FILE`, no
  grants, `IsValidChildAccount` still effectively always false, zero
  behavior change for every deployment that does not opt in.

### Negative

- **Grants are boot-time declarative, not live.** Changing
  `KARST_TENANCY_GRANTS_FILE` requires a restart to take effect, same
  operational shape as the relay/TURN registries. Acceptable for an
  operator-only, infrequent action; would need revisiting if this ever
  becomes self-service (see Alternatives rejected).
- **No account display metadata in the v1 switcher.** The console lists
  granted account IDs, not names/domains — an intentional simplification
  to avoid adding a new cross-account account-metadata lookup path in this
  pass. A real, honest gap, not a hidden one: worth a follow-up once this
  ships.
- **The client-supplied `?account=` value is not itself trusted** — this
  ADR does not change that upstream contract, it only makes
  `IsValidChildAccount` a real check instead of an always-false one. A
  granted account outside the caller's home account is exactly as
  reachable as this table says and no further; getting that table wrong
  (over-broad grants) is the actual risk surface this feature introduces,
  not the query parameter itself.

### Reconsider if

Same-identity multi-account membership becomes a real, requested feature
(as opposed to operator/support cross-tenant viewing) — that is a distinct,
larger design this ADR deliberately does not attempt, and deserves its own
ADR against `User`'s primary-key model rather than an amendment here.
