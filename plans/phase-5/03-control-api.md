# The control API the console consumes

**Not named in PLAN.md's Phase 5 block · W1–W6 · Go 1, with Go 2 from W3.**

## 1. Why this file exists

> **Re-baselined 2026-08-27.** The Karst administrative and `/me` portal API
> surface exists, including nodes, policy, relays, posture, audit, Bedrock
> status/mode, and self-service devices. Bedrock export/import, audit JSON/CSV
> export, durable webhook/TLS-syslog delivery, and the offline audit-anchor
> ceremony are implemented. Auditor read-only access is implemented and covered
> by the role matrix.
>
> **Real-server coverage landed 2026-08-28.** Every mutating console route is
> now driven against the real account manager, the real permissions manager and
> the real Karst stores — as an administrator, who must never be refused, and
> as a member of the same account, who must always be. The table is checked
> against the router itself, so a route added later without coverage fails
> `TestEveryMutatingConsoleRouteHasRealServerCoverage` rather than shipping
> unexercised. Writing it found FINDINGS.md 66: an export that answered a
> missing precondition with a 500 where its sibling answered 412, invisible to
> the handler tests because their double cannot produce the error.

The following coverage table is the original gap analysis, retained as a record
of why the namespace exists; it is superseded by the re-baseline above.

PLAN.md §8 specifies eleven admin views and a "generated OpenAPI client"
without saying what generates it. The fork ships an OpenAPI document — 14 373
lines of it, `server/shared/management/http/api/openapi.yml` — describing
NetBird's object model. **Six of the eleven views have no endpoint behind them,
and three more need fields the fork's objects do not carry.**

This is the critical path for two frontend engineers for eight weeks. It is the
largest unlisted dependency in the phase and it starts in W1.

## 2. Coverage of §8.1, view by view

| View | Backing API today | Gap |
|---|---|---|
| Machines | `/api/peers`, `/api/peers/{id}` | **Karst node state is not in the peer object**: no PSK epoch, no negotiated suite, no direct-vs-relay path, no relay assignment, no Bedrock coverage. Node facts live in `karst/node.Store`, which the REST layer has never seen |
| Users | `/api/users` and friends — invites, tokens, approve/reject | Adequate. Add per-user device list joined from Karst nodes |
| Groups | `/api/groups` | Adequate; needs the ACL cross-reference in §5 |
| Access controls | `/api/policies` | **Wrong model.** The fork's policies are structured rules; Karst's are a HuJSON document compiled by `karst/policy`. Needs a document-oriented endpoint with validate, diff, version, rollback |
| Auth keys | `/api/setup-keys` | Adequate |
| DNS | `/api/dns/nameservers`, `/api/dns/settings` | Mostly adequate; needs split-DNS routes and the MagicDNS toggle from [01](01-karstdns.md) §4.1 |
| Relays | — | **Net new.** `karst/relayreg` loads an operator-written file at startup and validates it fatally. No API, no health, no onboarding |
| Bedrock | — | **Net new.** [02](02-bedrock.md) |
| Crypto posture | — | **Net new**, and PLAN.md §8.1 calls it "a differentiating feature, not a nicety" |
| Audit log | `/api/events` | Different log. `karst/audit` is the hash-chained one; the fork's events table is not it. Needs chain verification and head export |
| Settings | `/api/accounts/{id}`, IdP config | Adequate; add SCIM token from [08](08-scim-and-groups.md) |

## 3. Where the new surface lives

**A separate `/api/karst/v1/` namespace on the same router, behind the same
auth middleware.** Not new fields bolted onto the fork's objects.

ADR-0009 settled fork-and-diverge over fork-and-track, so merge conflicts are
not the argument. The argument is the *other* half of ADR-0009: "we offer our
own contributions upstream under BSD-3 … PQ-specific work is ours and stays
ours", recorded there as an obligation rather than an aspiration. A clean path
boundary makes that boundary mechanical — everything under `/api/karst/` is
ours and AGPL, everything else is a fork change that might be offered back.
A `crypto_posture` field grafted onto NetBird's `Peer` schema makes it a
judgement call in every future review.

Mechanically:

- `server/management/internals/karst/api/` — handlers, one file per resource,
  following the shape of `modules/agentnetwork/handlers/` which already does
  `RegisterEndpoints(manager, router)` against the same `mux.Router`.
- Registered from `http/handler.go:NewAPIHandler`, after the existing
  registrations, so it inherits `metricsMiddleware`, `corsMiddleware`, and
  `authMiddleware` without a second auth path. **Do not build a second auth
  path.** A separate namespace with its own token handling is how an
  authorisation bypass ships.
- `server/shared/management/http/api/karst-openapi.yml` — our own document,
  generated into Go types by the same `oapi-codegen` config the fork uses
  (`api/cfg.yaml`) and into a TypeScript client for the console.

## 4. The contract freeze

**End of W2, the OpenAPI document is frozen and a mock server serves it.**
Implementation continues for four more weeks behind it; the frontend builds
against the mock from W3.

Concretely, by Friday of W2:

- `karst-openapi.yml` describes every endpoint in §5, with response schemas,
  error shapes, and pagination.
- `just api-mock` runs Prism (or `oapi-codegen`'s server stub with fixtures) on
  a local port serving realistic example payloads — a fifty-node account, two
  relays, a Bedrock chain, mixed crypto posture, an audit log with a break in
  it. **Fixtures with interesting data, not empty arrays.** A console built
  against three tidy peers looks fine and falls apart on the first real
  account.
- The generated TypeScript client is committed to `web/packages/api-client/`
  and regenerating it is a CI check that fails on drift.

Changes after the freeze go through an amendment noted in this file's changelog
section, agreed with both frontend engineers. Not a process for its own sake —
a silently changed response shape costs the frontend a day to diagnose and the
backend five minutes to have avoided.

## 5. Endpoints

Sketch, not a specification; the specification is the YAML.

### 5.1 Nodes — `/api/karst/v1/nodes`

The join the console needs and nothing today provides: the fork's `Peer`
record, plus `karst/node.Store` state, plus live session facts.

```
GET    /nodes                      list, filterable by tag, user, posture, coverage
GET    /nodes/{handle}             detail
PATCH  /nodes/{handle}             rename, tag, set expiry, disable
DELETE /nodes/{handle}             deprovision
GET    /nodes/{handle}/paths       current path per peer: direct|relay, endpoint, since
GET    /nodes/{handle}/posture     negotiated suite, PSK epoch, lattice-only flag
```

`paths` and `posture` are the interesting ones, because **the server does not
know either.** The control plane distributes keys; it does not observe
sessions. Both come from the node's own report.

Phase 4 already built the channel for exactly this: `netmap.go`'s handler
records "§9.1's report, from the node that measured it" — the node's relay
observation — and refuses a malformed one rather than ignoring it. Extend that
report with the session facts the console needs, store them on the node record
with an observation timestamp, and **render them in the console as "as of
14:32", never as current truth.** A node that has been offline for a day should
show its last known posture greyed out with the age, not a stale green dot.

### 5.2 Policy — `/api/karst/v1/policy`

```
GET    /policy                     current document, version, author, timestamp
GET    /policy/versions            history
GET    /policy/versions/{v}        one version
POST   /policy/validate            parse + lint, no write — returns diagnostics with line/column
POST   /policy/preview             compile against the current netmap; returns flows added/removed
PUT    /policy                     write, with If-Match on the current version
POST   /policy/rollback/{v}        write an old version forward as a new one
POST   /policy/test                run the policy unit tests in the document
```

`preview` is the one that makes the HuJSON editor worth using and it is not
hard: `karst/policy` already compiles a document to a per-node filter for the
netmap. Compile the current document and the proposed one for every node,
diff the rule sets, and return the delta as flows. **Budget a week for it
anyway** — the diff is cheap and presenting it in terms an admin recognises
("`group:sre` loses `tag:prod:22`", not "rule 7 changed") is not.

`validate` must return line and column. A HuJSON editor with schema-aware
autocomplete and inline lint is specified in §8.1, and inline lint means the
server tells the editor *where*.

### 5.3 Relays — `/api/karst/v1/relays`

```
GET    /relays                     registry with health and region
POST   /relays                     onboard: address, identity key, region
DELETE /relays/{id}
GET    /relays/{id}/health         last seen, sessions, bytes, admission state
```

Today the registry is a file read at startup and validated fatally
(`karst/relayreg`), because `karstd` fails an entire netmap over one bad entry.
Moving it into the database is a small change with one sharp edge: **the fatal
validation must survive the move.** An API that accepts a relay entry with a
malformed identity key and puts it in the netmap breaks every node in the
account at once. Validate on write, with the same code path, and return 422.

`relay_id` stays derived from the pinned key rather than typed by the admin —
Phase 4 made that choice deliberately and the API must not undo it by
accepting an `id` field.

Health comes from the relay itself. Phase 4 built the roster producer that
rewrites the admission file every 25 s; the reverse direction — relays
reporting to the control server — does not exist. Either add a small
authenticated report endpoint, or derive health from the roster's mtime and
label it as such in the UI. **Prefer the second for Phase 5**: it needs no new
protocol and the console can honestly say "last confirmed 25 s ago".

### 5.4 Bedrock — `/api/karst/v1/bedrock`

```
GET    /bedrock                    mode, quorum config, root and authority inventory
GET    /bedrock/log                entries, paginated, with verification status
GET    /bedrock/log/verify         re-verify the chain server-side; returns head + result
GET    /bedrock/requests           pending signing requests
POST   /bedrock/requests/export    bundle for the offline signer
POST   /bedrock/responses/import   signed bundle back in
PUT    /bedrock/mode               off | advisory | enforcing
```

`PUT /bedrock/mode` to `enforcing` **requires a body listing the handles the
caller acknowledges will be cut off**, and 409s if that list does not match the
server's. [02](02-bedrock.md) §7 explains why; the API is where it is enforced,
because the console is not the only thing that will ever call it.

### 5.5 Crypto posture — `/api/karst/v1/posture`

```
GET /posture                       aggregate: PQ coverage %, suite histogram, flagged sessions
GET /posture/sessions              per-session rows, filterable
```

The aggregate answers the question the whole product exists to answer, and it
must be **defensible to an auditor**, which means every number needs a
denominator and an as-of time. "PQ coverage 98%" is a claim; "247 of 252
sessions observed in the last 5 minutes negotiated ML-KEM-768 + X25519; 5
sessions from 2 nodes are lattice-only (no PSK); 3 nodes have not reported in
over an hour and are excluded" is evidence. Design the response shape to make
the honest version the easy one to render.

The **lattice-only (PSK-absent) indicator** from §2.6 is a first-class field,
not a derived one. A session with no per-pair PSK has lost the
assumption-diversity hedge ADR-0001 bought deliberately, and an operator should
be able to filter for exactly that.

### 5.6 Audit — `/api/karst/v1/audit`

```
GET  /audit                        filterable, paginated
GET  /audit/export?format=json|csv
GET  /audit/head                   current head hash and sequence
GET  /audit/verify                 chain verification result, with the first bad sequence
POST /audit/sinks                  webhook / syslog configuration
```

`audit.go` is candid that a hash chain does not detect tail truncation and that
the mitigation is an external anchor. So the console must **show the anchor
state**: last anchored sequence, last anchored time, and how many entries have
accrued since. An audit view that shows a green "chain verified" tick while
nothing has been anchored for three weeks is worse than no tick, because it
claims a property the construction does not have.

**Implemented ceremony.** The audit log now records successful Karst mutations,
queues a durable delivery for every configured webhook or TLS-syslog sink, and
retries failed delivery from a bootstrap worker. An administrator anchors the
chain without giving the server an authority key:

1. In the console's Bedrock view, choose **Create and export audit-anchor
   request**.
2. Move the downloaded request to an authority machine and run
   `karst-bedrock sign REQUEST AUTHORITY_KEY RESPONSE`; inspect the rendered
   audit sequence and hash, then type `sign` to confirm.
3. Return only `RESPONSE` and use **Import signed response** in the console.
4. Use **Verify chain** in the Audit view. The imported Bedrock anchor makes
   tail truncation at or before its committed sequence detectable.

The API test performs this exact prepare → authority-sign → import →
`VerifyAnchored` flow. Automation remains deliberately out of scope: a server
authority able to sign anchors could also countersign nodes unless a future,
capability-scoped authority design is adopted.

## 6. Authorisation

PLAN.md §4.4 specifies six roles — Owner, Admin, Network Admin, IT Admin,
Auditor, Member — "enforced by a central authorization middleware with a
table-driven permission matrix that is unit-tested exhaustively".

The fork has a `permissions.Manager` in the middleware chain already. Extend
its table rather than writing a second one, and add the exhaustive test the
plan asks for: **a table of (role × endpoint × method) with an expected
allow/deny, generated from the route table so a new endpoint with no entry
fails the test rather than defaulting to allow.** That last property is the
whole value of the test; a matrix that must be updated by hand is a matrix that
silently omits the endpoint added on a Friday.

Auditor is the role most likely to be got wrong: read-only must include the
audit log and the crypto posture, and must exclude anything that would let a
read-only user learn a PSK or a setup key. Grep the response schemas for secret
material before wiring the role.

## 7. What must not appear in any response

The control channel exists (ADR-0011) because a netmap in plaintext hands every
per-pair PSK to whatever terminates TLS. The REST API is exactly that
plaintext boundary. So:

- **No PSKs, no disco keys, no node private material, ever.** Not redacted —
  absent from the struct.
- Setup keys are returned once, at creation, and never again.
- `leakscan.rs`'s discipline applies here too. Add a Go test that walks every
  registered route, requests it against a seeded fixture account as each role,
  and greps the responses for the fixture's known-secret byte patterns.
  Phase 3 did the equivalent scan for logs and traces; the REST surface is a
  new mouth and deserves the same gag.

## 8. Work breakdown

| # | Item | Weeks |
|---|---|---|
| 8.1 | Endpoint inventory against §8.1, agreed with frontend | W1 |
| 8.2 | `karst-openapi.yml` complete, generated Go types and TS client | W1–W2 |
| 8.3 | Mock server + interesting fixtures, `just api-mock` | W2 |
| 8.4 | **Contract freeze** | end W2 |
| 8.5 | Nodes, including the extended node report from `karstd` | W3–W4 |
| 8.6 | Policy: validate, preview, versions, rollback | W3–W4 |
| 8.7 | Relays out of the file and into the store | W4 |
| 8.8 | Posture aggregate and sessions | W4–W5 |
| 8.9 | Audit, verification, export, sinks | W5 |
| 8.10 | Bedrock endpoints | W5–W6 |
| 8.11 | Role matrix + exhaustive generated test | W5–W6 |
| 8.12 | Secret-leak scan over every route × role | W6 |

## 9. Exit criteria

1. Every view in §8.1 has an endpoint, and the console's generated client is
   built from a document that CI checks for drift.
2. The role matrix test enumerates routes from the router, so an unlisted
   endpoint fails the build.
3. No response, under any role, contains a PSK, a disco key, or a setup key
   after creation — asserted by a scan, not by review.
4. `POST /policy/preview` returns the flow-level diff for a fifty-node fixture
   in under a second.
5. Moving Bedrock to `enforcing` with an out-of-date acknowledgement list
   returns 409.
