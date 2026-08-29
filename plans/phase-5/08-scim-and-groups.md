# SCIM 2.0 provisioning and group sync

**PLAN.md §4.4 · W5–W8 · Go 2, with a Rust change in W6 that is not optional —
see §2.**

## 1. Scope

> **Re-baselined 2026-08-27.** Basic user, group, role, setup-key, and
> self-service device flows are available through the inherited management
> surface and the Karst portal. What remains is the promised SCIM 2.0 lifecycle
> and group synchronization, including a real IdP-backed first-account path and
> measured deprovisioning. Preserve the existing Auditor role's read-only
> Karst-control permission while adding lifecycle automation; do not collapse
> audit and administrator identities.

- SCIM 2.0 (RFC 7642/7643/7644) for user and group create, update, and
  deprovision.
- Group sync driving ACL `group:` membership automatically.
- Deprovisioning as a security control: "Removing a user in the IdP must expire
  their node keys and drop their sessions **within 60 seconds**. This gets its
  own integration test."

The first two are ordinary work. The third is the one that needs a design
change, and it is worth reading before the schedule.

## 2. The 60-second requirement cannot be met by the current architecture

> **Measured 2026-08-28, and the costing below is wrong.** §3's question is
> answered: removal from the netmap *does* tear an established session down —
> the survivor's roster loses the peer, its flow cache is cleared, and traffic
> stops. The problem is purely latency, and it is now a number rather than an
> argument: **48.9 seconds** on a settled node
> (`a_revoked_peer_loses_its_session_inside_the_deprovisioning_budget`), past
> the 30-second CI gate and inside the 60-second requirement only by where the
> sample landed in the poll interval.
>
> **The push is bigger than this section says.** "The stream is already
> bidirectional and already exists for exactly this reason" is true of the
> server and false of the node: `Connection::open` appears once in production
> code, inside `Client::sync`, and the connection is dropped when `sync`
> returns. A node opens a control connection per refresh and holds none in
> between, so there is nothing to push to. Before the select described below
> there is a persistent-connection lifecycle in `karstd` — reconnect, backoff,
> keepalive — and a wire change to tell a push from a response, because
> `Connection::request` would otherwise consume a push as its own answer. See
> FINDINGS.md 67 and 68; re-estimate before starting.

`bins/karstd/src/control.rs:55`:

```rust
/// A poll rather than a server push, for now. The request is cheap when nothing
/// has changed …
pub const REFRESH: Duration = Duration::from_secs(60);
```

And `service.go:115` runs a strict receive-then-send loop: the `Session` RPC is
bidirectional, but the server only ever speaks in reply.

So the deprovisioning chain is:

```
IdP disables user
  → SCIM PATCH arrives                          (IdP batch latency: seconds to minutes)
  → user disabled, node keys expired            (immediate)
  → netmap recomputed                           (immediate)
  → each peer notices                           (up to 60 s — the poll)
  → peer drops the session                      (does this happen at all? §3)
```

**The poll alone can consume the entire budget**, before the IdP's own latency
and before anything tears a session down. The requirement is not met today and
no amount of care in the SCIM handler will meet it.

Two ways out:

| Option | Cost | Verdict |
|---|---|---|
| Shorten `REFRESH` | One constant, and N× the request rate against the control server for every node in every account, forever | **No.** It trades a real scaling property for a worst case that is still not a bound |
| Server-initiated push on the existing stream | The stream is already bidirectional and already exists for exactly this reason. The server loop becomes a select over "a request arrived" and "this node's map changed"; the node's reader must accept an unsolicited envelope | **Yes** |

ADR-0009's revised estimate already contemplates "new delta-push work". This is
that work, and Phase 5 is where it becomes load-bearing rather than an
optimisation. **Budget one week of Go and half a week of Rust in W6**, and
treat it as a dependency of the deprovisioning test rather than as a nice
improvement to netmap freshness.

Keep the 60-second poll as the floor. Push is an accelerator, not a
replacement: a node whose stream dropped must still converge, and a node that
missed a push must not stay stale forever.

## 3. Does a node actually drop a session when a peer disappears?

Unverified, and it decides whether §2's work is sufficient. Check in W5, before
building anything: when a peer is removed from the netmap, does
`bins/karstd/src/netmap.rs`'s projection tear down the established PHREATIC
session in `engine.rs`, or does it only stop refreshing it?

If the session survives its peer's removal from the map, the deprovisioning
requirement is unmeetable regardless of how fast the netmap arrives, and the
fix is in the datapath: removal from the projection must close the session,
drop the filter entries, and stop the keepalive.

**Write the failing test first.** A netns test where a peer is removed and the
established TCP connection between the two is expected to die is three hours of
work and tells you exactly which of the two problems you have.

## 4. SCIM surface

`/scim/v2/` mounted on the same router, with its own authentication.

| Endpoint | Methods |
|---|---|
| `/scim/v2/Users` | `GET` (filter, pagination), `POST` |
| `/scim/v2/Users/{id}` | `GET`, `PUT`, `PATCH`, `DELETE` |
| `/scim/v2/Groups` | `GET`, `POST` |
| `/scim/v2/Groups/{id}` | `GET`, `PUT`, `PATCH`, `DELETE` |
| `/scim/v2/ServiceProviderConfig` | `GET` |
| `/scim/v2/ResourceTypes`, `/scim/v2/Schemas` | `GET` |

The last three are discovery documents. Okta and Entra ID both fetch them and
both behave differently based on what they say, so they are not optional
decoration — declare exactly the capabilities that are implemented, especially
`patch`, `filter`, `bulk: false`, and `sort`.

**Authentication is a bearer token, not a user JWT.** Generated in the console
(Settings), shown once, hashed at rest, rotatable, and scoped to provisioning
only — it must not be usable against `/api/`. Log every SCIM request to the
audit log with the token's identifier.

### 4.1 Details that decide whether real IdPs work

- **`externalId` is the join key, not email.** People change their email
  address; a provisioning integration keyed on email renames a user into a new
  account and orphans their devices. Store `externalId`, index it, and use it
  for every lookup.
- **Filtering.** Both Okta and Entra probe with
  `filter=userName eq "..."` before creating. Implement `eq` on `userName`,
  `externalId`, and `displayName`; return `501` for operators that are not
  implemented rather than silently returning everything, which is how a
  provisioning run deletes a directory.
- **`PATCH` is the hard part.** RFC 7644 §3.5.2 path expressions —
  `members[value eq "x"]` — are what Entra uses for group membership deltas.
  Implement `add`, `remove`, and `replace` on `members` and on `active`.
  Everything else can 501.
- **Pagination** with `startIndex` (1-based, not 0) and `count`. Getting the
  base wrong is a classic and presents as a silently skipped first user.
- **Soft delete.** `active: false` is deprovisioning; `DELETE` is rarer and
  should do the same thing plus tombstone. Never hard-delete a user record
  that node history references — the audit log must still be able to name who
  owned a device.
- **Idempotency.** IdPs retry. Creating a user that exists returns `409` with
  the existing resource, not a duplicate.

## 5. Group sync into ACLs

Groups arriving over SCIM populate the same group store the policy compiler
reads for `group:` terms. Three rules:

1. **A group referenced by the policy but absent from the directory is an
   error, not an empty set.** An empty set silently opens or closes access
   depending on whether the rule is an allow or a deny, and neither is what the
   admin meant. Surface it as a policy lint warning in the console and keep
   the last known membership until it is resolved.
2. **Renaming a group in the IdP must not break the policy.** Bind by
   `externalId`, display the name.
3. **A membership change must move the netmap version.** The compiled filter
   depends on group membership, so `netmap_version` must too, or a node keeps
   an out-of-date filter and the server tells it nothing has changed. Verify
   this: the version hash covers filter *rules* (`karst-control-v1.md` §5.5),
   so if membership changes the compiled rules the version moves for free —
   but confirm it with a test rather than with a reading, because the case
   where membership changes and the compiled rules happen to be identical is
   exactly the case where nothing needed to happen anyway.

Nested groups: Okta flattens, Entra does not send them at all. Do not
implement nesting. Document that membership is flat and let the IdP flatten.

## 6. Interop testing

A SCIM implementation that passes its own tests and fails against Okta is
worth nothing. Both of the two IdPs that matter offer free developer tenants.

| Test | How |
|---|---|
| Okta end to end | Developer tenant, a real SCIM app integration, run Okta's own "Test Configuration" and its provisioning checks |
| Entra ID end to end | Free tenant, a non-gallery app with the provisioning agent pointed at a tunnel to a dev server |
| Spec conformance | An off-the-shelf SCIM compliance suite in CI against a test server, so regressions surface without a tenant |
| Deprovision timing | §7 |

Record which IdP versions were tested and when, in the docs. "SCIM 2.0
supported" is a claim an evaluator will test in their own tenant on day one.

## 7. The deprovisioning test

The named integration test from §4.4, and the phase's most valuable single
test:

1. Bring up the compose stack, three nodes, an ACL that lets them talk.
2. Establish a TCP connection between node A (owned by the user) and node B.
3. `PATCH /scim/v2/Users/{id}` with `active: false`, and start a stopwatch.
4. Assert, within 60 seconds: the user's node keys are expired; node B's
   netmap no longer contains A; the TCP connection is dead; A cannot
   re-establish; the audit log records the deprovisioning with the SCIM token
   identity.
5. Record the elapsed time in the test output, and **fail the test if it
   exceeds 30 seconds**, not 60. A test that passes at 59 seconds is a test
   that will fail in production on a slow day.

Put it in the privileged suite next to the aquifer tests, which already stand
up whole topologies ending in a TCP conversation under an ACL — this is that
harness with a revocation in the middle.

## 8. Schedule

| Week | Work |
|---|---|
| W5 | §3 investigation; SCIM schema, discovery documents, token auth |
| W6 | Users and Groups CRUD, filter, PATCH; **push on the control stream** (Go 1 and Rust 1 pair) |
| W7 | Group sync into the policy compiler; console Settings surface for the token |
| W8 | Okta and Entra interop; deprovisioning test; docs |

## 9. Exit criteria

1. Okta and Entra ID both provision, update, and deprovision users and groups
   against a running server, verified in real tenants.
2. Disabling a user in the IdP kills their live sessions in under 30 seconds,
   measured by a test in the privileged suite.
3. Group membership from the IdP drives `group:` terms in the ACL, and a
   membership change reaches every node's filter.
4. The SCIM token cannot call `/api/`, asserted by a test.
5. Every SCIM mutation appears in the audit log.
