<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Control API change set — review findings

Reviewed 2026-08-22 against the staged change set on `main` at `e52fd09`
(99 files, +6,027/−242). The change set implements
[`plans/phase-5/03-control-api.md`](plans/phase-5/03-control-api.md): the
`/api/karst/v1` surface, four new persistence stores, node session reporting on
the control channel, the OpenAPI contract, and a generated TypeScript client.

**Verified by running**, not by reading alone: `cargo check --workspace
--all-targets`, `cargo clippy --workspace --all-targets --all-features -D
warnings`, `cargo fmt --all --check`, `go build ./...`, `go vet
./management/internals/karst/...`, `go test ./management/internals/karst/...
./management/server/permissions/...`, and the CI licence gate's own `find`
expression.

Clippy is clean and every Go test passes. Two CI gates fail. Thirty-five other
issues follow, ranked.

---

## Blocking — CI is red

### 1. `cargo fmt --check` fails

Three hunks in `bins/karstd/src/run.rs`:

| Line | Problem |
|---|---|
| 24 | `use karst_control_client::transport::pb;` is ordered after `karst_disco` |
| 2209 | `let peer = client.netmap().peers().find(…)?;` exceeds the width |
| 2218 | the `endpoint:` field expression exceeds the width |

`just check` and the CI fmt job both fail. Minutes of work.

### 2. Missing SPDX header on a CI-checked generated file

`server/shared/management/http/api/karst/types.gen.go` has no
`SPDX-License-Identifier`. CI's licence gate matches

```
find server -type f -name '*.go' \( -path '*/karst/*' -o -name 'karst_*' \) -not -name '*.pb.go'
```

and this file is under `*/karst/*` and is not a `.pb.go`. It is the only file
in that set without a header. `generate-karst.sh` does not add one either, so
regenerating will not fix it — contrast `web/packages/api-client/scripts/generate.mjs`,
which post-processes the TypeScript output to insert exactly this header.

---

## High — correctness

### 3. The negotiated suite is a hardcoded string

`bins/karstd/src/run.rs:2223` sends `suite: "ML-KEM-768 + X25519".to_owned()`.

The crypto-posture view exists to prove the PQ claim per-session to an auditor
and to flag **downgraded** sessions. A constant reports the good value
unconditionally and can never show a downgrade, so the `suites` histogram in
`/posture` is decorative rather than evidential.

`engine::PeerStatus` does not carry the negotiated suite today, so the fix is a
datapath field, not a string change.

### 4. Telemetry can deny a netmap

`server/management/internals/karst/control/netmap.go:113` maps **any**
`ReplaceSessionObservations` failure to `codes.InvalidArgument` and returns, so
the node receives no netmap at all.

Two problems in one: a server-side database error (lock contention, disk,
constraint) is misreported as a client error, and an advisory observation write
is escalated into loss of connectivity for that node. An observation write
should never sit on the netmap's success path — log it and continue.

### 5. Peers with no DNS label are silently dropped from posture

`bins/karstd/src/run.rs:2210` joins observations to netmap peers on
`peer.dns_name == status.name`. But `bins/karstd/src/config.rs:837` names a
peer with no DNS label `node-<first 8 chars of handle>`, so those never match
and are dropped by `filter_map` with no counter and no log line. The `/posture`
denominator quietly shrinks by however many label-less peers exist.

`PeerStatus` exposes no `node_id`, which is why the join runs through a display
name; that is the thing to fix.

### 6. `unreachable` violates the published contract

`node.go` accepts `direct | relay | unreachable` and `getNodePaths` passes
`observation.Path` straight into `kind`, but `karst-openapi.yml:328` declares

```yaml
kind: {type: string, enum: [direct, relay]}
```

and the generated client is `enum kind { DIRECT, RELAY }`. Any node with an
unreachable peer emits a response its own generated client cannot type.

### 7. `GET /audit` omits the required `anchor`

`AuditPage` requires `[items, anchor]` (`karst-openapi.yml:419`); `auditList`
returns only `items` and `next_cursor`.

The anchor is what makes the tamper-evidence claim honest. `audit.go`'s own
package documentation says a hash chain cannot detect tail truncation and that
the mitigation is an external anchor. A console rendering "chain verified" with
no anchor state claims a property the construction does not have.

### 8. `NodePaths.observed_at` can be null against a non-nullable required field

The schema marks it required with no `nullable: true`. `getNodePaths` leaves
`observedAt` as a nil `*time.Time` when a node has no observations, which
marshals to `null`.

### 9. `posture` and `coverage` query filters are declared and ignored

`/nodes` documents both parameters; `listNodes` implements only `user` and
`tag`. A request for `?posture=lattice_only` returns **every** node.

The code guards precisely this hazard for `tag`, with a comment saying so:

> Tags have no Karst-owned persistence yet. An explicit tag filter must not
> silently broaden into an all-nodes response, which would mislead callers.

and then does not apply its own rule to the two parameters immediately
alongside it.

### 10. The node list always reports `posture: unknown`

`toNodeResponse` hardcodes `nodePosture{Status: "unknown"}` while
`/nodes/{handle}/posture` computes real posture from the same store. The
comment justifying it —

> nodePosture is intentionally unknown until the authenticated node report is
> extended with negotiated session facts

— is stale: this change set *is* that extension.

### 11. Bedrock, policy, relays and audit sinks are global, not account-scoped

`bedrock.Configuration` is a singleton row (`ID: 1`). `policy.Version`,
`relayreg.StoredRelay` and `audit.Sink` have no account column.
`bedrockStatus` and `bedrockMode` call `h.nodes.All()` across every account.

In a multi-account deployment, one account's admin rewrites everyone's ACL and
flips the global network lock, and `uncovered_handles` discloses other
accounts' node handles. Every other endpoint scopes carefully through
`GetPeers`; these four bypass it entirely.

### 12. Two stubs report success for work they do not do

- `POST /bedrock/responses/import` returns **204** having imported nothing.
- `GET /bedrock/log/verify` returns `{"valid": true, …}` with no chain in
  existence.

`bedrock.Coverage` has no writer at all, so nothing can ever become covered. A
green "verified" tick for an unbuilt mechanism is worse than a `501`.

---

## Medium

### 13. `/posture` is internally inconsistent

It reports `window_start = now - 5m` but never filters rows by that window;
sets `eligible_sessions` equal to `observed_sessions`; and hardcodes
`stale_nodes: 0`. Coverage is therefore always 100% of whatever happened to
report — the denominator problem the endpoint was designed to solve.

### 14. `compileFilter` discards the request context

It calls `h.PolicyStore.Current(context.Background())`, losing cancellation and
deadline propagation on the netmap hot path.

### 15. Per-request policy parse and relay compile

Every netmap request now re-reads and re-parses the HuJSON policy from the
database and base64-decodes and revalidates every relay. That is N nodes every
60 s, where it used to be an in-memory struct. No caching, no version check.

### 16. `getNodePaths` reports the wrong `observed_at` and a misleading `since`

`observedAt` is assigned inside the loop, so it ends up as the last row
iterated rather than the newest — `getNodePosture` computes the maximum
correctly, so the two endpoints disagree. Separately, `since` is set to
`observed_at`, so the console will render "direct since 14:32" when 14:32 is
merely the last poll.

### 17. `deleteNode` orphans Karst state

It deletes the fork peer but leaves `karst_node_identities` and
`karst_session_observations`. Deleted nodes remain in `nodes.All()`, therefore
permanently in Bedrock's `uncovered_handles` — so once any node has been
deprovisioned, `enforcing` can never be acknowledged correctly.

### 18. Relay seeding resurrects deleted relays

`bootstrap.go` seeds the store from the registry file when the store is empty.
Delete every relay through the API, restart, and they all come back.

In the other direction: after first boot, any edit to
`KARST_RELAY_REGISTRY_FILE` is silently ignored. A documented configuration
mechanism becomes a no-op with no log line.

### 19. Startup policy seeding stores a re-serialised document

`json.Marshal(pol)` writes the parsed struct, not the operator's source. This
contradicts `Version`'s own doc comment about keeping "exactly what was
reviewed, including HuJSON formatting", and any key `policy.Document` does not
model (`ssh`, `nodeAttrs`) is silently dropped.

It matters more than a fidelity complaint: `compileFilter` now prefers
`PolicyStore` over `Policy`, so the round-tripped copy is what actually
compiles into netmaps.

### 20. Node-supplied telemetry is unvalidated

`suite`, `endpoint` and `peer_handle` are stored verbatim with no length or
count limit, and `peer_handle` is never checked to be a real peer in the
reporter's account. A node can inflate the table on every poll and inject
arbitrary strings into the histogram the console renders. `Path` is the only
validated field.

### 21. `relaysDelete` ignores `RowsAffected`

Deleting a nonexistent relay returns 204 instead of 404.

### 22. `relaysCreate` leaks raw driver error text

A duplicate returns the GORM/SQLite constraint message to the client as a 400
body.

### 23. Nil-dependency guards are inconsistent

`relayHealth`, `auditSink`, `policyPreview` and the Bedrock handlers check for
a nil store. `relaysList`/`Create`/`Delete`, all four `audit*` readers, and
every `policy*` handler except `policyPreview` do not, and will panic on a nil
interface.

### 24. The authorization middleware is conditionally installed and untested

`RegisterEndpoints` applies `karstAuthorization` only `if permissionsManager !=
nil`, so a mis-wiring opens every endpoint silently — and six of the seven
tests register with `nil`.

Neither test covers the enforcement path:

- `TestRoleMatrixCoversEveryKarstRoute` validates the permission **table**,
  walking routes from mux but never issuing a request through the middleware.
- `TestAllRegisteredResponsesExcludeSecretSentinels` passes a real manager but
  asserts only the absence of secret sentinels, never a 403.

Nothing in the suite proves a `User` is refused.

### 25. Read-only POSTs require `Create`

The method-to-operation switch maps every POST to `operations.Create`, so
`/policy/validate`, `/policy/preview`, `/policy/test` and
`/bedrock/requests/export` — all non-mutating — are closed to an Auditor.

---

## Lower and hygiene

### 26. The generated Go types are imported by nothing

`server/shared/management/http/api/karst/types.gen.go` declares package
`karstapi` and no file imports it; the handlers hand-roll `map[string]any`
responses. Wiring the generated types would turn findings 6, 7 and 8 into
compile errors. This is the root cause of the drift rather than a separate
issue.

### 27. OpenAPI 3.1 document using 3.0 syntax

The document declares `openapi: 3.1.0` but uses `nullable: true`, which is not
valid in 3.1 (3.1 uses type unions). The current generator tolerates it and
emits `| null` correctly; a stricter or replacement tool will drop nullability
silently.

### 28. Network-fetched, deprecated toolchain

`generate.mjs` runs `npx --yes openapi-typescript-codegen@0.29.0`, which is
archived upstream, and `package.json`'s `check` runs `npx --yes --package
typescript@5.6.3 tsc`. Both fetch from the network at build time, against the
repo's `pnpm install --frozen-lockfile` posture. TypeScript is not a declared
dependency anywhere under `web/`, so `just web-check`'s `pnpm -r exec tsc
--noEmit` has no `tsc` to run now that a workspace package actually exists.

### 29. No CI wiring

`api-generate-karst`, `api-mock` and `api-client-check` were added to the
`justfile`, and `check-drift` to `package.json`, but `.github/workflows/` is
untouched. Contract drift cannot fail a build — which is why findings 6, 7 and
8 are present in the first place.

### 30. The mock is more capable than the server

`web/tools/karst-api-mock.mjs` returns an audit `anchor`, populated roots and
authorities, distinct `eligible`/`stale` counts, and real lint line and column
numbers. The server returns none of those. A console built against this mock
reproduces the exact shape of FINDINGS 42 and 43 — a harness supplying the
field production leaves empty — one layer up.

### 31. The control-channel spec is untouched

`spec/karst-control-v1.md` is not in the change set, though the wire format
gained `KarstSessionObservation` and `KarstNetmapRequest` field 4. Specs are
normative in this repo.

### 32. Unrecorded threat-model change

The server now continuously learns every node's direct peer endpoints
(`IP:port`) and its full peer topology, refreshed every 60 s. Not credential
material — but it is precisely the metadata the "distributor of policy, not an
enforcement point" framing disclaims. It belongs in `docs/THREAT-MODEL.md`, not
only in a proto comment.

### 33. `auditExport` weaknesses

Buffers the entire log in memory before writing. Offset pagination over a
concurrently-appended table can duplicate or skip rows. CSV fields are not
guarded against formula injection (`=`, `+`, `-`, `@`), and both `writer.Write`
and `writer.Flush` errors are discarded, so a truncated export looks
successful.

### 34. `AddSink` accepts any scheme and host

`http://169.254.169.254/…` included — latent SSRF once a delivery
implementation exists. Its ID is `hash(kind + endpoint)`, so re-adding the same
sink is a primary-key violation rather than idempotent.

### 35. `policy.Write` races on Postgres

Read-then-insert inside a transaction. Under READ COMMITTED two concurrent
writers both target version N+1; the loser surfaces a raw PK violation as a 500
rather than `ErrVersionConflict` / 412.

### 36. No request body size limit

No `http.MaxBytesReader` on any handler; policy documents are unbounded.

### 37. Implicit lifecycle contract

`RegisterAPIExtension` must be called before `APIHandler()` is first built and
fails silently if it is not. `main.go` happens to order it correctly today.

---

## What the change set gets right

Worth recording, because several of these were explicit design requirements
that are easy to get wrong:

- **One authentication path.** Routes are registered on the shared router after
  `NewAPIHandler`, inheriting auth, CORS and metrics middleware rather than
  building a second credential path.
- **`nodeReader` is deliberately read-only**, so the administrative read
  surface cannot grow a write capability by accident.
- **The secret-sentinel scan over every route × role** is a genuinely good test
  and the right shape — routes discovered from mux, not copied into the test.
- **`relayreg.Compile` keeps API-created relays on the same validation path as
  the startup file**, which was the specific hazard identified when moving the
  registry into the database, and `relay_id` stays derived from the pinned key
  rather than caller-supplied.
- **The `User` role's explicit all-false entry** closes read access that
  `AutoAllowNew` would otherwise have granted.
- **Adding `Permissions` maps to Owner, Auditor and User does not disturb other
  modules** — `lookupModulePermissions` falls through to `AutoAllowNew` on a
  miss. Verified, because it would have been an easy regression.

---

## Suggested order

1. Findings 1 and 2 — the CI gates. Minutes.
2. Finding 4, then 3, then 5 — the node-report path, where the data is either
   wrong or silently lost.
3. Finding 26 — wire the generated types, which collapses 6, 7 and 8 into
   compile errors.
4. Finding 11 — account scoping, before any of this state has real data in it.
