<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-0042: Internal short-link redirect service

- **Status:** Accepted
- **Date:** 2026-09-30
- **Deciders:** TBD
- **Related:** #213 (this ADR's tracking issue), `spec/karstdns-v1.md`
  (the mesh-zone/peer-hostname resolution this reuses unchanged),
  `docs/adr/0025-dns-scoped-filtering-resolves-sc-06.md` (KarstDNS's stated
  scope as a policy resolver, not a general-purpose DNS server — why this
  is its own service rather than a KarstDNS feature)

---

## Context

#213 asks for a tiny internal "go/foo" style link shortener: short,
memorable names that resolve and redirect only for devices inside the mesh,
with no public-facing listener and no DNS zone visible outside it.

Two things constrain the design before any preference applies:

- **KarstDNS is explicitly scoped as a policy resolver, not a
  general-purpose DNS server** (ADR-0025). Its resolution table
  (`spec/karstdns-v1.md`) knows exactly four things: a peer's own hostname
  record, the matching PTR, split-DNS forwarding, and global-upstream
  forwarding. There is no keyword-to-URL concept and no generic
  operator-authored record type. Adding one would mean extending the
  authenticated `KarstNetmapResponse` wire contract and both the Go and
  Rust resolver implementations, for a feature that is not name resolution
  at all — it is an HTTP redirect with a DNS-resolvable front door.
- **A mesh peer's hostname already resolves account-wide with no protocol
  change.** Every enrolled device gets a stable `<label>.<zone>` record
  today, where `label` defaults to the device's OS hostname but is already
  operator-settable by renaming the device (`peer.Name`,
  `GetPeerHostLabel` in `server/management/server/types/account.go`). A
  device named `go` is therefore already resolvable as `go.<zone>` from
  every other peer on the account, via the exact same authoritative
  peer-record path any other node uses — before a single line of new code.

Given both, the cheapest correct design is: don't touch KarstDNS, don't
touch the netmap wire contract, and don't touch `karstd`. Build a small,
separate HTTP service that an operator runs on one ordinary, already-enrolled
mesh device, and let existing peer-hostname resolution do the "resolvable
only within the mesh" part for free.

## Decision

A new, self-contained Go binary, `karst-shortlink`
(`server/cmd/karst-shortlink`, backed by `server/shortlink`), deployed on
one kernel-TUN mesh device per account that the operator has named `go` (or
any other short label — the binary does not care what its own host is
named; the name is a property of how the device was enrolled, not of this
service).

It is not part of `karst-control` and adds nothing to the account
manager, the netmap projection, or the wire protocol. It is "an arbitrary
application built on top of the mesh," the same category of thing the mesh
already exists to carry — it just happens to be an application this project
ships.

### Why mesh-only reachability needs no new mechanism

A kernel-TUN peer's mesh address is an ordinary interface address on that
host. Any process bound to it (or to `0.0.0.0`, on a host with no other
public listener) is reachable exactly the way SSH on a mesh device already
is: through the overlay, from other mesh peers, and from nowhere else,
because nothing routes to that address except through the mesh. No
firewall rule, ACL entry, or code change is needed beyond ordinary
deployment hygiene (don't also expose the host publicly) — the same
hygiene every other service running on a mesh device already needs.

This does not extend to userspace mode, which deliberately opens no host
socket at all (`spec/karstdns-v1.md`'s Host Safety section notes the same
limitation for DNS host integration). `karst-shortlink` therefore requires
a kernel-TUN node. That is recorded as a real limitation below, not
silently assumed away.

### Data model and scope

One running instance serves exactly the account of the mesh it is enrolled
into. "Scoped per account" therefore falls out of the deployment shape —
there is no cross-account state to accidentally leak, because there is no
cross-account code path at all. A multi-tenant operator who wants the
feature on more than one account's mesh runs one instance per account, each
named `go` on its own mesh (names do not collide across accounts, because
zones don't).

Storage is a local SQLite file (`gorm.io/driver/sqlite`, already a
dependency via `server/go.mod`) holding one table:

```go
type Link struct {
    Keyword   string `gorm:"primaryKey"`
    TargetURL string
    CreatedAt time.Time
    UpdatedAt time.Time
}
```

No `AccountID` column: see above.

### HTTP surface

- `GET /{keyword}` — `302 Found` to the stored target, or `404` if unknown.
  Unauthenticated: this is the redirect any mesh peer follows, the same
  trust boundary as reaching any other unauthenticated service on the mesh.
- `GET /api/links`, `POST /api/links`, `PUT /api/links/{keyword}`,
  `DELETE /api/links/{keyword}` — CRUD, gated by a bearer token
  (`KARST_SHORTLINK_ADMIN_TOKEN`) set at deploy time. `keyword` may not be
  `api` or `healthz` (reserved) or empty; `target_url` must parse as an
  absolute `http(s)` URL.
- `GET /healthz` — liveness, unauthenticated.

### Alternatives rejected

- **A KarstDNS record type for arbitrary keyword → URL mappings.** Rejected
  by ADR-0025's own scope statement, and because "resolve a name" and
  "fetch a URL and 302" are different concerns that don't need to share a
  wire format. It would also mean every node carries every account's
  short-link table in its authenticated netmap whether or not it ever uses
  the feature.
- **Riding the existing netmap/`KarstNetmapResponse` to push the table to
  `karstd`, which hosts the listener itself.** This was the first design
  considered — projecting a new `repeated KarstShortlink` field the way
  `KarstDNSConfig` already rides the netmap. Rejected for a first cut: it
  touches the authenticated wire contract, the Go projection layer, and the
  Rust client for a feature with no protocol-level reason to be inside
  `karstd` at all (see "why mesh-only reachability needs no new mechanism"
  above) — cost without a matching benefit. Worth revisiting only if a
  future requirement needs the table distributed to *every* node rather
  than served centrally by one.
- **Admin-console-managed storage in the central account database**, the
  same way nameserver groups and mesh domains are managed. Rejected for a
  first cut as unnecessary central-schema/migration/permissions-module
  surface for a feature whose data has nothing to do with account
  membership, routing, or policy — and because centralizing it would
  reintroduce exactly the cross-account blast radius this design avoids.
  A follow-up can add a console-managed mode without changing the
  redirect/CRUD contract above.

---

## Consequences

### Positive

- No change to KarstDNS, the netmap wire contract, `karstd`, or the account
  manager. The entire feature is new, additive code, reviewable in
  isolation.
- "Unreachable and unresolvable from outside the mesh" holds by
  construction, not by a new enforcement mechanism that could have a bug.
- Deploying or removing the feature on one account has zero effect on any
  other account, or on any node not running the binary.

### Negative

- Requires a kernel-TUN node; userspace-mode deployments cannot host it.
- CRUD auth is a single shared bearer token, not per-operator
  admin-console identity — acceptable for a first cut, but it means every
  admin of the link table shares one credential with no per-action audit
  trail. A console-integrated mode (central storage, per-user auth,
  activity-log entries matching other account resources) is real future
  work, not assumed away.
- Basic keyword-usage accounting (flagged as a stretch goal in #213) is not
  built. The store has no last-accessed tracking.
- The operator must remember to name the device `go` (or whatever label is
  chosen) and must not let that device's hostname collide or get renamed
  out from under the service — nothing enforces the link between "this
  binary is running here" and "this peer is named `go`."

### Reconsider if

A deployment needs the table pushed to more than one node (e.g. redundancy
across multiple `go`-ish entry points, or serving it from every relay for
locality) — at that point the netmap-projection alternative above becomes
worth its cost. Or if per-operator audit trail on link edits becomes a real
requirement — at that point move storage into the central account database
and expose it through the admin console, per the rejected alternative
above.
