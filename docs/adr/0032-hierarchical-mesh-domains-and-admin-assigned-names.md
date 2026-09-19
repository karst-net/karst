<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-0032: Admin-assigned names as the real mesh identity; hierarchical domains with delegated sub-administration

- **Status:** Proposed
- **Date:** 2026-09-19
- **Deciders:** TBD
- **Related:** ADR-0010 (naming convention this ADR follows: "standard
  technical terms" get plain names, not invented ones), `spec/karstdns-v1.md`
  (current flat name grammar this ADR extends), `spec/ponor-v1.md` §5.4
  (Aquifer — a pre-existing, unrelated term this ADR deliberately does not
  reuse), commit `0d0bfb4` ("macos: show the control-plane-assigned device
  name (#163)" — the display-only fix this ADR supersedes with a real fix),
  GitHub issue #163

---

## Context

Issue #163 originally asked for the macOS client to show a human-readable
device name instead of an opaque 44-character identity hash. That got a
first, narrow fix in `0d0bfb4`: the client now shows `dns_name`, a label the
*server* derives from the *device's own self-reported hostname* at login
(`peer.go:1016`, `nbdns.GetParsedDomainLabel(peer.Meta.Hostname)`). That
commit's own message flags what it didn't do: the admin actually types a
name when creating a device invitation (`types.SetupKey.Name`,
`setupkey.go:386` `CreateDeviceInvitation`), and that name is stored and
echoed back to the console, but is never sent to the device and never
touches the peer record (`peer.go:1138` only copies it into an audit-log
event). The name an admin chooses today is asked for advice not
consulted.

Reopening #163 asks for three things:

1. **The name shown should be the admin-specified one**, and it should be
   the device's *real* address on the mesh — not a separate display label
   layered over a different, hostname-derived DNS name.
2. **Devices should be organizable into domains and subdomains** — not one
   flat namespace per account.
3. **Top-level domain administrators should be able to create subdomains and
   delegate their administration** to other admins.

None of this exists today. Concretely, per the account/naming/RBAC audit
behind this ADR:

- **Naming is single-label and account-flat.** `spec/karstdns-v1.md`'s grammar
  is `<label>.<zone>` — one label, one zone, unique only *within the
  account* (`types/account.go` `GetPeerDNSLabels`/`getUniqueHostLabel`). There
  is no hierarchy anywhere in the pipeline: not in the DB model
  (`types.SetupKey`, `nbpeer.Peer`), not in the wire protocol
  (`KarstDNSConfig{Zone: ...}`, a bare string), not in the client resolver
  (`crates/karst-dns`'s `MeshZone` is a flat peer map against one zone).
- **RBAC is entirely account-wide.** `permissions/roles/` defines five fixed
  roles (owner, admin, network_admin, auditor, user), each granting
  CRUD on a *module* (Peers, SetupKeys, Dns, ...) across the *whole
  account*. Nothing scopes a role to a subset of an account's resources —
  there is no "admin of this thing only" primitive to build delegation on.
- **"Domain" is already a taken word, twice over, inside this codebase**,
  for two unrelated things: `Account.Domain`/`DomainCategory`
  (IdP-derived email-domain account linking — nothing to do with DNS) and
  `proxydomain.Domain` (custom domains for the reverse-proxy/ingress
  feature, scoped per account, with its own `RequireSubdomain` flag but no
  admin-delegation model). Separately, `server/management/internals/modules/zones`
  defines a `zones.Zone` type — custom DNS *records* (A/CNAME/etc.)
  distributed to specific peer groups (split-DNS), which is also
  informally called a "zone" or "domain" in its own code and API, but is a
  different feature entirely: it injects externally-defined records for
  peers to resolve, and has nothing to do with how a peer names *itself*.
- **"Aquifer" is already a taken word, and it is load-bearing.** Per
  `spec/ponor-v1.md` §5.4, an aquifer is the relay's tenant-isolation tag: "a
  relay MUST refuse to forward a frame unless the source and destination
  are in the **same** aquifer." It is enforced in the relay's trust boundary
  (`bins/karst-relay/src/hub.rs`), and is deliberately flat and
  single-valued per deployment today (`roster.go:70-79`'s own comment:
  *"Single-valued because the first deployment target is single-tenant...
  a multi-tenant server replaces this field rather than adding to it"*).
  Reusing "aquifer" as the product name for a *hierarchical, per-account*
  domain concept would conflate two different things — a device's
  human-facing network name/organizational placement, versus which
  customers' traffic a shared relay is allowed to mix — under one word, in
  a spec where that word already carries security meaning. **Decided
  explicitly with the user: keep them separate.** Aquifer keeps its
  current meaning and scope (relay-forwarding tenant isolation, currently
  ≈ one per account) unchanged by this ADR.

## Decision

### Terminology: plain "domain" / "subdomain," not an invented name

Per ADR-0010's own stated rule — *"invented proper nouns get themed names;
standard technical terms do not"* — a DNS domain hierarchy is exactly the
kind of standard technical term that should stay plain. No new themed word
is introduced. To resolve the collisions named above without inventing
branding:

- The new hierarchical entity is the Go type `meshdomain.Domain`, in a new
  package (`server/management/internals/modules/meshdomain`), analogous to
  how `proxydomain.Domain` already disambiguates its own meaning by
  package. It is never referred to as a "zone" in code or API to avoid a
  third meaning of that word alongside `KarstDNSConfig.Zone` and
  `zones.Zone`.
- Docs and UI say "mesh domain" wherever bare "domain" could be confused
  with `Account.Domain` (IdP linking) or the reverse-proxy's custom
  domains.
- "Aquifer" is not touched: it keeps meaning relay-forwarding tenant scope,
  stays flat, and stays ≈ one per account, exactly as `roster.go` has it
  today. This ADR does not implement per-subdomain relay isolation — see
  Consequences and "Reconsider if."

### Data model: an account-scoped domain tree

A new `meshdomain.Domain`: `{ID, AccountID, ParentID *string, Label string}`.
`ParentID == nil` marks a top-level (root) domain. An account gets exactly
one implicit root domain on migration, carrying its existing
`Settings.DNSDomain`/`account.Network.Dns` suffix, so every existing peer's
current name keeps resolving unchanged — this is additive, not a breaking
migration.

A peer's full mesh name is its label plus the label path from its domain up
to the account's DNS root: `<peer-label>.<domain-label>.../<root-suffix>`.
Label-uniqueness, currently enforced per-account
(`Account.GetPeerDNSLabels`), moves to per-domain: two peers in different
domains may share a label, the same way two hosts under different DNS
zones can.

This is a real protocol change, not just a data-model one: `KarstDNSConfig`
today carries one flat `Zone` string for the whole account
(`control/dns.go:19`); the netmap must instead project, for every peer a
given node is allowed to see, that peer's full domain path — not just a
label against one shared suffix. That wire/resolver change
(`crates/karst-dns`'s `MeshZone`/`MeshPeer` going from a flat map to a
domain-aware one) is nontrivial and is scoped as implementation work
following this ADR, not specified down to the wire format here.

### Admin-assigned names become the real mesh identity

`CreateDeviceInvitation`'s `name` (`setupkey.go:386`) stops being
console-only bookkeeping. At creation time it is validated against
KarstDNS's existing label grammar (`[a-zA-Z0-9-]`, ≤58 chars,
`spec/karstdns-v1.md`) and associated with a target `Domain` (defaulting to
the account's root domain, preserving today's behavior when an admin
doesn't pick one). At enrollment, `LoginPeer` (`peer.go:960-1021`) reads
the setup key's name and domain and assigns them to the new peer's
`Name`/`DNSLabel`/domain membership, instead of deriving the label from
`peer.Meta.Hostname`. Uniqueness dedup (the existing `-1`..`-999` suffix
scheme) still applies, now scoped to the target domain.

The client-visible `dns_name` field added in `0d0bfb4` needs no shape
change — it already carries `peer.DNSLabel`, which already **is** the live,
resolvable network name (`netmap.go:355,396`). Once the label's source
changes, the macOS "Enrolled as `<name>`" display is correct with no
further client work: the value it already shows becomes the admin's name
for free.

Setup keys with no admin-specified name (the older bare "Auth keys" flow,
`CreateSetupKey`) keep today's hostname-derived fallback — unaffected,
not deprecated by this decision.

An admin should also be able to rename an already-enrolled peer, not only
at invitation time — the same validation and per-domain dedup applies, and
the change reaches nodes on their next netmap poll the same way any other
`netmap_version`-bumped field does (`spec/karst-control-v1.md` §5.5).

### Delegated subdomain administration: a new resource-scoped role

Today's roles (`permissions/roles/`) are exclusively account-wide. This
ADR adds a **domain-scoped admin role**: a role binding of
`{UserID, DomainID}`, checked in `permissions/manager.go`'s
`ValidateUserPermissions` alongside the existing account-wide checks. A
domain-scoped admin gets the same module permissions (Peers, SetupKeys,
domain management) an account admin has, but the check additionally
requires the target resource (a peer, a setup key, a subdomain) to fall
within that admin's domain subtree.

A domain-scoped admin may create further subdomains beneath their own
domain and delegate those recursively — the same shape, one level down.
They cannot act outside their subtree, cannot see or touch sibling or
parent domains, and cannot grant themselves or anyone else a wider scope
than their own. Account-wide roles (owner, admin) are unaffected and
implicitly cover every domain in the account, including future ones —
delegation narrows a *subset* of what an account admin can already do; it
does not add new capability at the top.

### Alternatives rejected

- **Reuse "aquifer" for the domain hierarchy.** Rejected per the collision
  above and the user's explicit direction: it already names something
  else, security-critical and intentionally flat.
- **Extend `zones.Zone` to also carry naming/delegation semantics.**
  Rejected: that module's job is injecting externally-defined DNS records
  for specific peer groups to resolve (split-DNS), scoped by
  `DistributionGroups`. A peer's own name and organizational placement is
  a different lifecycle and a different scoping axis (a domain tree, not
  a group list). Conflating them would make both harder to reason about
  for no shared benefit.
- **Keep naming flat; just make the display value admin-typed
  (rename-only, no hierarchy, no delegation).** Rejected: satisfies the
  narrowest reading of "show the admin's name" but not that it's "the name
  the device is addressed by," and does nothing for the domain/subdomain
  and delegation asks, which are the larger and more clearly stated part
  of the reopened request.
- **Give every subdomain its own Aquifer (relay-forwarding scope).**
  Rejected as part of this ADR: it would expand the relay's trust boundary
  far beyond what's asked here and directly contradicts `roster.go`'s
  stated single-valued-per-deployment design. If true relay-level traffic
  isolation between subdomains is ever wanted, that is a separate,
  larger decision — see "Reconsider if."

---

## Consequences

### Positive

- #163 gets a real fix: the name shown is the name the admin chose, and it
  is genuinely how the device resolves on the mesh, not a display-only
  label next to a different underlying identity.
- Domains give account admins an organizational and naming hierarchy
  (e.g. a department or site structure) that didn't exist at all before.
- Delegated sub-administration is a first real answer to a gap
  `permissions/` had no primitive for — useful well beyond this issue
  (MSP/multi-department account structures).
- No wire-shape change to the already-shipped `dns_name` field; the
  `0d0bfb4` client work is preserved, not thrown away.

### Negative

- **This is materially larger than the original issue.** What started as
  "show a nicer name" now includes a new data model, a netmap/resolver
  protocol change, and a new RBAC primitive. Sequencing (e.g. ship
  admin-assigned flat names first, domains/delegation as a follow-on) is
  an implementation decision this ADR does not make for the reader.
- **Per-domain uniqueness is a real behavior change** from today's
  per-account uniqueness, and needs a correct migration (implicit root
  domain per existing account) to avoid silently renaming or colliding
  existing peers.
- **New RBAC scoping surface is new attack surface.** A bug in the
  domain-subtree check in `permissions/manager.go` is a privilege-
  escalation bug (a subdomain admin reaching outside their scope). This
  needs the same care as any other authorization boundary and dedicated
  test coverage, not just happy-path testing.
- **Aquifer/relay-forwarding scope is unchanged and stays account-wide.**
  An account and everything under it — however many domains and
  subdomains — remains one relay-forwarding tenant. Traffic between two
  devices in unrelated subdomains of the same account is *not* isolated
  at the relay by this ADR; only DNS naming and admin authority are
  hierarchical. If that's read as implying traffic isolation, it doesn't
  provide it, and that should be stated plainly wherever domains are
  documented to admins.

### Reconsider if

- A scenario needs actual **relay-level traffic isolation between
  subdomains** (not just naming/admin separation) — that's a materially
  different, larger decision about extending Aquifer itself to be
  hierarchical, deserving its own ADR against `spec/ponor-v1.md` §5.4
  rather than folding into this one.
- Domain nesting depth or the per-node netmap payload size (every visible
  peer now carries a domain path, not a bare label) becomes a real
  performance problem — would justify a depth cap or a more compact wire
  encoding than "full label path per peer."
