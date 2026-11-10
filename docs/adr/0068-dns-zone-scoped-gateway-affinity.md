<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-0068: DNS-zone-scoped Gateway affinity for legacy IP-allowlisted networks

- **Status:** Proposed
- **Date:** 2026-11-07
- **Deciders:** Proposed in this session; follow-on work tracked in #553, #554.
- **Related:** ADR-0056, ADR-0057, ADR-0064, ADR-0065, GitHub issues #109, #553, #554

> **Naming note (ADR-0069, 2026-11-08):** "Gateway" throughout this document
> is now **Aven**; the decision below is otherwise unaffected.

---

## Context

A legacy network's own firewall frequently admits inbound traffic only from
one specific, pre-registered source IP — an allowlist the operator of that
network controls, not Karst. Reaching it through Karst means some Gateway
candidate's real egress address must be, and must stay, the one address that
firewall trusts.

Two distinct problems hide inside that one sentence, and neither is solved by
the other:

1. **Egress identity must not drift silently.** `route_offer::select_effective`
   (`bins/karstd/src/route_offer.rs`) already reduces an HA family of Gateway
   candidates to one effective winner — lowest metric, tied by
   lexicographically smallest gateway id — "a pure function of the candidate
   set, not of live reachability" (its own doc comment). That is correct for
   an ordinary route: a client should not care which redundant Gateway
   actually carries its traffic. It is wrong for a legacy-firewalled
   destination: a failover candidate's real egress address is not the one
   address the legacy firewall allows, so a failover that is invisible and
   harmless for an ordinary route silently black-holes this one.

2. **Destination address alone cannot always name the Gateway.** Cryptokey
   routing (`routing::AllowedIps`, `bins/karstd/src/routing.rs`) answers "which
   peer owns this destination?" as a pure, static function of an
   authenticated, conflict-free prefix set — `AllowedIps::build` *hard-rejects*
   two peers claiming the same range, by design, because a silent winner there
   means traffic goes somewhere the operator did not choose
   (`routing.rs:270-276`). That is exactly right for one network. It is
   structurally unable to serve two independent legacy networks that happen
   to reuse the same private address range behind two different Gateways — a
   routine situation after a merger, or simply two sites provisioned from the
   same template. No prefix-based policy, however it is layered, can
   disambiguate those by destination address; only the DNS zone a client
   actually queried can, because the two networks' internal names do not
   collide even when their addresses do.

KarstDNS's existing split-DNS routing (`crates/karst-dns/src/split.rs`,
`RoutingTable::matching`) already picks a *resolver* by longest domain
suffix. It has no effect on cryptokey routing today — a name resolved through
a split route still has to find its Gateway through the same `AllowedIps`
longest-prefix match as anything else, which is precisely what problem 2
above says cannot always work.

## Decision

Two additive fields on `KarstRouteOffer`
(`server/shared/management/proto/karst_control.proto`), gated by a new
`dns_zone_affinity_schema` capability declaration on both the netmap request
and response — the same additive-schema discipline ADR-0064's
`gateway_ingress_schema` already established, so an old agent is never sent a
field it would silently misinterpret as an ordinary claim:

- **`pinned_egress_ip`** declares the stable address a legacy firewall is
  expected to allow for this Gateway candidate. Candidates in the same HA
  family must agree on it or the netmap is rejected — extending
  `route_offer::parse_all`'s existing "two offers sharing a key that disagree
  on kind/masquerade/keep_route is a conflict, not an HA family" check
  (`route_offer.rs`'s `AgreedFields` tuple) to cover it too. Two candidates
  that genuinely share one address (an active/standby pair behind a floating
  IP, say) still fail over between themselves exactly as before; two that
  declare *different* addresses are refused outright rather than silently
  resolved by metric, because that silent resolution is the drift problem 1
  above describes. This is a consistency check and an admin-facing
  declaration, not a verified fact — nothing here probes the Gateway's real
  egress address. Verifying it (nftables egress-address observation, drift
  alerting in the admin console) is deliberately left to a later change; see
  "Reconsider if".

- **`dns_zone`** binds an offer to a DNS zone instead of to `prefix` by
  longest-prefix match. `prefix` remains required, but becomes an
  *authorization bound* a resolved address must fall inside, never a claim
  inserted into `AllowedIps::build`'s own pairs — two zone-scoped offers are
  explicitly allowed to declare the same or an overlapping `prefix`, which an
  ordinary offer may never do. `route_offer::Offer::group_key` groups HA
  candidates by `dns_zone` rather than by `prefix` whenever one is present,
  so two different zones that happen to share a `prefix` are never folded
  into one HA family and do not lose a candidate to the other's metric.

A new, deliberately separate table, `zone_route::ZoneRoutes`
(`bins/karstd/src/zone_route.rs`), holds the authenticated half of this:
built from the same effective route offers `AllowedIps` is, but only from the
`dns_zone`-bearing ones, which never join `AllowedIps::build`'s pairs — doing
so would reintroduce the exact same-range conflict that function exists to
reject, for ranges this mechanism allows to collide by construction
(`config.rs::from_netmap_enforced`, the `zone_triples` collection). It is just
as intolerant as `AllowedIps` of two peers claiming the *same* zone; it is
simply never bothered by two different zones claiming the same address range.

A second, runtime-only table, `zone_route::DnsAffinityCache`, holds the
learned half: when a query matching a bound zone is answered, each resolved
address that actually falls inside that zone's authorized bound is pinned to
the zone's Gateway, bounded by the answer's own TTL clamped to a one-hour
ceiling (`zone_route::MAX_PIN`) and a 4096-entry cap, independent of the
netmap's own refresh cycle. `Engine::outbound` (`bins/karstd/src/engine.rs`)
consults this cache before falling through to `AllowedIps::route` — never as
a fallback *from* it, since the two tables are never both authoritative for
the same destination by construction. A resolved address outside its zone's
bound is simply never pinned, not routed by ordinary `AllowedIps` as a
fallback: trusting an unbounded answer would let a compromised or merely
misconfigured resolver behind one legacy network redirect traffic to an
address its zone binding never authorized.

### What this change actually delivers today

Implemented and tested end to end: the proto fields and schema gate;
`route_offer::Offer`'s parsing, HA-family grouping, and pinned-egress-IP
consistency check; `zone_route::ZoneRoutes` and `zone_route::DnsAffinityCache`;
`config::Config::zone_routes` built alongside `routes` with zone-scoped
offers excluded from `AllowedIps`; `Engine::note_dns_answer` and
`Engine::outbound`'s consultation ordering; and the wire-answer path itself —
`karst_dns::service::answered_addresses` extracts every A/AAAA record and its
own TTL from a forwarded response, `karst_dns::listener::serve_udp_once_with`/
`serve_tcp_once_with` report them (additive siblings of the existing
functions, which become one-line wrappers passing a no-op hook — no existing
caller's behavior changed), and `bins/karstd/src/dns.rs`'s new `AnswerHook`
threads this into both `Runtime::start` (kernel/host-socket mode) and
`Runtime::start_userspace` (the overlay-only path, which bypasses
`handle_wire` for a split answer and so needed its own, duplicated-on-purpose
`report_answer` — see `dns.rs`'s own doc comment on why sharing it across
the crate boundary wasn't worth the coupling).

The one real obstacle — `dns.rs`'s `Runtime::start`/`start_userspace` are
constructed in `run.rs::run_engine` *before* the `Engine` a hook would need
to call into exists, and reordering that startup sequence was exactly the
kind of change this ADR declined to make as a side effect — is resolved
without reordering anything: `run_engine` builds `dns_engine`, an
`Arc<OnceLock<Arc<Engine>>>`, before the DNS runtime starts, and a hook
closure capturing it is handed to every `Runtime::start`/`start_userspace`/
`dns::reconcile` call (the last on every netmap refresh, via a new
`dns_hook` parameter on `refresh_netmap`). The hook is a no-op — nothing to
pin, nothing routable yet regardless — until `dns_engine.set(...)` runs
immediately after `Engine::new`, a few hundred lines later. The only
observable change to `run_engine` itself is that its local `engine` binding
became `Arc<Engine>` instead of a bare value, solely so that one `Arc::clone`
exists to hand the `OnceLock`; every other one of its ~80 existing `&engine`
usages across that function kept compiling unchanged through ordinary
`Arc<T>` deref coercion.

### Alternatives rejected

- **Let `select_effective`'s metric tiebreak keep deciding, and simply
  document that a pinned route's operator must keep every HA candidate's
  egress address identical.** Rejected: that is an invisible operational
  invariant with no enforcement and no failure signal — exactly the kind of
  silent drift ADR-0064's own "Alternatives rejected" already warned against
  for an unversioned field. Declaring and checking `pinned_egress_ip` costs
  one more comparison in an already-existing conflict check.

- **Resolve the overlapping-range ambiguity by relaxing
  `AllowedIps::build`'s same-range rejection**, e.g. let the most specific
  *source* zone win. Rejected: that is precisely the "a silent winner means
  traffic goes somewhere the operator did not choose" failure mode
  `AllowedIps::build`'s own doc comment exists to prevent, and it would still
  need to know the zone to pick a winner by — at which point the zone, not
  the address, is already doing the real work, and it belongs in its own
  table.

- **Trust a DNS answer's address unconditionally once its zone is bound to a
  Gateway.** Rejected: a resolver behind one legacy network could then
  return an address inside another zone's intended range, or outside any
  authorized range at all, and have it pinned to a Gateway that address was
  never meant to reach. The authorized `prefix` bound on the offer is the
  ceiling; an address outside it is never pinned, full stop — see
  `zone_route::tests::an_answer_outside_its_zones_bound_is_never_resolved`.

- **Fall back to ordinary `AllowedIps::route` when no affinity pin exists for
  a destination inside a zone-scoped offer's bound.** Rejected: the whole
  reason the offer's `prefix` is excluded from `AllowedIps::build` is that it
  may collide with another zone's range; falling back to that same table
  would silently resurrect the ambiguity this ADR exists to remove, the
  moment a client sends to an address before resolving it.

---

## Consequences

### Positive

- A legacy network's firewall can allowlist one real Gateway address and
  trust Karst never to swap it for another without the netmap itself
  changing.
- Two independent legacy networks may reuse the same address range behind
  different Gateways without an operator ever hitting `AllowedIps::build`'s
  `Conflict`.
- Both new tables fail closed by construction: a malformed or contradictory
  offer is rejected at `parse_all`, and an out-of-bound DNS answer is simply
  never pinned — there is no path that silently does the wrong thing instead
  of nothing.
- Nothing here changes behavior for a node that was never sent a
  `dns_zone`/`pinned_egress_ip` offer: `ZoneRoutes::is_empty` short-circuits
  `Engine::note_dns_answer`, and an ordinary offer's `AllowedIps` treatment is
  untouched.

### Negative

- This ADR covers the client-side mechanism only. The Go control plane has no
  way yet to let an operator declare a `dns_zone`/`pinned_egress_ip` binding;
  that is necessary before this is usable end to end, and is not in this
  change — tracked as GitHub issue #553.
- `pinned_egress_ip` is a declaration, not a verified fact. An operator who
  misconfigures it, or a Gateway whose real egress address drifts (a cloud
  NAT reassignment, say), gets no signal from this change alone. Closed by
  issue #554 (see the addendum below) — detection and alerting exist now;
  automatic remediation remains out of scope, by that issue's own design.
- A learned affinity pin can keep sending traffic to a Gateway for up to one
  hour (`zone_route::MAX_PIN`) after the control plane withdraws its zone
  binding, since the cache is deliberately independent of the netmap's own
  refresh cycle. This is a bounded, documented staleness window, not an
  unbounded one, but it is real.

### Reconsider if

A Gateway ever needs automatic failover at all (GitHub issue #109): a pinned
route's "no silent cross-IP failover" rule would need its own answer to that
question, not inherit whatever issue #109 eventually decides for ordinary
routes. Also reconsider if an operator asks for automatic *remediation* of a
detected drift (re-pinning, or actuating the Gateway's egress address) —
issue #554 below deliberately stops at detection and alerting.

---

## Addendum: issue #554, egress-IP verification

`pinned_egress_ip` is now a verified fact, not a bare declaration. A
Gateway candidate with a pinned route self-reports its own observed
outbound address — a local, zero-traffic UDP route-table lookup
(`bins/karstd/src/gateway.rs::observed_egress_ip`), never a network probe —
over the same authenticated channel `KarstRouteObservation`'s other fields
(`bytes`, `forwarding_active`) already use. The control plane compares it
against the route's declared `pinned_egress_ip` at read time and surfaces a
mismatch in the console's route detail view (`routes.tsx`'s Metrics tab),
the same declared-vs-observed drift idiom `ClientVersionObservation`
already established for agent/control version skew.

**Decision: an independent observation/alerting path, not inside
`infraprovision.Driver` (ADR-0067).** ADR-0067's own "Reconsider if" named
that Driver as the natural extension point once the control plane could
"actuate or verify Gateway infrastructure directly," which read as an
invitation to put this there. Reading the interface itself
(`server/management/internals/karst/infraprovision/infraprovision.go`)
shows why that would be the wrong fit: `Driver` is strictly compute
lifecycle for one named relay allocation instance —
`Create`/`TLSServerName`/`Drain`/`Destroy` — with no concept of a running
node's network path or a self-reported observation at all. Egress-IP drift
is a fact about an already-running, already-enrolled Gateway, reported the
same way every other netmap-request observation is; it has nothing to do
with provisioning compute for a relay allocation. Forcing it through
`Driver` would mean inventing a method that interface's every other
implementation (AWS, Kubernetes, Nomad) would have to either implement
meaninglessly or stub out, for a concern that already has a working,
narrower mechanism. Automatic *remediation* of a detected drift — actually
changing a Gateway's egress address, as opposed to reporting it — remains
the one place `infraprovision.Driver` could plausibly apply in the future,
and remains explicitly out of scope here (see "Reconsider if" above).
