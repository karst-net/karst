<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-0025: DNS-scoped filtering resolves SC-06's web-filtering ask; a native time-of-day ACL primitive stays a distinct, open gap

- **Status:** Accepted
- **Date:** 2026-09-14
- **Deciders:** TBD
- **Related:** ADR-0023, ADR-0024 (the same composition pattern applied to
  SC-05); UC-05, UC-06 (`docs/USE-CASE-ANALYSIS.md`); `spec/karstdns-v1.md`;
  `docs/CUSTOMER-SCENARIOS.md` SC-06; GitHub issue #151

---

## Context

Issue #151 named two independent gaps behind SC-06 ("Parent implementing web
filtering with time-of-day rules"): no time-window dimension on access-policy
rules, and no content/category filtering in KarstDNS. The original writeup
also noted why the access-policy engine is a poor fit for "block a website"
regardless of scheduling — Karst's ACLs authorize IP-and-port destinations,
and most modern sites sit behind shared CDN/anycast ranges no fixed IP rule
reliably targets.

ADR-0024 resolved SC-05 not by building the requested feature, but by
recognizing an *already-shipped* mechanism supplied it once the actual
requirement was separated from the literal proposal. The same question is
worth asking here before building anything: does KarstDNS's existing
split-DNS mechanism already give an administrator what SC-06 needs?

It does. `spec/karstdns-v1.md`'s Configuration section states: "The server
projects only enabled nameserver groups that apply to the receiving peer.
**Primary groups become global upstreams**; non-primary group domains become
split routes." Read against `docs/USE-CASE-ANALYSIS.md` UC-06 — nameserver
groups carry "upstreams, optional split domains, search domains, and
**distribution groups**" — this means an administrator can already scope a
*specific* group of devices (a `kids` tag, say) to a *specific* DNS resolver
of the administrator's choosing, authenticated and delivered the same way
every other netmap field is (`KARST-CONTROL v1` §5.5's version construction).

That resolver does not have to be generic. Dedicated DNS-filtering products
already exist that do exactly what SC-06 asks for — domain/category
blocklists (Pi-hole, AdGuard Home, NextDNS, OpenDNS FamilyShield) *and*,
for several of them, per-client time-of-day scheduling (AdGuard Home's
per-client schedule, NextDNS's scheduling tier). KarstDNS's own framing
supports pointing at one rather than building one: it is "deliberately a
policy resolver, not a general-purpose DNS server" (`spec/karstdns-v1.md`
line 4) — the mesh zone and forwarding policy are its job; content
categorization and blocklist maintenance are somebody else's, already done
better by products that specialize in it.

## Decision

**Karst will not build native content-category filtering into KarstDNS, and
will not add a time-window dimension to access-policy ACL rules on the
strength of this issue alone.** SC-06 is resolved by composition: an
administrator points the relevant distribution group's *global* nameserver
at a filtering resolver of their choice, using the group-scoped upstream
mechanism KarstDNS already ships. Both the content filtering and its
schedule then live in that resolver, not in Karst.

### The recipe

1. Create a nameserver group in the admin console, scoped to the target
   distribution group (e.g., a `kids` tag) — the same group-scoping pattern
   SC-04's file-share ACL and SC-05's exit-node consent already use.
2. Mark it primary, with `nameservers` pointing at the chosen filtering
   resolver's address (a self-hosted AdGuard Home/Pi-hole instance, or a
   hosted filtering DNS service).
3. Configure blocklists and any time-of-day schedule **on that resolver**,
   using its own product features — not in Karst.

### What stays true, and the real limits

- **This requires kernel-TUN mode.** `spec/karstdns-v1.md`'s Transport
  section is explicit: in userspace mode, "host DNS integration is always
  `none`" — KarstDNS never takes over the host's resolvers there, so a
  userspace-mode device does not get this at all, the same platform caveat
  UC-01 already states for DNS integration generally.
- **This is DNS-based, so it can be bypassed the same way any network-level
  DNS filtering can be**: a device capable of using a hardcoded
  DNS-over-HTTPS resolver (several browsers ship one on by default) routes
  around whatever resolver the host is configured to use. Karst has no ACL
  primitive today that blocks non-approved outbound DNS/DoH to close this,
  and this ADR does not add one. Combined with ADR-0024's finding for SC-05:
  reliable enforcement of either scenario still depends on the administrator
  also holding local/OS control of the device, or additionally running it
  through an admin-controlled exit node (SC-05) where such egress could be
  firewalled at the gateway using ordinary host tools — outside Karst's own
  ACL engine either way.
- **This resolves the SC-06 scenario, not the general ACL gap.** A future
  request to schedule *non-DNS-nameable* traffic — an enterprise wanting
  SSH reachable only during business hours, say — is not addressed by this
  decision at all and would hit the original time-window gap in the
  access-policy engine unchanged. Nothing here should be read as "time-of-day
  policy is solved."

### Alternatives rejected

- **Build native domain/category blocklists into KarstDNS.** Rejected:
  duplicates existing, better-maintained, purpose-built products; conflicts
  with KarstDNS's own stated scope as "a policy resolver, not a
  general-purpose DNS server"; and creates an open-ended blocklist-curation
  and false-positive-handling burden with no natural owner on this project.
- **Add a general time-window field to access-policy `accept` rules.**
  Rejected *for this issue*: no scenario in the current basis set needs it
  once DNS delegation covers SC-06, the only time-of-day ask on record.
  Building it speculatively, with no concrete second use case driving the
  design, risks the wrong shape (per-rule window? per-group calendar?
  timezone handling for a distributed account?) being picked without a real
  requirement to test it against. Left as a "Reconsider if," not built here.
- **Add an ACL primitive to block outbound DNS/DoH except to the configured
  resolver**, closing the bypass gap named above. Plausible and scoped
  independently of SC-06's completion, but nobody has asked for it as its
  own scenario, and it is really an exit-node/egress-enforcement question
  more than a KarstDNS one. Not built here; noted as a candidate follow-up.

## Consequences

### Positive

- Resolves SC-06 with no new KarstDNS or access-policy engineering — the
  group-scoped global-upstream mechanism already exists and is already
  documented (UC-06).
- Keeps KarstDNS's scope coherent: mesh-zone authority and forwarding
  policy, not a competitor to dedicated filtering-DNS products.
- Avoids committing to a speculative ACL schema (time windows) before a
  concrete second use case exists to validate the design against.

### Negative

- The administrator now depends on a third-party or self-hosted resolver
  product for the actual filtering and scheduling logic — a dependency and
  a trust decision Karst itself does not need to also carry, but the
  administrator does.
- The DNS-bypass limitation is real and unresolved: a technically capable
  device user can defeat this without touching Karst at all. Stated plainly
  here rather than implied away.
- The general access-policy time-window gap remains completely open; anyone
  hitting it for a different reason than SC-06 gets no help from this ADR.

### Reconsider if

A concrete scenario surfaces that needs to schedule access to a
non-DNS-nameable destination (an IP/port ACL entry, not a website) by time
of day — that is the original gap this ADR declined to build against, and
it deserves its own design once a real use case exists to shape it, rather
than continuing to be inferred from SC-06.
