# Documentation

**PLAN.md Phase 6, workstream 11 · W6–W8 · All, SRE-owned.**

This is the detailed plan behind [00-overview.md](00-overview.md) §2 item 11.
It is a re-baseline against the tree on 2026-09-04. `docs/` already carries
three substantial documents — `GETTING-STARTED.md` (974 lines, CI-exercised),
`THREAT-MODEL.md` (251 lines, a Phase 0 exit criterion, already reviewed and
signed off once), and `USE-CASE-ANALYSIS.md` (399 lines) — plus scattered
operational knowledge in `deploy/compose/README.md` and `justfile`. None of
Phase 6's four named documents (install guide, operations manual, security
whitepaper, migration guide) exist as separate artifacts. The work is
therefore consolidation and gap-closing against real, CI-checked material in
most cases, not a from-scratch writing project — except the migration guide,
which has no existing source to draw from anywhere in the tree.

This workstream depends on [09-ha.md](09-ha.md): the operations manual's
backup/restore and failover sections are fed directly by HA's runbooks and
must not be authored independently here. Where this plan needs to reference
HA content, it names the input and defers to workstream 9's output rather
than inventing failover procedure.

## 1. Outcome and scope

A self-hoster or evaluator can go from "nothing installed" to a working,
understood, and operable Karst deployment using only published documentation:
install from released artifacts, understand what Karst does and does not
protect against, run day-to-day operations including backup/restore and a
real failover, and — if migrating from WireGuard or Tailscale — know what
changes and what doesn't. A crypto lead's name is attached to the security
whitepaper's claims, not just an engineer's.

In scope:

- extending `GETTING-STARTED.md` to close the two architectural gaps the
  Phase 6 pentest found undocumented (§2 below), rather than starting a
  competing install guide;
- a new operations manual consolidating `deploy/compose/README.md`,
  `justfile`, `karst bugreport`, and workstream 9's HA runbooks;
- a new security whitepaper derived from `THREAT-MODEL.md` and
  `plans/phreatic-review-findings.md`, with the crypto lead's sign-off
  recorded in the document itself;
- a new migration guide from WireGuard and Tailscale, written from scratch;
- the README status-line rewrite deferred at Phase 5's close
  ([phase-5/09-exit-criteria.md](../phase-5/09-exit-criteria.md) §7).

Out of scope:

- rewriting `THREAT-MODEL.md`'s structure or scope — only correcting the
  stale Phase 6 external-review claim it currently carries (§2 below);
- content ownership for HA runbooks, subnet-router/exit-node operation, or
  ACL-gated SSH operation — those are pulled in from workstreams 9, 6, and 7
  respectively once each lands, not authored here;
- translation or localization;
- a rewrite of `USE-CASE-ANALYSIS.md`, which stays as-is and is referenced,
  not duplicated.

## 2. What already exists, and the two gaps that must close

| Document | Present now | Gap this workstream closes |
|---|---|---|
| `docs/GETTING-STARTED.md` | 974 lines; three paths (A: two bare nodes, B: coordination server + relay via containers, C: bare metal + systemd), enrollment, ACLs, console/portal dev serving. CI-exercised mechanically by `getting-started-walkthrough.sh` and named directly in [00-overview.md](00-overview.md) §0 item 2 as the doc an actual outsider must complete unaided | Document the control-channel TLS limitation and the reverse-proxy port-sharing constraint (below) — both found live in the Phase 6 pentest and confirmed absent from this file |
| `docs/THREAT-MODEL.md` | 251 lines; Phase 0 exit criterion, already reviewed once (§10). §9 "Validation commitments" and §10 "Review" both assert **external cryptographic review in Phase 6** | Stale against [00-overview.md](00-overview.md) §6, which moved external review to Phase 8 on 2026-08-21. This document currently makes a claim the phase plan of record contradicts — fix it here, first, before anything (including the whitepaper) cites it |
| `docs/USE-CASE-ANALYSIS.md` | 399 lines, ten use cases including UC-07 (subnet router/exit node, workstream 6) and UC-10 (audit) | None — reference from the new docs, do not duplicate |
| `deploy/compose/README.md` | 204 lines: co-located deployment, roster mechanics, self-signed certificate rationale, TURN fallback, image verification | Fold into the operations manual as the container-deployment chapter rather than leaving it as the only operational doc a self-hoster finds |
| `justfile` | 354 lines, ~35 targets (`test-*`, `walkthrough-*`, `licenses*`, `verify*`, `packages-verify*`) | Undocumented outside inline comments and `just --list`; the operations manual needs an operator-facing index of which targets matter for running (not developing) a deployment |
| README.md | Status line: "**Status: pre-alpha. Usable, not reviewed.** Phase 5 of 7 complete... nothing here has had external cryptographic or security review... two things Phase 5's own exit gate asked for are not yet true" | Rewrite once workstream 0's carried items (deprovisioning timing, outsider walkthrough) are closed and this workstream's docs exist — see §6 |
| Security whitepaper | Does not exist | New document, §5 |
| Migration guide | Does not exist anywhere in the tree — confirmed by search | New document, §5 |

### 2.1 The two undocumented gaps, found live in the Phase 6 pentest

Both from [04-pentest.md](04-pentest.md), stated there as things "nothing in
GETTING-STARTED.md or `deploy/compose/README.md` says," not merely an
observation to leave in a pentest report:

1. **`karstd`'s control-channel client has no TLS support at all**
   (pentest doc §8). `crates/karst-control-client/Cargo.toml` builds `tonic`
   with no `tls`/`tls-webpki-roots`/`tls-native-roots` feature; a node's
   `[control] server` URL scheme is cosmetic — the client only ever dials
   plaintext h2c, authenticated by ML-KEM/ML-DSA pins per ADR-0011, not TLS.
   `GETTING-STARTED.md`'s existing nginx block (line 751,
   `walkthrough=none`, deliberately not exercised by CI because "no path
   deploys" it) proxies `/api/` for the console but says nothing about the
   gRPC control channel nodes dial, and nothing warns a reader who fronts
   `:33073` with a TLS-terminating reverse proxy that node enrollment over
   that proxy will not work the way the console traffic does.
2. **The reverse-proxy port-sharing constraint.** The pentest's own
   deployment needed a second, LAN-only, unproxied port
   (`deploy/compose/pentest/docker-compose.yml`) for node enrollment because
   Caddy fronting `:33073` for the console left no clean way to also carry
   raw HTTP/2 node traffic through the same TLS-terminating hop in that
   topology. `GETTING-STARTED.md` §7's nginx example implicitly assumes
   nodes reach `karst-control` on their own directly-exposed port while the
   console gets a separate origin, but never says so — a reader who puts
   both behind one reverse-proxied origin, as the nginx snippet's phrasing
   invites, hits this blind.

Both get a named subsection in `GETTING-STARTED.md` §7 (the existing
"Serving the console" section) rather than a new document — the reader who
needs this is already reading §7 to solve exactly this problem.

## 3. Decisions to lock before implementation

### 3.1 The install guide is `GETTING-STARTED.md`, not a new document

Do not create `docs/INSTALL.md`. `GETTING-STARTED.md` is already the
CI-exercised, walkthrough-validated entry point named explicitly by
[00-overview.md](00-overview.md) §0 item 2 and by
[phase-5/09-exit-criteria.md](../phase-5/09-exit-criteria.md) §3's outsider
protocol. A second install document would either drift from it or duplicate
it, and CI has no mechanism to keep two documents in sync. Phase 6's "install
guide" exit line is satisfied by extending this file (§2.1's two gaps) and
keeping it current, not by authoring a parallel one.

### 3.2 Fix `THREAT-MODEL.md` before writing the whitepaper

`THREAT-MODEL.md` §9 and §10 currently assert an external cryptographic
review lands in Phase 6 — true when that document was last reviewed, false
since [00-overview.md](00-overview.md) §6 moved external review to Phase 8 on
2026-08-21. The security whitepaper is meant to draw its claims from
`THREAT-MODEL.md`; if the source document is stale, the whitepaper inherits
the same false claim on day one. Correct §9 and §10 first, as their own
change (not folded silently into the whitepaper's authoring commit), so the
correction is visible in git history independent of the new document.

### 3.3 The security whitepaper is derived, not independently researched

Do not re-derive threat analysis. The whitepaper draws from
`THREAT-MODEL.md` (post-3.2 fix) for the threat model itself,
`plans/phreatic-review-findings.md` for what the internal cryptographic
review (workstream 3) actually found and fixed, and `spec/phreatic-v1.md` /
`spec/karst-control-v1.md` for the wire-level claims. Its job is synthesis
for an external, non-implementor audience — an evaluator's technical
security officer — not new analysis. Every claim in it must trace to one of
these three sources or to a specific test/CI job; unsourced claims are a
defect in this document, checked in §6.

### 3.4 The operations manual absorbs, not replaces, `deploy/compose/README.md`

`deploy/compose/README.md` stays where it is — it is the file
`docker-compose.yml`'s own directory points a reader to, and Docker Compose
users will find it there regardless of what else exists. The operations
manual (`docs/OPERATIONS.md`) is the broader document: container deployment
(referencing `deploy/compose/README.md` rather than duplicating it),
bare-metal operation (referencing `GETTING-STARTED.md` §6), the `justfile`
operator-relevant target index, `karst bugreport` usage, and — once
workstream 9 lands — backup/restore and failover procedure pulled from its
runbooks by reference or direct inclusion, workstream 9's call to make.

### 3.5 The migration guide states the non-goal up front

`README.md` and `docs/THREAT-MODEL.md` §7 already state **no WireGuard
interoperability** as a deliberate non-goal (ADR-0003: a 2378-byte handshake
breaks WireGuard's framing). The migration guide is not an interop guide —
it is a side-by-side conceptual and operational mapping (ACLs vs. WireGuard
peer config, Bedrock vs. Tailscale's coordination server trust model, DERP
vs. Ponor relays cited in README's acknowledgments) plus a cutover procedure
assuming a clean break, not a bridge period running both. State this in the
document's first paragraph so a reader hunting for an interop bridge finds
out immediately that none exists, rather than after reading the whole guide.

### 3.6 README rewrite is gated, not scheduled independently

Per [phase-5/09-exit-criteria.md](../phase-5/09-exit-criteria.md) §7, the
rewrite was deliberately not drafted at Phase 5's close because the two red
gate items it would need to describe honestly (deprovisioning timing, the
outsider walkthrough) were still open. Workstream 0 items 1–2 in
[00-overview.md](00-overview.md) are now closed. The rewrite is a §6 exit
item here, sequenced after this workstream's own three new documents exist
(so the README can link to them) and signed off by the crypto lead on
wording, not just engineering — the same discipline §7 already specifies.

## 4. Document inventory and structure

| Document | Path | New or extended | Primary owner |
|---|---|---|---|
| Install guide | `docs/GETTING-STARTED.md` | Extended (§2.1, two subsections) | SRE |
| Operations manual | `docs/OPERATIONS.md` | New | SRE |
| Security whitepaper | `docs/SECURITY-WHITEPAPER.md` | New | Crypto lead, signs off |
| Migration guide | `docs/MIGRATING-FROM-WIREGUARD-TAILSCALE.md` | New | A Go or Rust engineer with product-facing writing bandwidth (per §5's staffing) |
| Threat model correction | `docs/THREAT-MODEL.md` §9/§10 | Extended (correction only) | Crypto lead |
| README status line | `README.md` | Extended | SRE, crypto lead signs off |

### 4.1 Operations manual table of contents

Fixed now so W6's drafting has a target rather than growing organically:

1. Deployment topologies — container (points to `deploy/compose/README.md`),
   bare metal + systemd (points to `GETTING-STARTED.md` §6).
2. Day-to-day operations — enrolling/revoking nodes and users, rotating the
   relay roster, reading `karst status`.
3. Observability — once workstream 8 lands, the metrics/tracing/diagnostics
   surfaces it adds; until then, what exists today (`karst bugreport`,
   inherited Prometheus metrics) with an explicit forward-reference rather
   than silence.
4. Backup and restore — pulled from workstream 9's runbook.
5. Failover and the tested RTO/RPO figure — pulled from workstream 9's
   runbook; the number reported must be the one workstream 9 actually
   measured, not a placeholder.
6. The `justfile` operator index — a table of the targets an operator (not a
   developer) runs, e.g. `just packages-verify`, `just verify`, excluding
   `test-*` targets that only make sense against a source checkout.
7. Upgrading a deployment — currently undocumented anywhere; write from the
   packaging/release material `GETTING-STARTED.md` and
   `scripts/release-manifest.sh` already establish.

### 4.2 Security whitepaper table of contents

Mirrors `THREAT-MODEL.md`'s structure deliberately, since it is a derived
document, but written for an external evaluator rather than an implementor:

1. What Karst protects against, and the harvest-now-decrypt-later premise
   (README's own framing, already written for this audience).
2. Cryptographic design summary — PHREATIC's suites, Bedrock's anchor tier,
   sourced from `spec/phreatic-v1.md` and ADR-0016.
3. What the internal review found and fixed —
   `plans/phreatic-review-findings.md`'s findings, summarized, with GitHub
   issue numbers kept as citations for a reader who wants the primary
   source.
4. Accepted risks and non-goals — `THREAT-MODEL.md` §7, restated for this
   audience.
5. What has **not** happened yet: no external cryptographic review, no
   external penetration test (both Phase 8) — stated as plainly as
   README's current status line does, not softened for a whitepaper's more
   formal register.
6. Crypto lead sign-off block: name, date, and the specific commit hash of
   `THREAT-MODEL.md` this whitepaper was derived from — so the sign-off is
   checkable against a specific version, matching §10's existing practice
   of versioned review sign-off.

## 5. Implementation sequence

### W6 — corrections and inventory (SRE, crypto lead)

1. Fix `THREAT-MODEL.md` §9/§10 per §3.2. This is a one-paragraph change but
   is a hard prerequisite for W7's whitepaper drafting — land it first, as
   its own commit.
2. Draft `GETTING-STARTED.md` §7's two new subsections (§2.1). Verify each
   against the actual pentest deployment's configuration
   (`deploy/compose/pentest/docker-compose.yml`,
   `deploy/compose/pentest/Caddyfile`) rather than writing from memory of
   the pentest doc's prose.
3. Write the operations manual's table of contents (§4.1) into
   `docs/OPERATIONS.md` as section headers with a one-line scope note each,
   filling sections 1, 2, and 6 completely (they depend on nothing still in
   flight) and leaving 3–5 as explicit "pending workstream 8/9" placeholders
   rather than silently absent sections.
4. Start the migration guide's non-goal statement and conceptual mapping
   (§3.5) — the parts requiring no dependency on other workstreams.

### W7 — whitepaper, manual completion, migration guide (crypto lead, SRE, migration guide owner)

1. Draft the security whitepaper (§4.2) against the corrected
   `THREAT-MODEL.md` and `plans/phreatic-review-findings.md`. Every claim
   traced to a source per §3.3.
2. Pull workstream 9's backup/restore runbook and tested RTO/RPO figure into
   the operations manual's sections 4–5. If workstream 9 has not landed a
   real figure yet, the operations manual's section 5 stays a placeholder
   rather than asserting a number — this is checked in §6.
3. Complete the operations manual's section 7 (upgrading a deployment) and
   section 3 (observability) once workstream 8's surfaces exist; same
   placeholder discipline if it hasn't.
4. Complete the migration guide: cutover procedure, and an explicit worked
   example (a WireGuard `wg0.conf` peer list and the equivalent Karst ACL,
   side by side) so the mapping isn't only prose.

### W8 — README rewrite, cross-linking, sign-off (SRE, crypto lead)

1. Rewrite `README.md`'s status line per §3.6, linking to all four new/
   extended documents.
2. Cross-link: `GETTING-STARTED.md` → operations manual for anything
   past first connection; operations manual → security whitepaper for "why
   is this safe" questions; README → all three.
3. Crypto lead signs off on the security whitepaper (§4.2 item 6) and the
   README status-line wording, recorded as a reviewed commit, not a verbal
   approval.
4. Run the accuracy checks in §6 against the final state of all documents.

## 6. Accuracy and completeness checks

The workstream is not complete without all of these:

- `getting-started-walkthrough.sh` still passes against the extended
  `GETTING-STARTED.md` — the two new subsections must not break the
  mechanical CI walkthrough that already exercises this file.
- A fresh outsider walkthrough (same discipline as
  [00-overview.md](00-overview.md) §0 item 2, a person not on the engineering
  team, unaided) attempting a reverse-proxied single-origin deployment
  produces **zero** numbered deviations attributable to the control-channel
  TLS limitation or the port-sharing constraint — both are now documented
  before they're hit, not after.
- `grep -n "Phase 6" docs/THREAT-MODEL.md` finds nothing asserting an
  external cryptographic review happens in Phase 6.
- Every factual claim in `docs/SECURITY-WHITEPAPER.md` traces to
  `THREAT-MODEL.md`, `plans/phreatic-review-findings.md`,
  `spec/phreatic-v1.md`, `spec/karst-control-v1.md`, or a named CI job —
  checked by a second reader (not the drafter) reading the whitepaper
  against those sources line by line, not by the drafter's own review.
- `docs/OPERATIONS.md`'s backup/restore and failover sections quote the
  actual RTO/RPO figure workstream 9 measured, with the date and command
  used to measure it — not a target or an estimate.
- `docs/OPERATIONS.md`'s `justfile` index runs clean: every target it names
  actually exists in `justfile` (a stale target reference is a defect), and
  every operator-relevant target in `justfile` (excluding `test-*` and
  `walkthrough-*`, which are development/CI targets) appears in the index.
- `docs/MIGRATING-FROM-WIREGUARD-TAILSCALE.md`'s worked ACL example is
  actually valid against the console's ACL schema — run it through whatever
  validation `GETTING-STARTED.md` §4 already demonstrates for a real ACL,
  don't just prose-describe one.
- No document in this workstream asserts external cryptographic review or
  penetration test has happened or is scheduled for Phase 6 — all four new/
  extended documents and the README rewrite are internally consistent with
  [00-overview.md](00-overview.md) §6's "No external cryptographic review or
  penetration test. Both are Phase 8."
- README's rewritten status line is checked against the actual state of
  workstream 0's carried items at the time of the rewrite — it must not
  assert deprovisioning-timing or outsider-walkthrough closure unless
  [00-overview.md](00-overview.md) §0 actually shows both closed.

## 7. Exit demonstration

1. A person with no prior Karst exposure, given only a released tag's
   artifacts and `docs/GETTING-STARTED.md`, deploys behind a single
   TLS-terminating reverse-proxy origin and either succeeds using the new
   §7 subsections or the attempt surfaces a **new**, not-yet-documented gap
   — logged as a numbered issue, same discipline as workstream 0 item 2.
2. An operator, given only `docs/OPERATIONS.md`, executes workstream 9's
   backup/restore runbook against a running deployment and recovers it,
   without consulting source code or asking a maintainer.
3. The crypto lead reads `docs/SECURITY-WHITEPAPER.md` end to end against
   its cited sources and either signs off in a recorded commit or returns
   specific line-level corrections — not a verbal "looks fine."
4. A reader who knows WireGuard or Tailscale but has never used Karst reads
   `docs/MIGRATING-FROM-WIREGUARD-TAILSCALE.md` and correctly states, without
   help, that there is no interop bridge and a cutover is a clean break —
   confirming §3.5's up-front framing actually lands.
5. `README.md`'s status line, read on its own, makes no claim unsupported by
   the tree at the time it's read — checked by the same second-reader
   discipline as the whitepaper.

## 8. Definition of done

- The Phase 6 exit line is demonstrably true: install guide, operations
  manual, security whitepaper (crypto lead signed off), and migration guide
  all published under `docs/`.
- Both pentest-found documentation gaps (§2.1) are closed in
  `GETTING-STARTED.md`, not merely filed.
- `docs/THREAT-MODEL.md` no longer asserts a Phase 6 external cryptographic
  review.
- The operations manual's HA content is pulled from workstream 9's actual
  runbook and measured figures, not authored independently or left
  aspirational.
- The README status line is rewritten, links to all new documents, and
  carries the crypto lead's sign-off on wording alongside the engineering
  sign-off — closing the item [phase-5/09-exit-criteria.md](../phase-5/09-exit-criteria.md)
  §7 deferred.
- All six checks in §6 pass, verified by someone other than each
  document's own drafter.
- Any documentation gap the exit demonstration (§7) surfaces is fixed before
  this workstream is marked done, not carried forward as a known issue —
  documentation gaps found by using the documentation are this workstream's
  own defects, not a future workstream's.
