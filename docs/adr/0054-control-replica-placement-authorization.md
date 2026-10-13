<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-0054: Control-replica placement authorization

- **Status:** Proposed
- **Date:** 2026-10-13
- **Deciders:** TBD
- **Related:** ADR-0045 §7b (deferred this decision explicitly), ADR-0014
  (Bedrock trust hierarchy), ADR-0016 (capability-scoped anchor tier — the
  precedent this ADR follows and departs from), ADR-0011 (control-channel
  authentication — the keys at stake), ADR-0033 (per-account Bedrock scoping —
  the scoping mismatch this ADR inherits), `docs/THREAT-MODEL.md` §6/B2 and R11
  (the threat this resolves), `docs/operations/ha.md` (today's manual
  provisioning this replaces no part of)

---

## Context

ADR-0045 §7b scoped autoscaling of control replicas out, with one line: they
"carry the signing keys and roster; scaling them enlarges the most sensitive
trust boundary. Out of scope until the threat model covers it." #335 added
that coverage as a threat, not a mitigation — §6/B2's new row and R11 state the
risk plainly and propose nothing, because nothing existed yet to propose. This
ADR is that follow-up.

### What a control replica actually holds, and how it gets it

`bootstrap.go`'s `loadOrCreateKeys` reads one row (`karst_server_keys`,
`id = 1`) from the shared Postgres database: a 64-byte ML-KEM-768 seed, a
32-byte ML-DSA-65 identity seed, and the 32-byte per-pair PSK master — in the
clear, in a plain column, generated once by whichever replica boots first
against a fresh database and read unchanged by every replica after. This is
assets A3 (identity/control-channel key) and A4 (PSK derivation master) from
`THREAT-MODEL.md` §2, handed to any process that holds a Postgres connection
string. There is no admission step: nothing checks *which* process is asking,
only that it can reach the database.

Compare this to how a **node** gets trusted. ADR-0005/0014/`spec/bedrock-v1.md`
require a `node-sign` entry — an authority quorum's (`q`-of-`a`) offline,
deliberate signature over that specific node's identity key — before any other
node will accept it as a peer. A control replica requires nothing of the kind.
It is, structurally, *easier* to add a new full-trust control replica than to
add a new client device, which is backwards: a replica's compromise yields
everything a client device's compromise does not (§5's "what a compromise
actually yields" table).

Today this asymmetry is latent, not exploited, because replica placement is a
slow, manual, operator-run `docker compose up` against hosts the operator
already controls (`docs/operations/ha.md`). **An autoscaler changes that by
design** — its entire purpose is to let something other than a human decide,
at runtime, that a new replica should exist and where. R11 is precisely the
gap between "a human decides" and "a program decides" for an asset this
sensitive, and closing it is what this ADR is for.

### The scoping mismatch this inherits

Bedrock chains are per-account (`karst_bedrock_log`, confirmed per-account in
ADR-0033's scoping note). `karst_server_keys` is a single global row serving
every account the deployment hosts. Any design that gates replica admission
through *a* Bedrock chain is picking one account's quorum to speak for a
deployment-wide asset — the same category of mismatch ADR-0033 already named
for the audit log ("a deployment-wide quantity dressed as a per-account one")
and chose to state honestly rather than paper over. This ADR does the same:
§"Open question" below names it and does not resolve it, because resolving it
is a separate decision this one should not smuggle in.

---

## Decision

**A new Bedrock op pair, `replica-sign` / `replica-revoke`, at the same
quorum-authority weight as `node-sign` / `node-revoke` — not a capability-scoped
automated tier like ADR-0016's anchor key.** A boot-time check in `bootstrap.go`
refuses to release `karst_server_keys` to a process that cannot present a live,
unrevoked, unexpired `replica-sign` entry for an attestation key it holds. A
future autoscaling driver may start and stop processes within an already-signed
set of placements; it has no path to mint a new one.

### Why this cannot be an anchor-style automated tier

ADR-0016 built a fourth tier specifically so one capability — fixing audit
history forward — could be automated safely, and stated the reasoning that
makes it safe: "an anchor key's only power is to *fix* history at a point. It
cannot un-fix one." A compromised server holding an anchor key gains nothing it
did not already have, because anchoring is monotonic and one-directional.

Minting a `replica-sign` entry has no such property. It is, definitionally,
equivalent to T5's yield: whoever can produce one can stand up a fully-trusted
replica anywhere they choose. A key that could do this safely on a continuously
running host is a weaker-looking key that can still do everything a full
authority key can. ADR-0016's own "Reconsider if" names this exact boundary: *"A
deployment wants \[X\] automated but will not put a key on any host it operates
continuously, in which case the fallback \[...\] is the whole answer and this
tier should not be built."* Minting replica admission is that case. It stays at
authority weight, signed offline, the same ceremony `node-sign` already uses.

**Revocation is the opposite case, and is a plausible candidate for a narrower
tier later.** Revoking a `replica-sign` entry only removes trust — the same
one-directional property that made `anchor` safe to automate. A `replica-sign`
entry that an operator pre-approved for a placement that is being scaled down
could, in principle, be auto-revoked by a narrowly-scoped key the autoscaler
itself holds, without that key being able to mint a replacement. This ADR
does **not** propose that tier now — ADR-0016's closing lesson is "choose [...]
rather than adding tiers by reflex" — but names it as the natural Phase 2 of
this design, should auto-revocation turn out to matter in practice.

### Wire shape (mirrors `node-sign`/`node-revoke`, `spec/bedrock-v1.md` §3.1/§3.4)

```
replica-sign    LP(placement) || LP(attestation_pk)
                              || BE64(not_before) || BE64(expiry)

replica-revoke  LP(placement) || LP(reason) || BE64(effective)
```

- `placement` is an operator-chosen opaque label an admin picks at ceremony
  time (e.g. `"aws:123456789012:eu-central-1"`) — meaningful to the operator
  and to the future driver's own placement allowlist, not parsed by the log
  itself, following §3.3's "bodies are opaque" discipline.
- `attestation_pk` is a fresh ML-DSA-87 keypair the candidate replica host
  generates locally *before* the ceremony and presents for signing — the same
  "identity is presented, not assigned" pattern ADR-0011 §2 uses for node
  registration. The replica's own keystore seals the private half the same way
  node keys are sealed (B6).
- `not_before`/`expiry` bound the window a placement is valid, exactly as
  `node-sign` already does — an expired slot is not revoked, it simply stops
  working, which gives a time-boxed trial placement for free.

### Boot-time gate (new; `bootstrap.go`'s `Install`)

Before `loadOrCreateKeys`'s result is handed to `channel.NewStaticFromSeed` and
`identity.FromSeed`, a replica that opts into this gate (see "Reconsider if" on
making it mandatory) must:

1. Load or generate its local attestation keypair (first boot: generate and
   present the public half out-of-band for an admin to sign offline; every
   boot after: load the sealed private half).
2. Verify, against the replicated Bedrock log it already fetches and verifies
   for other reasons, that a `replica-sign` entry names its own
   `attestation_pk`, is not past `expiry`, and has no later `replica-revoke`
   naming the same placement.
3. Sign a local challenge with the attestation key as proof of possession
   before proceeding — the same shape as `ChannelInit`'s signature over
   `server_random`, reused rather than invented.

A replica that fails this check does not start. This is the one new refusal
path; everything downstream of it (the control channel, the PSK deriver) is
unchanged.

### Alternatives rejected

**Gate on infrastructure/IAM alone (network ACLs, cloud account boundaries,
"only our VPC can reach Postgres").** This is already true today and is not
nothing — but it is exactly the boundary R11 is about: it raises the bar to
"compromise the autoscaler's decision logic or the IaaS account," not to
"forge a cryptographic admission." An attacker who can influence what the
autoscaler launches is, under this alternative, indistinguishable from an
operator. Rejected as the sole mechanism; retained as useful defense-in-depth
alongside the Bedrock gate, the same layering `BoundedDriver` already applies
to region allowlists (#327).

**Reuse the existing `UserRoleScaler` PAT / `SetupKey` primitive**, the way
relay and TURN enrollment already do (#311, #319, #329). Rejected: that role
is deliberately narrow — a hard allowlist of a handful of compute-provisioning
endpoints (`server/management/server/permissions/roles/scaler.go`), chosen
specifically so a compromised Scaler credential cannot reach anything beyond
spinning up/down capacity-bound compute. Routing access to the PSK master and
control-channel identity through it would make the Scaler role a path to full
control-plane compromise, defeating the entire reason that role is scoped the
way it is.

**A single always-on "replica-admit" key at authority weight, held by a
provisioning service.** This is just `node-sign`'s key with a different name,
continuously exposed on a host an attacker only needs to reach once. Rejected
for the reason ADR-0014 and ADR-0016 both already established: a key's
capability is not reduced by where it is kept.

**Do nothing; leave R11 as an accepted, undefended risk**, the way §7's other
non-goals are stated. Rejected for now because, unlike (say) metadata exposure
(§7 item 1), this risk has a cheap, precedented mechanism available
(Bedrock already exists and already solves the structurally identical problem
for nodes) — leaving it undefended would be declining to reuse a tool already
in the tree, not accepting a genuinely unavoidable cost.

---

## Consequences

### Positive

- Closes the specific asymmetry R11 names: adding a replica becomes at least
  as hard as adding a node, not easier.
- No new cryptographic primitive, wire format family, or ceremony tool — this
  is two new op codes in a log format already built to add them (§3.1's table
  is not closed), signed with the authority ceremony tooling that already
  exists (`karst-bedrock sign`), verified with the verifier every node already
  runs.
- The "Alternatives rejected" entries double as a second audit of why the
  Scaler role's narrow allowlist (#330, #332's `relayDeenroll` design) was the
  right call there — this ADR leans on that narrowness rather than eroding it.
- A future control-replica driver inherits the same defense-in-depth posture
  `BoundedDriver` gives relay/TURN pools: a placement allowlist the driver
  checks independently of what the Bedrock log already enforces.

### Negative

- **This only protects Bedrock-enabled deployments.** Bedrock is opt-in per
  account, default `ModeOff` (`bedrock.Store.Configuration`). A deployment that
  has never turned Bedrock on for any account has no quorum anywhere to gate
  this with — for that deployment, R11 remains exactly as open as it is today,
  full stop. This must be stated as a hard precondition, not softened: **there
  is no safe path to autoscaled control replicas without Bedrock**, and a
  future control-replica driver must refuse to run against a deployment where
  it is off, rather than silently falling back to today's DB-credential-only
  trust.
- **The scoping mismatch named above is not resolved here.** Which account's
  chain — or whether a new deployment-wide chain is needed — speaks for
  replica admission is left open; implementing this ADR requires answering
  that first (see "Open question").
- **A second, parallel admission ceremony for operators to run**, alongside
  node admission. More ceremony surface is more opportunity to get a ceremony
  wrong, the same cost ADR-0016 named for its own tier.
- **The boot-time gate is a new way for a replica to fail to start** — an
  expired or missing `replica-sign` entry now joins "can't reach Postgres" as
  a startup failure mode operators must learn to diagnose.
- This ADR designs the admission mechanism; it does **not** design the
  autoscaling driver itself (how placements are chosen reactively within an
  admitted set, how `list()`/`destroy()` work, how this interacts with HAProxy
  membership). That remains separate, larger work, gated by this ADR's
  mechanism existing first — consistent with `THREAT-MODEL.md` §9's new gate.

### Open question

**Which Bedrock chain speaks for the deployment, not any one tenant, when
signing `replica-sign`?** Candidates: (a) designate one operator-chosen
account's chain as the deployment's own "fleet" authority by convention; (b) a
new zone-level chain, parallel to but distinct from per-account chains,
scoped to the deployment rather than any tenant — closer to what `genesis`'s
already-present but underused `zone` field may have been for. This ADR takes
no position; it must be answered, and recorded as its own decision, before
`replica-sign`/`replica-revoke` are implemented.

### Reconsider if

- A deployment pattern emerges where Bedrock is reliably off but
  control-replica autoscaling is still wanted — at which point the honest
  answer is still "not safely," and the right fix is making Bedrock adoption
  easier, not weakening this gate.
- Auto-revocation (the "Phase 2" sketched above) turns out to matter in
  practice — design that narrow tier then, using ADR-0016's reasoning as the
  template, rather than folding it into this decision speculatively.
- The zone-level-chain question above is answered in a way that changes what
  `genesis`'s `zone` field means deployment-wide — that answer may have
  consequences for this ADR's gate that are not visible yet.
