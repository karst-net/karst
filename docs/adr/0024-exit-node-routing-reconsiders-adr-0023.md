<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-0024: Exit-node routing satisfies the SC-05 request; forcing it from the control plane does not

- **Status:** Accepted
- **Date:** 2026-09-14
- **Deciders:** TBD
- **Related:** ADR-0023 (declines account-owner activity visibility as a
  first-class feature; this is the "Reconsider if" case it named), UC-07
  (`docs/USE-CASE-ANALYSIS.md`), `docs/subnet-routers-and-exit-nodes.md` §3
  (exit-node privacy and consent), `spec/karst-control-v1.md` §5.4 (route
  offers), `spec/ponor-v1.md` §11 (what a relay operator learns), GitHub
  issue #150

---

## Context

Reopening #150, the proposal was: let an administrator **force traffic
through a relay**, so the relay can provide the visibility ADR-0023 declined
to build as an account-owner feature.

Taken literally, this does not work, and it's worth recording precisely why,
since it is easy to conflate "relay" and "exit node" — the opening of
`docs/USE-CASE-ANALYSIS.md` exists specifically to prevent that conflation,
and this proposal walked into it. Ponor (the relay) is a **ciphertext-only
NAT-traversal fallback between two enrolled mesh peers**. `spec/ponor-v1.md`
§11 states exactly what its operator learns — node IDs, connection timing,
traffic volume, packet sizes, source `IP:port` — and states plainly that
**"the content of any packet"** is not visible, because "Ponor derives no
session key" (§13.3). This is a formally verified property (`ponor.pv`,
`ponor-norelayid.pv` in CI), not an implementation gap, and it protects every
device that ever falls back to that relay, not only a device someone might
want to monitor. Re-architecting Ponor to decrypt would mean removing a
tested invariant from shared infrastructure to build a single-household
feature — a wildly disproportionate trade, and one this ADR declines for the
same reason ADR-0023 declined silent surveillance: it would make an
administrator's reach over other people's traffic larger, more silently,
for a benefit achievable another way (below).

The **exit node** (UC-07) is a different thing entirely, and it already does
what the proposal wants. An exit node is, by construction, the point where
overlay ciphertext becomes plaintext again to reach the real Internet — see
`docs/subnet-routers-and-exit-nodes.md` §3: "The gateway is a full traffic
intermediary for that traffic in exactly the sense any VPN exit node is: it
sees cleartext destinations and, for unencrypted protocols, cleartext
payloads." Even for TLS-protected destinations, the exit node sees the SNI
hostname in the unencrypted `ClientHello`, which is exactly how ordinary
network-level parental-control appliances work today, with no packet
decryption at all. **This capability already exists and needs no new Karst
engineering** — it's inherent to what UC-07 already ships.

The open question is therefore not "can an exit node provide visibility" (it
can, today) but **"can an administrator force a device onto one without the
device's own consent?"** — and here Karst already has a deliberate answer,
predating this issue: no.

### Exit-route consent cannot be forced from the control plane, on purpose

`spec/karst-control-v1.md` §5.4 is explicit: "A recipient **MUST NOT**
activate an `EXIT` offer until its local operator has consented to that
route ID." `docs/subnet-routers-and-exit-nodes.md` §3.2 restates the
rationale: "the control server can *offer* `0.0.0.0/0`/`::/0`, **never
activate it**... the console can report an offered or active exit route but
**cannot manufacture consent on a client's behalf**." This is enforced, not
just documented: `karst exit-node use`/`disable` are served only on
`karstd`'s primary control socket, bound `0700`/`0600`
(`bins/karstd/src/ipc.rs::bind`) — root-only on a Unix host. The separate
`--status-socket` listener is deliberately narrower: it is read-only
(`bins/karstd/src/main.rs`: "a second, unprivileged read-only socket"). A
local, unprivileged user cannot activate or disable an exit route; only
whoever holds root/administrator on that specific machine can.

This is the same boundary ADR-0023 protects, one layer down the stack: an
account owner should not be able to silently redirect a device's traffic
that the device's own operator did not agree to. It should not be relaxed
for this request any more than the audit log should have been reused for
it.

## Decision

**No control-plane change.** Exit-route consent stays local, durable, and
un-forceable from the console or API, exactly as `spec/karst-control-v1.md`
§5.4 and `docs/subnet-routers-and-exit-nodes.md` §3.2 already specify.

**The request is already satisfiable today, when the administrator is also
the machine's local operator.** Karst already separates two roles that this
proposal conflated: the *enrolled Karst user* of a device, and the *local
operator* who holds root/administrator on it. For a family-managed device —
a parent who sets up, and holds administrator rights on, a child's
computer — the parent already **is** the local operator in Karst's model,
distinct from the child's enrolled-user identity. Nothing prevents the
parent from being the one who runs:

```sh
karst exit-node use <route-id>   # on the child's device, as its administrator
```

once, pointing at an exit node the parent operates. `docs/subnet-routers-and-exit-nodes.md`
§3.2's durability guarantee — consent "survives config reload, daemon
restart, and a missed netmap push" — means this is a one-time setup step,
not a recurring chore. Because the child's own OS account (per the ordinary
practice of not giving a managed device's daily user root) cannot reach the
`0600` control socket, they cannot `exit-node disable` it either. Visibility
then comes from ordinary host-side tooling on the parent's exit-node
gateway — DNS query logs, TLS SNI inspection, or a full logging/filtering
proxy if wanted — using the plaintext (or SNI-visible) traffic that gateway
already legitimately sees as the tunnel's exit point. None of this requires
new Karst code.

### Where this genuinely does not reach

- **A device whose enrolled user also holds local administrator rights on
  it** (a personally-owned, self-administered machine) can always run
  `exit-node disable` themselves. No client-side software — Karst or any
  competitor's — can prevent a local administrator from reconfiguring their
  own machine; achieving that requires device supervision/MDM, which is a
  different product than a VPN client and out of scope here.
- **This is still fundamentally UC-07's existing privacy disclosure**, not a
  new, quieter one: `docs/subnet-routers-and-exit-nodes.md` §3 already states
  plainly that an exit node "sees cleartext destinations." Nothing about
  this ADR changes what that section discloses; it only identifies that the
  disclosure already covers this scenario.

### Alternatives rejected

- **Force exit-route activation from the console/control plane,
  bypassing local consent**, so an administrator without machine access
  could still mandate it remotely. Rejected for exactly ADR-0023's reason:
  it turns a documented, disclosed privacy trade-off the *local operator*
  currently makes for themselves into one an account owner can impose on
  someone else without their machine ever being touched — the precise
  asymmetry ADR-0023 objected to, relocated to a different layer.
- **Add a setup-key flag that pre-consents an exit route at enrollment**,
  removing the one manual `exit-node use` step. Plausible as a pure
  onboarding-ergonomics improvement — it does not change who can dissent
  locally, since local disable is still root-gated regardless of how consent
  was first granted — but it is a distinct, smaller feature from what #150
  asked for, and is not needed to satisfy this issue. Left as a
  `good first issue`-sized idea if anyone wants it, not committed here.
- **Force traffic through the Ponor relay for metadata visibility**, as
  literally proposed. Rejected per the Context section above: it cannot
  deliver website-level visibility at all (no session key, verified), and
  the metadata it *could* surface is already disclosed as visible to any
  relay operator (`THREAT-MODEL.md` §7 item 1) — forcing the path would add
  operational cost for the same information the relay would only reveal for
  mesh-peer traffic, not general Internet destinations, since exit-bound
  traffic isn't necessarily relay-scoped mesh traffic at all.

## Consequences

### Positive

- Resolves the underlying want in #150/SC-05 with zero protocol or
  control-plane changes — the existing UC-07 exit-node feature already
  covers it once the parent/administrator holds local machine control.
- Reaffirms, rather than erodes, the exit-route consent boundary
  (`spec/karst-control-v1.md` §5.4) and ADR-0023's disclosure principle,
  keeping both internally consistent instead of carving out a household-
  specific exception.
- Ponor's "no session key" invariant is untouched — no re-verification of
  the formal models is needed.

### Negative

- Does not help an administrator who lacks local machine access to the
  device in question (see "Where this genuinely does not reach" above).
  That is a real limit on the scenario, stated plainly rather than implied
  away.
- The one remaining manual step (`karst exit-node use` at setup) is friction
  ADR-0023-style solutions don't have to pay; a future enrollment-time
  pre-consent feature (noted above, not committed) could remove it.

### Reconsider if

Karst ever adds device supervision/MDM-style enrollment where the account,
rather than the device's local operator, is the intended holder of ultimate
control over a specific device (e.g., a company-owned, non-BYOD fleet with a
different consent model by design). That is a materially different premise
from every other actor boundary in `docs/USE-CASE-ANALYSIS.md` and would
need its own ADR, not an amendment to this one.
