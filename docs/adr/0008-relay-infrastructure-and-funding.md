# ADR-0008: Relay infrastructure and funding model

- **Status:** Accepted
- **Date:** 2026-08-09
- **Deciders:** TBD
- **Related:** ADR-0007 (licensing), PLAN.md §5, §6, §13 Q4

---

## Context

Relays carry the fraction of peer pairs that never achieve a direct path
(§6 targets ≥90% direct, so roughly 10%), plus brief bootstrap traffic for
everyone else. Somebody has to pay for that bandwidth. PLAN.md §13 Q4 asked
who.

The question was sharpened by a specific proposal: could Karst use existing
DERP relay infrastructure rather than standing up its own?

---

## Decision

### 1. Karst does not use Tailscale's relay fleet, and will not

Two independent reasons, either sufficient:

- **Ethical, and dispositive on its own.** Routing a competing product's
  traffic over Tailscale's bandwidth without their consent is free-riding.
  This holds regardless of whether a technical path exists. The same reasoning
  applies to community-run `derper` instances in the Headscale ecosystem: many
  run without `--verify-clients`, which makes them *reachable*, not
  *available*.
- **Technical.** Tailscale's production fleet verifies connecting clients
  against their control plane. A Karst node key is not in it.

### 2. No DERP wire compatibility

Reusing the protocol would be licence-clean — DERP is BSD-3, which our
dependency allowlist permits, and reimplementing a wire protocol in Rust from a
BSD-3 Go codebase is legitimate. It is rejected on other grounds:

- DERP's client↔relay layer authenticates with **Curve25519, classical only**,
  regressing §5's hybrid `X25519MLKEM768` requirement. The exposure is bounded
  — relays carry PHREATIC ciphertext, so breaking the outer layer yields metadata
  rather than content — but metadata under retroactive decryption is precisely
  what a PQ-mandate buyer is trying to avoid.
- DERP addresses frames by 32-byte node keys; ours are 1184 and 1952 bytes.
  A 32-byte node ID mapping is possible but is not compatibility.
- **Decisively: wire compatibility would create the free-riding vector rather
  than close it.** A client able to speak to any unverified `derper` is a
  product whose default behaviour consumes strangers' bandwidth.

**This is a standing constraint, not a one-time judgement.** `karst-relay`
must not gain a DERP compatibility mode, and the relay registry must reject
`derp://` endpoints. Recorded here so a future contributor does not add it as a
helpful-looking feature.

We do borrow DERP's *design* — mesh presence, home-relay selection,
relay-first-then-upgrade. That prior art is credited explicitly in
`spec/phreatic-v1.md` and §5.

### 3. The relay is co-located with the coordination server by default

The self-hoster **already operates a public-IP host**: the coordination server
must be reachable or nothing works. Shipping the relay in the same
`docker-compose` and as the same static binary makes the marginal
infrastructure cost zero, and on a commodity VPS with bundled egress the
fallback traffic sits inside the included allowance at small scale.

For the self-hosted-first target this dissolves most of Q4. What remains is
real but narrower: a single relay is a single region, so a geographically
spread aquifer gets poor fallback latency, and it is a single point of failure.

### 4. Standard TURN as a pluggable sustained-fallback datapath

This is the answer to "reuse existing infrastructure," and it works because
TURN (RFC 8656) is a **standard with a real provider ecosystem** rather than
one vendor's internal fleet. A self-hoster can point at coturn they already
run, or rent from a commodity provider for cents, and solve the regional
coverage and SPOF problems without anyone donating bandwidth.

- **Supplement, not replacement.** DERP's presence model — always connected, so
  peers are reachable before any direct path exists — has no TURN equivalent.
  `karst-relay` retains bootstrap and presence; TURN carries the sustained
  fallback where regional coverage matters.
- **ChannelData framing** (4-byte header) rather than Send/Data indications, to
  minimise MTU impact. Total of datapath MTU plus PHREATIC overhead plus 4 bytes
  must fit the path MTU; asserted in tests.
- **Ephemeral credentials.** The control server mints time-limited HMAC
  credentials (the standard TURN REST scheme) and distributes them via netmap.
  Static TURN credentials must never be placed in a netmap. Note that this
  makes TURN credentials one more netmap secret, reinforcing the
  netmap-encryption requirement from §2.6 and the Phase 3 exit criterion.
- TURN over TLS/TCP is available as a last resort on UDP-blocked networks,
  though `karst-relay` on port 443 already covers that case.
- **Privacy is identical to a relay:** the TURN provider learns who talks to
  whom, when, and how much. Same disclosure obligations as §5.

### 5. No default public Karst fleet

Ruled out, and the reason follows directly from a decision already taken:
**ADR-0007 forecloses the revenue that would fund egress.** A free global fleet
would be an open-ended cost with no funding mechanism and, worse, an obligation
that cannot be gracefully exited once people depend on it.

### 6. Community relay pool: opt-in, strict-mode mandatory

A volunteer pool is permitted and supported in the relay registry, with two
conditions that §5 currently leaves optional:

- **Admission control is mandatory, not optional** — signed-roster only. An
  open relay becomes an abuse conduit and hands its operator traffic they
  cannot inspect and did not agree to carry.
- **The privacy cost is disclosed at the point of configuration**, not buried
  in documentation. A volunteer relay operator learns the metadata of everyone
  routed through them. Quietly defaulting users of a security product onto
  strangers' relays would be indefensible; opting in with informed consent is
  fine.

---

## Consequences

### Positive

- Q4 largely dissolves for the self-hosted-first target: zero marginal cost,
  one deployment artefact.
- Regional coverage and SPOF are solvable with commodity infrastructure the
  operator already has or can rent cheaply.
- No dependence on, or extraction of value from, another project's
  infrastructure.
- Self-hosted relay is the better privacy answer as well as the better
  economic one — the operator and the data subject are the same party.

### Negative

- TURN is a second relay code path: allocation, permissions, channel binding,
  credential refresh, and its own slice of the NAT test matrix. **This adds
  scope to Phase 4, which is already the longest phase at 10 weeks.** Since
  the co-located relay covers the base case, TURN is the designated
  slip candidate within Phase 4 — it moves to Phase 6 if the NAT matrix work
  overruns, rather than compressing the matrix work.
- Self-hosters wanting multi-region fallback must configure something. There is
  no zero-configuration global default, by design.
- Ruling out a public fleet forecloses a plausible future adoption lever.
  Reversing it would require revisiting ADR-0007 first.

### Follow-ups

- §5 gains the co-location default, the TURN fallback, and the DERP prior-art
  credit; §5's "optional strict mode" becomes mandatory for pool relays.
- Phase 4 scope gains the TURN client, control-server credential minting, and
  coturn in the NAT matrix.
- Relay registry validation must reject `derp://` endpoints.
