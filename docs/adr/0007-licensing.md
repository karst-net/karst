# ADR-0007: Licensing and contribution model

- **Status:** Accepted
- **Date:** 2026-08-08
- **Deciders:** TBD
- **Related:** ADR-0003 (greenfield rationale), `LICENSING.md`, PLAN.md §13 Q2/Q5

---

## Context

Karst must satisfy three goals that pull against each other:

1. **Auditability.** For a post-quantum VPN, "you can read and verify the
   crypto" *is* the credibility of the product. This is the dominant goal.
2. **Adoption.** Self-hosted relays (§5), distro packaging, mobile clients, and
   third-party protocol implementations all depend on low licensing friction.
3. **Commercial defensibility.** Preventing a hosted "Managed Karst."

**The project owner has explicitly deprioritized (3)** in favour of community
and security. This ADR is written on that basis; the decision below would look
different for a revenue-driven project, and any future reader considering a
change should start by re-examining that premise.

### Constraints that eliminate options before preference applies

- **GPL-family licenses conflict with iOS App Store distribution.** The FSF's
  position is that App Store usage rules are incompatible with GPL §6; VLC was
  removed from the store over this in 2011. Phase 7 ships an iOS client, so the
  node agent, CLI and crates **cannot** be (A)GPL. This is dispositive for the
  client side.
- **A future in-kernel datapath requires GPLv2 compatibility.** Rust-for-Linux
  is GPLv2. Apache-2.0 is not GPLv2-compatible; MIT and BSD-3 are.
- **PQ cryptography has patent history** (NIST bought out patent claims around
  Kyber), so an express patent grant is worth more here than usual.

The last two constraints appear to conflict. They are resolved by the Rust
ecosystem convention of dual `MIT OR Apache-2.0`: downstream picks, so the
project gets Apache's patent grant *and* GPLv2 compatibility via the MIT arm.

---

## Decision

| Component | License |
|---|---|
| `crates/*`, `karstd`, `karst`, `karst-relay` | **MIT OR Apache-2.0** (dual) |
| `karst-control`, `karst-console`, `karst-portal` | **AGPL-3.0-or-later** |
| `spec/`, ADRs, formal models, docs | **CC-BY-4.0** + royalty-free implementation grant |
| Contributions, all repos | **DCO** (Developer Certificate of Origin) |

### Why AGPL for the server, on non-commercial grounds

AGPL is normally chosen to close the SaaS loophole. That is not the reason
here. The reason is that **the coordination server holds per-pair PSKs
(§2.6) and computes every node's packet filter.** A user whose operator runs a
modified, unpublished server cannot audit the component with the most
concentrated authority in the system. AGPL §13 obliges that operator to publish
their modifications, which converts "trust your operator" into "verify your
operator." That is a security property, and it is the justification of record.

The commercial side effects are accepted but not sought: enterprises with
blanket AGPL bans (Google's is well known) may decline to deploy. Without a CLA
there is no commercial license to sell them as an alternative. This is a real
cost and is accepted deliberately.

### Why the relay is permissive

§5 identifies third-party relay operators as a primary adoption lever. Copyleft
on the relay works directly against that. Relays see only ciphertext, so the
auditability argument that justifies AGPL for the control server does not
apply to them.

### Why DCO rather than a CLA

A CLA exists to preserve relicensing and dual-licensing optionality. With
monetization deprioritized, that optionality has no consumer, while the CLA's
costs — a signature barrier for casual contributors, and the appearance of
corporate capture — fall directly on the community the project is optimizing
for. DCO is sufficient for provenance and is the lighter instrument.

### Why `-or-later` rather than `-only`

`AGPL-3.0-only` is the correct choice when a CLA lets you relicense centrally.
With DCO and no CLA, `-only` would permanently freeze the project on AGPLv3
even if the FSF publishes a successor. `-or-later` preserves that path and is
the FSF's own recommendation. The accepted risk is that future license versions
have unknown terms.

---

## Consequences

### Positive

- Every line of the system is open source under an OSI-approved license.
  Distro packaging, security research, and third-party implementations are all
  unobstructed.
- Clients stay App Store-compatible and kernel-datapath-compatible.
- Anyone running a modified coordination server must publish it.
- Contributing requires a `Signed-off-by` line and nothing else.

### Negative

- **Relicensing the server is effectively foreclosed.** Without a CLA, any
  future change requires the agreement of every contributor. Commercial
  dual-licensing is off the table in practice. This is the principal
  irreversible consequence of this ADR.
- Enterprises with AGPL prohibitions have no commercial-license escape hatch
  and may simply not adopt.
- No license-based protection against a hosted competitor; the only remaining
  lever is trademark.

### Follow-ups

- **Trademark is now the sole defensive instrument**, which sharpened PLAN.md
  §13 Q5. The project's original name collided directly with ThreeFold's
  Mycelium, an encrypted overlay network in the same category and language;
  it was renamed to **Karst** ([ADR-0010](0010-project-name-and-component-naming.md)).
  Because this ADR forecloses licence-based defensibility, mark distinctiveness
  carries more weight here than it would for most projects, and formal
  clearance is a Phase 0 exit criterion.
- License allowlists in CI (`cargo deny`, `go-licenses`) from Phase 0, before a
  transitive GPL dependency becomes expensive to unwind.
- `SECURITY.md` with a disclosure policy and an explicit **safe harbour for
  good-faith research**. A project optimizing for security and community should
  not leave researchers guessing about legal exposure.
- Publishing cryptographic source requires a notification email to BIS and NSA
  under EAR 740.13(e). Import restrictions in France, China, and Russia apply
  to VPN software and need a compliance note, not a code change.
- Canonical license texts must be fetched from SPDX or gnu.org, never
  transcribed by hand.
