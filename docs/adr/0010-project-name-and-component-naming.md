# ADR-0010: Project name and component naming

- **Status:** Accepted
- **Date:** 2026-08-09
- **Deciders:** TBD
- **Related:** ADR-0007 (licensing — makes trademark the sole defensive lever), ADR-0009 (prior-art review that surfaced the collision), PLAN.md §13 Q5

---

## Context

The project was originally called **Mycelium**, chosen for the metaphor: a vast
distributed organizm, connected below the surface, resilient and self-healing.

The prior-art review in ADR-0009 established a direct collision. ThreeFold's
[Mycelium](https://github.com/threefoldtech/mycelium) is an actively developed
end-to-end encrypted overlay network, written in Rust, whose daemon binary is
literally `myceliumd` — the exact binary name this project had chosen. Same
name, same product category, same language, same binary.

Two things make this more serious than an ordinary naming clash:

1. **ADR-0007 forecloses license-based defensibility.** With no CLA and no
   commercial license, **trademark is the only defensive instrument the project
   has.** A weak or contested mark leaves nothing.
2. **The name is structural.** It is baked into repo paths, crate names, binary
   names, the DNS suffix, and every SPDX header. Renaming is nearly free before
   Phase 0 scaffolding and expensive immediately after.

---

## Decision

The project is renamed to **Karst**.

Karst is the terrain formed where soluble rock is dissolved by water, riddled
with underground channels, caves and conduits — an invisible, deeply
interconnected network beneath an ordinary-looking surface. It preserves the
original metaphor (hidden distributed connection) while moving out of the
fungal namespace entirely.

### Why Karst over the alternatives

Candidates were scored on metaphor fit, mark strength, and ergonomics.
Karst was the only one at or near the top of all three.

| | Karst | Pando | Kelp | Cenote | Ponor |
|---|---|---|---|---|---|
| Metaphor | Hidden interconnected passages | One organizm, many nodes | Dense canopy | Nodes onto a hidden network | Entry into the network |
| Mark strength | **Very high** — rare, essentially no tech prior use | Moderate — defunct Pando Networks (P2P) | Low — common word, existing tech uses | High | Very high |
| Ergonomics | **One syllable, unmisspellable** | Good | Good | 3 syllables, pronunciation beat | Good |

Karst's one weakness is that it names *terrain* rather than *connection*.
That was weighed and accepted: it is a distinction noticed once and never
thought about again, whereas one syllable and zero spelling ambiguity pay out
daily for the life of the project. Mark strength also carries unusual weight
given ADR-0007, and Karst is the strongest available.

### Component naming

The name extends into a coherent system, which was itself part of the case
for it:

| Concept | Name | Derivation |
|---|---|---|
| Project, CLI, daemon | **Karst** — `karst`, `karstd` | |
| Handshake and encrypted transport | **PHREATIC** (was SPORE) | Cave passages below the water table, permanently submerged |
| Relay protocol and service | **Ponor** | Where a surface stream vanishes into the karst system — precisely a relay's role |
| Path discovery / NAT traversal (§6) | **AVEN** (added 2026-08-14) | A shaft connecting the cave system upward to the surface — what cavers look for to find a way out |
| Network lock (§4.5) | **Bedrock** (was Mycelium Lock) | The rock karst forms in; anchoring trust |
| Name service (§7) | **KarstDNS** (was MycoDNS) | |
| Mesh DNS suffix | `.karst.` | |
| Crates | `karst-*` | |

### What deliberately was *not* renamed

**`netmap` stays `netmap`.** "Survey" was considered — it is what cavers call
the maps they make, and it fits the system neatly. It was rejected because
`netmap` is the established industry term for this object and the documents
must stay legible to people arriving from Tailscale, Headscale or NetBird.
Branding an internal data structure buys flavor at the cost of clarity, and
clarity wins. "Survey" remains available as user-facing wording in the console
if it ever helps.

This is the general rule: **invented proper nouns get themed names; standard
technical terms do not.**

---

## Consequences

### Positive

- The strongest available trademark, which matters disproportionately here.
- Excellent CLI ergonomics: `karst up`, `karstd`, `karst status`.
- A naming system with room to grow, rather than isolated names.
- No association with, or confusion against, an unrelated active project.

### Negative

- Every document, path, crate and header changes. Done now, before scaffolding,
  this is a text substitution; after Phase 0 it would touch published artifacts.
- The mycology metaphor was a genuinely good fit and is lost.

### Clearance — complete

**Trademark clearance for "Karst" completed successfully on 2026-08-09.** The
name is confirmed and the Phase 0 gate is satisfied.

**Correction to this ADR as originally drafted:** it listed the package
registries inside "clearance," conflating two independent axes. Trademark
clearance concerns likelihood of confusion within commercial classes and is
what counsel performed. **Package and org namespaces are first-come,
first-served and largely indifferent to trademark.** They are recorded
separately below.

**Ponor** was the designated fallback and is no longer needed for that purpose;
it remains the relay protocol name.

### Namespace reservations

| Namespace | Result | Status |
|---|---|---|
| GitHub org | **`karst-net`** — `karst`, `karstnet`, `karstlabs` all taken | ✅ created 2026-08-09 |
| npm org | `karst` unavailable; scope taken under an alternate name | ✅ created 2026-08-09 |
| Domain | — | ⏳ pending |
| crates.io | `karst` held as a `0.0.0-reserved` placeholder since Sept 2024 | ⚠️ workaround below |
| PyPI | `karst` is an **active** unrelated project (v0.2.9, June 2026) | ❌ not pursued — no Python in the plan |

**The `karst` binary name is preserved regardless.** The CLI crate is published
as `karst-cli` with `[[bin]] name = "karst"`, so what users type is unaffected
by the crates.io placeholder. This is the only concession the namespace
situation forces.

**crates.io policy note.** Pre-publishing empty `karst-*` stubs to reserve names
would be squatting, which crates.io policy discourages and which is the same
free-riding logic ADR-0008 rejected. Crates are published as they become real
during Phases 1–2, with genuine content — README, license, and a doc comment.

### The namespace is crowded — recorded for future reference

Four independent claimants to "karst" were found: a personal GitHub account
(Karst is a common Dutch given name), an active PyPI project in AI developer
tooling, a crates.io placeholder for volumetric rendering, and a karst-geology
research organization. None are in networking, so the trademark position is
sound, but the name will be contended in most namespaces indefinitely.

Ponor returned clean on three of four registries. **Had this been known before
clearance, Ponor would have been the stronger choice.** It is not worth
re-clearing now — clearance is the slow, expensive step and it is done — but
the sequencing lesson is worth recording: **check namespace availability
*before* commissioning trademark clearance**, not after. The cheap check should
gate the expensive one.

### Crate naming conflict

The GitHub org `karst-net` collides visually with the planned `karst-net` crate
(UDP sockets, GSO/GRO, endpoint management) from PLAN.md §3.1. The crate is
renamed **`karst-transport`** to avoid `github.com/karst-net/karst` containing a
`karst-net` crate that has nothing to do with the org.

Ongoing obligations, since ADR-0007 leaves the mark as the project's only
defensive instrument:

- Register the mark rather than relying on common-law rights alone.
- Publish a trademark usage policy with the first public release — anyone may
  fork the code, nobody may call their fork Karst.
- Reserve the package and org names now, before the first public commit, so
  they cannot be taken during Phase 0.
