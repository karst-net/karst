<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-0039: Air-gapped deployment is a run-time claim, not a build-time one

- **Status:** Accepted
- **Date:** 2026-09-28
- **Deciders:** TBD
- **Related:** #131 (disposition record: air-gapped/CNSA-strict — pursue),
  #167 (this issue), #130 (Bedrock anchor-age demonstrations),
  ADR-0018 (CNSA 2.0 as the sole suite), `docs/operations/air-gapped-deployment.md`
  (the runbook this ADR produces)

---

## Context

#131's disposition pass recorded air-gapped deployment as "pursue," and
flagged something important up front: *"most of what 'air-gapped' needs is
already true incidentally... #167 is about verifying and documenting that
rather than building a parallel product variant from scratch."* #167 itself
lists four open questions rather than a design, and says explicitly that the
first step is an ADR defining what "air-gapped" commits to before any
implementation work.

"Air-gapped" is ambiguous between two different claims, and #167's own
scope section names this directly:

- **Run-time air-gapped**: a *deployed* Karst instance keeps working
  indefinitely with no network path out except the mesh peers and control
  plane the operator explicitly stood up — no implicit reachability
  requirement to anything else, ever.
- **Build-time air-gapped**: *compiling Karst from source* inside a network
  with no path out at all, using no package registry the sealed network
  doesn't already mirror.

These are not the same claim, and conflating them is exactly the trap #167
warns against. This ADR resolves which one "air-gapped deployment" means
going forward, checked against the tree rather than assumed:

### What's already true, verified directly

- **No baked-in phone-home, telemetry, or public-DNS-fallback surface.**
  `bins/karstd/src/*.rs`, `crates/karst-dns/src/lib.rs`, and `web/console`
  were grepped for hardcoded external hosts, CDNs, fonts, and analytics
  endpoints. The one apparent hit (`1.1.1.1:53` in `karst-dns`) is confined
  to a `#[cfg(test)]` fixture, not a production default. `karst-dns`'s
  resolver takes its upstreams from configuration; there is no compiled-in
  public resolver it falls back to.
- **The embedded local IdP has no external OIDC dependency.**
  `server/management/server/idp/embedded.go` wraps Dex's `LocalConnectorID`
  — a self-contained connector, not a redirect to an external identity
  provider. An operator is never forced to reach outside their own
  deployment for authentication.
- **`docs/GETTING-STARTED.md`'s own config examples carry no hosted
  default** for `[control] server`, relay, or TURN — every example is the
  operator's own host (`karst.example.com`), never a Karst-operated shared
  service. There is nothing to accidentally dial out to; an operator's
  control plane and relay are exactly as reachable as the operator makes
  them, which for an air-gapped network means "only from inside it."
- **CNSA 2.0 is already the sole cryptographic suite** (ADR-0018) — there is
  no "strict mode" to add as a separate profile; every deployment already
  gets the CNSA-only behavior a "CNSA-strict variant" would have asked for.
- **Bedrock anchor-age has no external time-source dependency — the
  premise in #167's own text is incorrect, and worth correcting on the
  record.** #167 asks what "air-gapped" means for anchor-age validation,
  "a mechanism whose whole point involves external verification." Checked
  directly against `spec/bedrock-v1.md` §3–4: an `anchor` is a signed
  head-hash and sequence number of the account's *own* audit log, signed by
  an authority or anchor key that lives on the deployment's own admin
  device or server (ADR-0016) — never a blockchain anchor, RFC 3161
  timestamping authority, or any other externally-verified time source.
  `management_karst_bedrock_anchor_age_seconds` (`docs/observability.md`)
  is a wall-clock delta since the last such locally-signed entry. There is
  no external reachability question here at all: the whole ceremony is
  self-contained within the deployment, air-gapped or not.
- **Packaging ships prebuilt binaries, and mostly needs nothing else at
  install time.** `scripts/build-macos-pkg.sh` and
  `scripts/build-windows-msi.ps1` make no network calls; the Windows MSI's
  one native dependency (Wintun) is already vendored in-repo
  (`packaging/windows/vendor/wintun`), not fetched at build time.
  `packaging/scripts/postinstall.sh` only reloads systemd units — no
  package-manager or network calls.

### What's genuinely missing, or genuinely out of scope

- **The Linux `.deb`/`.rpm` packages declare OS-level runtime
  dependencies** (`packaging/nfpm/karst-client-linux.yaml`: `zenity`,
  `pkexec` on Debian; `polkit`, recommending `zenity`, on RPM) for
  `karst-setup`'s desktop consent prompts. On a machine with no reachable
  package repository and no local mirror, `apt`/`dnf` cannot resolve these
  at install time — a real, concrete air-gapped-install requirement, not
  a code defect. The fix is operational (pre-stage these OS packages on
  the air-gapped network's own local mirror before installing Karst), not
  a Karst change — see "Alternatives rejected."
- **Building Karst itself is not air-gapped today, by a wide margin.**
  There is a `Cargo.lock` but no vendored crate tree; no Go `vendor/`
  directory; a `pnpm-lock.yaml` but no offline-installable `node_modules`
  snapshot; and this session's own work needed `protoc`,
  `protoc-gen-go`/`protoc-gen-go-grpc` fetched via `go install`, and crates
  fetched from crates.io — all requiring outbound network reachability.
  Three independent package ecosystems (Cargo, Go modules, npm/pnpm) would
  each need their own mirror or vendor tree for a literally sealed build
  pipeline. No user or deployment has asked for this — the same
  no-demand-signal bar #131 used to decline Windows ARM64.

## Decision

**"Air-gapped deployment" means run-time network isolation of a deployed
instance. It does not mean, and does not commit to, building Karst from
source inside a sealed network.**

Concretely:

1. A deployed Karst control plane, relay, and node population MUST be able
   to run indefinitely with the only reachable network being the mesh
   peers and control plane the operator explicitly configured — verified
   above as already true, not something this ADR builds.
2. Build-time air-gapping (compiling Karst itself with no registry
   reachability) is explicitly **out of scope**, now. An operator deploying
   air-gapped installs prebuilt release artifacts (packages, binaries)
   produced by a normally-connected build (a developer machine or this
   project's own CI) and transfers them across the gap — the same shape
   every other piece of infrastructure software an air-gapped operator
   runs already uses. Building on the sealed side of the gap is not
   supported.
3. `docs/operations/air-gapped-deployment.md` (added by this ADR) is the
   concrete runbook: what to pre-stage, what to verify, and the one
   correction worth operators knowing (Bedrock anchor-age needs no
   external reachability at all).
4. The Linux packaging dependency gap above is documented as a
   pre-staging requirement in that runbook, not closed by bundling those
   dependencies into Karst's own packages.

### Alternatives rejected

- **Build a distinct "air-gapped edition."** Rejected: the verification
  above found no structural gap a separate product variant would close.
  A fork would carry its own maintenance burden (a second build target, a
  second set of packages to keep in sync) for zero behavioral difference
  from the existing self-hosted deployment.
- **Scope build-time air-gapping in now.** Rejected: no demand signal
  exists anywhere in the plans or issues, and mirroring three independent
  package ecosystems (Cargo, Go modules, npm/pnpm) is a disproportionate
  undertaking relative to what's actually been asked for. Revisit if a
  real operator asks for it — the same bar #131 set for Windows ARM64.
- **Bundle `zenity`/`pkexec`/`polkit` into Karst's own Linux packages** to
  remove the local-mirror requirement. Rejected: these are desktop
  consent-prompt dependencies for `karst-setup`'s GUI helper, which a
  headless air-gapped server deployment mostly doesn't invoke at all;
  carrying a GUI toolkit's own dependency graph into every Karst package
  (including headless server installs) to avoid documenting one
  pre-staging step is the wrong trade.
- **Treat CNSA-strict as a separate mode alongside air-gapped**, per the
  original `PLAN.md` phrasing ("air-gapped/CNSA-strict variants"). Rejected
  as already moot: ADR-0018 made CNSA 2.0 the sole suite for every
  deployment, air-gapped or not — there is no non-strict mode left to
  contrast it against.

---

## Consequences

### Positive

- #167 gets a real, checked-against-the-tree answer instead of a
  placeholder, closing out the last unresolved item from #131's
  disposition pass.
- Corrects a real misunderstanding baked into #167's own text (Bedrock
  anchor-age's supposed external-verification dependency) before it
  spreads further into docs or an operator's expectations.
- Operators get a concrete runbook rather than an emergent, unverified
  property nobody had written down.

### Negative

- **This does not solve build-time air-gapping.** An operator who
  genuinely cannot get any artifact across their air gap except source
  code still cannot build Karst on the sealed side. That is a real,
  named limitation, not a deferred implementation detail — see
  "Reconsider if."
- The Linux packaging dependency gap (`zenity`/`pkexec`/`polkit`) remains
  a real pre-staging step every air-gapped Linux install must do by hand;
  this ADR documents it rather than removing it.

### Reconsider if

- A real operator or customer asks for build-time air-gapping (compiling
  inside a sealed network). That is a materially larger effort — vendoring
  or mirroring three package ecosystems — deserving its own ADR against
  actual requirements, not built ahead of demand here.
- A genuinely reachable-external-service gap surfaces in a real air-gapped
  deployment that this review's static grep-based audit missed. A
  reachability audit by search is strong evidence, not a proof of absence,
  the same caveat this project's own macOS work has learned the hard way
  applies to anything not yet run for real.
