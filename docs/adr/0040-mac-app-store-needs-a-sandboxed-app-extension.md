<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-0040: The Mac App Store variant needs a sandboxed App Extension, not the existing Developer-ID System Extension — reconsiders ADR-0026's "unblocks the App Store" claim

- **Status:** Accepted
- **Date:** 2026-09-28
- **Deciders:** Adrian Anderson (project owner)
- **Related:** ADR-0026 (macOS NetworkExtension backend — the decision this
  corrects), ADR-0027 (host app/extension IPC), ADR-0028 (enrollment),
  ADR-0029 (`karst-ffi` UniFFI boundary), ADR-0030 (embedded engine
  lifecycle), `scripts/appstore-submit-macos.sh`,
  `.github/workflows/deliverables.yml`'s `app-store` job,
  `plans/phase-5/06-macos-client.md` §"On the App Store", GitHub issue #168

---

## Context

ADR-0026's "Positive" consequences list this, unqualified:

> Unblocks `scripts/appstore-submit-macos.sh` and the `app-store` CI stub for
> real, per `plans/phase-5/06-macos-client.md`'s "On the App Store" section.

Issue #168 repeated the same claim and scoped the remaining App Store work
down to an entitlements/capabilities audit — "the hard architectural blocker
is already gone... narrower than 'build a sandboxed variant from scratch.'"
That scoping is checked here directly, not assumed, per this project's own
established practice for NetworkExtension claims (ADR-0026's own item 7 found
a provisioning-profile requirement no prior research surfaced; issue #162's
research found no reliable managed-configuration detection signal despite the
initial issue text assuming one existed). The claim does not hold.

**What ADR-0026 actually built.** Item 5 is explicit: "a system extension,
not an app extension" — installed via `OSSystemExtensionRequest`
(`SystemExtensionActivator.swift`), not sandboxed
(`Karst.entitlements`/`PacketTunnel.entitlements` carry no
`com.apple.security.app-sandbox` entitlement), and signed for Developer ID
distribution. Both entitlements files already use
`packet-tunnel-provider-systemextension` — the `-systemextension`-suffixed
NetworkExtension entitlement value — and `Karst.entitlements`'s own comment
already explains *why*: "the array value naming applies specifically to a
Developer ID-signed System Extension." That comment was correct about the
value; this ADR is about what the value *means* for App Store eligibility,
which nothing in the tree had stated explicitly until now.

**What the entitlement value split actually encodes.** From Apple's own
developer forums (developer.apple.com/forums/thread/737894, the same forum
`Karst.entitlements`'s own comment already cites for a different
NetworkExtension entitlement finding, thread/807080):

> There are two groups of these values: the standard ones and the ones with
> the `-systemextension` suffix. During development and for App Store
> distribution, use the appropriate standard value. For direct distribution
> using Developer ID, use the corresponding value with the `-systemextension`
> suffix. [...] For your NE provider to work when distributed directly, it
> must: Be packaged as a system extension. Use Developer ID specific
> entitlements.

Read together with the Mac App Store's long-standing, unconditional
requirement that every submitted binary carry the
`com.apple.security.app-sandbox` entitlement (App Review Guideline 2.5.2;
true since sandboxing became mandatory for new Mac App Store submissions in
2012, and not something ADR-0026 or #168 questioned), this is not a
narrower version of the same artifact plus one more entitlement — it is two
different packaging shapes for the same `NEPacketTunnelProvider` extension
point:

| | This tree today (ADR-0026) | Required for the App Store |
|---|---|---|
| Extension packaging | System Extension (own bundle, `sysextd`-activated) | App Extension (`.appex`, embedded in the container app) |
| Entitlement value | `packet-tunnel-provider-systemextension` | `packet-tunnel-provider` |
| Sandbox | None (root-equivalent, confined only by its own UID) | `com.apple.security.app-sandbox` required, on host app and extension |
| Activation | `OSSystemExtensionRequest`, user/MDM-approved | Installed with the app itself, no separate activation |
| Distribution | Developer ID + notarization | Mac App Store only |

A sandboxed process cannot call `OSSystemExtensionRequest.activationRequest`
at all in the way `SystemExtensionActivator.swift` does today — sandboxing
and system-extension activation are the two mechanisms Apple offers for
exactly the cases this table's rows split on, not a spectrum with a
lower-effort middle. There is no configuration of the artifact ADR-0026
built — no additional entitlement, no `Info.plist` key — that makes a System
Extension submittable to the Mac App Store. The App Store variant is a
second, sandboxed App-Extension target, sharing `karst-ffi`
(ADR-0029/ADR-0030, which is already NE-agnostic — `EngineHandle` takes a raw
fd and a config path, not anything System-Extension-specific) and the Swift
business logic pattern already proven out, but a distinct Xcode target/bundle
from `KarstPacketTunnel`, not a superset of it.

## Decision

1. **Correct the record rather than silently drop the claim.** ADR-0026
   itself is left unedited — this project's convention (ADR-0024/ADR-0031 is
   the precedent: a superseded claim gets a new ADR that references the old
   one, not a retroactive edit) — but `scripts/appstore-submit-macos.sh` and
   `.github/workflows/deliverables.yml`'s `app-store` job header, both of
   which still describe the *removed* root-LaunchDaemon architecture
   (ADR-0026 item 8 deleted it) as the reason submission is blocked, are
   corrected in this same change: they were wrong about the blocker even
   before this ADR, since the LaunchDaemon they cite no longer exists in this
   tree.
2. **#168's entitlements-audit framing is answered, not merely narrowed.**
   The audit's answer is: the existing target is categorically ineligible,
   independent of which specific entitlements or Info.plist keys it carries.
   Nothing about "no disallowed APIs" is reachable as a next step before a
   sandboxed App Extension target exists to audit.
3. **Scope a new App-Extension target as its own follow-up**, not folded into
   this ADR or into #168 as originally framed: a second `NEPacketTunnelProvider`
   (`.appex`), a sandboxed container app to hold it, `com.apple.security.app-sandbox`
   on both, provisioning profiles using the standard (non-`-systemextension`)
   entitlement values, and a `build-macos-pkg.sh`-sibling packaging path
   distinct from the Developer-ID one. `karst-ffi` needs no change for this —
   confirmed by reading `EngineHandle::start`'s signature (`crates/karst-ffi/src/engine.rs`):
   it takes `config_path`/`socket_path`/`fd`, none of which assume a System
   Extension's unsandboxed filesystem access, though the sandboxed target's
   own `config_path`/`socket_path` will need to live inside its App Group
   container rather than `KarstPacketTunnel`'s root-owned
   `/Library/Application Support/dev.karst.packettunnel` — sandboxed
   processes cannot write there.
4. **Managed-device / MDM coexistence (#168's third scope bullet) follows
   directly from the corrected architecture, not from new research.**
   `.mobileconfig`-pushed configuration (#162, ADR-0031) targets a specific
   `NETunnelProviderManager`/bundle identifier under a Developer-ID-signed,
   non-sandboxed app — the same category as `KarstPacketTunnel` today. A Mac
   App Store app is, by the Store's own terms, self-service-installed by the
   user from the Store; nothing about Apple's MDM/`.mobileconfig` model
   pushes configuration *for* a different app identity than the one the
   admin's profile names, and an admin deploying via MDM already has the
   non-Store Developer-ID build available as the managed option. The two
   therefore do not need to coexist in one bundle: an organization doing
   managed deployment uses the Developer-ID build (already MDM-capable per
   ADR-0031); an individual self-service user installing from the Store gets
   the sandboxed build. This is the same split most shipping NetworkExtension
   VPN clients already use for the same reason, not a gap specific to this
   project.
5. **Export compliance (#168's second scope bullet) is flagged, not
   answered, here.** Karst ships ML-KEM/ML-DSA (post-quantum) cryptography
   over TLS-equivalent transports, which is the same regulatory category
   (EAR Category 5 Part 2, encryption) any TLS-using app already falls under,
   most commonly self-classified under License Exception ENC's "publicly
   available"/open-source treatment (15 CFR §740.17, §742.15) the way this
   project's own MIT/Apache-2.0 licensing and public source already fit
   the "publicly available" criterion. Stated as a first-pass classification
   for reference, not as a compliance opinion this project can rely on
   without review — App Store Connect's export-compliance questionnaire is a
   legal filing, and getting it wrong has consequences an ADR's confidence
   level should not paper over.

### Alternatives rejected

- **Adding `com.apple.security.app-sandbox` to `Karst.entitlements`/
  `PacketTunnel.entitlements` directly** and calling the existing target
  App-Store-ready. Rejected: `SystemExtensionActivator.swift`'s
  `OSSystemExtensionRequest` call does not function inside the App Sandbox at
  all — this would not narrow the gap, it would break the Developer-ID build
  that works today for a change that still could not ship on the Store.
- **Treating this as confirmation to abandon the App Store variant
  entirely.** Rejected as premature: #131's original disposition on this was
  "pursue," nothing here changes the technical feasibility of a sandboxed
  App-Extension target (every dependency below `karst-ffi` is already
  NE-agnostic), and the cost this ADR identifies is "a second Xcode target,"
  not "impossible." That is a real, budgetable follow-up, which item 3 above
  scopes rather than closes out.
- **Silently updating ADR-0026's Positive-consequences bullet in place.**
  Rejected per this project's own ADR convention: ADR-0024 was reconsidered
  by ADR-0031 as a new document, not a retroactive edit, so a past ADR's
  reasoning stays legible to a future reader exactly as it was decided, with
  the correction recorded where it happened instead.

---

## Consequences

### Positive

- Issue #168 gets a real, checked answer instead of narrowing a false
  premise further: the "confirm entitlements" step it proposed as the
  remaining work was not reachable, and now doesn't need to be attempted
  against the wrong target.
- Two stale artifacts (`scripts/appstore-submit-macos.sh`,
  `.github/workflows/deliverables.yml`'s `app-store` job comment) that still
  described a deleted LaunchDaemon architecture as the blocker are corrected
  to describe the real one, so the next person reading them to plan the App
  Extension target starts from an accurate starting line.
- `karst-ffi`'s design (ADR-0029/ADR-0030) is confirmed, not just assumed, to
  need no rework for a sandboxed consumer — it was already fd/path-based with
  no System-Extension-specific API, which this ADR checked by reading its
  actual signatures rather than inferring from its current caller.

### Negative

- **The App Store SKU is further out than #168 or ADR-0026 stated.** A
  second Xcode target, a second entitlements/provisioning-profile set, a
  second packaging pipeline, and sandboxed-filesystem adjustments to where
  `karst-ffi`'s config/socket paths live are real, uncosted work — comparable
  in shape to the KarstPacketTunnel System Extension build itself
  (ADR-0026/0027/0028), not a checklist item on top of it.
- This is the second time this project's own App Store readiness claim
  (first `plans/phase-5/06-macos-client.md` §3's "App Store variant comes
  later," now ADR-0026's "unblocks... for real") turned out to need
  correction once checked against Apple's actual distribution rules rather
  than inferred from the NetworkExtension migration's own motivations (MDM,
  UniFFI/mobile code reuse). Any future claim that a NetworkExtension change
  "unblocks the App Store" should be checked against the standard-vs-
  `-systemextension` entitlement split before being stated as fact.
- The export-compliance question (item 5) remains genuinely open, not merely
  deferred paperwork — the algorithms in play (ML-KEM/ML-DSA) are less
  litigated in export-classification precedent than RSA/AES/ECC, and a
  first-pass self-classification here should not be treated as legal
  clearance.

### Reconsider if

- A future engineering effort actually builds and tests the sandboxed
  App-Extension target end to end: this ADR's cost estimate (item 3) is
  reasoned from reading existing code, not from building the target, the
  same "written and reviewed, not run" limit ADR-0029/ADR-0030 already carry
  for this codebase's macOS work generally.
- Apple changes the Mac App Store's sandboxing requirement, or extends the
  standard (non-`-systemextension`) NetworkExtension entitlement values to
  cover System-Extension-packaged providers — nothing in the sources checked
  here suggests this is planned, but the entitlement-value split itself is
  Apple's own mechanism to change if they choose to.
