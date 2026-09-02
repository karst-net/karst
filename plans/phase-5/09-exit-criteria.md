# Exit criteria, docs, and the walkthrough

**W8–W10 · SRE, with everyone on call for the findings it produces.**

**Status at Phase 5 close, 2026-09-02: ten of twelve claims demonstrated.**
Claim 4 (macOS installer) closed 2026-09-01 when Apple Developer Program
enrollment landed and `release-test-1` produced a real signed, notarized,
stapled `.pkg`. Claim 10 (60 s deprovisioning) and claim 12 (the outsider
walkthrough) are red and carried into Phase 6 in writing, per §6's own rule —
see PLAN.md's Phase 5 entry and [00-overview.md](00-overview.md).

## 1. The criterion, decomposed

> **Re-baselined 2026-08-27.** The gate must test completed user workflows,
> not merely the existence of screens. In addition to the claims below, require
> a real Bedrock request → offline sign → response import → client enforcement
> flow; successful console audit export in both JSON and CSV; observed audit
> sink delivery or an explicit deferral; accurate portal device/session data;
> and documented proof that a relay is fallback transport, not an exit node.
> Managed subnet/exit-node use cases are not Phase 5 gate claims and remain
> Phase 6 scope.

> A non-expert admin can install the server, connect three nodes across Linux
> plus one completed non-Linux client platform and two NATs, write an ACL,
> enable network lock, and deprovision a user — entirely from the console and
> installers, following only the published docs.

Twelve checkable claims hide in that sentence:

| # | Claim | Owner |
|---|---|---|
| 1 | The server installs from published artifacts | SRE |
| 2 | First-run setup completes in the console | [04](04-admin-console.md) |
| 3 | A Linux node installs from a CI-produced package and enrolls | **✅ §2 — install/upgrade/uninstall proven on 4 distributions; container signing and the published download location are the two items left** |
| 4 | A completed non-Linux client installs from its signed installer and enrolls | **✅ Closed 2026-09-01** — [06](06-macos-client.md), `release-test-1` |
| 5 | Windows client installation is a Phase 8 acceptance criterion, not a Phase 5 gate | [07](07-windows-client.md) |
| 6 | Two of the three nodes are behind different NATs and reach direct paths | Phase 4's matrix, re-run with the new client |
| 7 | An ACL is written, validated, and saved in the console | [04](04-admin-console.md) §5.1 |
| 8 | The ACL takes effect — a permitted flow works, a denied one does not | aquifer suite |
| 9 | Network lock is enabled from the console | [02](02-bedrock.md) |
| 10 | A user is deprovisioned and their sessions die in under 60 s | **🔴 Open, carried to Phase 6.** Measured 2026-08-28 at 48.9 s and not met as a bound — FINDINGS.md 67, 68 |
| 11 | The docs are sufficient — no source reading, no maintainer questions | §4 |
| 12 | The person doing it is not one of us | **🔴 Open, carried to Phase 6.** §3 — not yet run; CI's automated doc walkthrough is a regression guard, not this |

Claim 12 is the one most likely to be quietly dropped, and it is the one the
criterion actually turns on. Claim 3's residual items (container-signing
evidence, the published download location) and claim 10 are tracked, but
neither blocks a non-expert admin from completing the sentence in §1 today.

## 2. Linux packaging: proven on 2026-08-28, with two items left

The original version of this section found no package or systemd
implementation; a later revision found definitions but no proof. Both are
superseded. The proof now exists and is wired into `deliverables.yml`:

| Gate | Where |
|---|---|
| Install, upgrade, uninstall on Debian 12, Ubuntu 24.04, Fedora 41, RHEL 9 | `packages-verify`, 8 jobs (4 distributions × amd64/arm64) |
| The packaged unit under a real systemd, including DNS recovery after `SIGKILL` | `packages-systemd` |
| Binaries link against the oldest supported glibc | `scripts/glibc-floor.sh`, asserted in the build job |
| `SHA256SUMS`, detached signature, CycloneDX SBOM per artifact | `release-artifacts` |

All three checks are runnable without a push — `just packages`,
`just packages-verify`, `just packages-verify-systemd`.

**Writing it found four defects, three of them release-blocking**, which is the
argument for the section: FINDINGS.md 59 (every package shipped a binary that
could not start on Debian 12 or RHEL 9, and installed cleanly on both), 60 (the
daemon survived its own removal, leaving a dangling enablement symlink), 61
(nothing created `/var/lib/karst`, so the documented netmap-cache path did not
exist and had no mode), and 62, still open (`RuntimeDirectory=` deletes the DNS
revert record the manual recovery reads).

Two items remained before this row could be called finished:

- **Container image signing — ✅ done, release evidence captured
  2026-08-30.** Release tags matching `v*` publish `karstd`, `karst-relay`,
  and `karst-control` to GHCR, then sign each pushed digest with keyless
  Cosign through GitHub Actions OIDC. The workflow verifies the exact
  repository, workflow path, tag ref, and GitHub issuer before succeeding.
  The protected test tag `v0.0.0-signing-test.1` produced and preserved
  exactly that evidence for all three images — for `karst-relay`:
  digest `sha256:f96d5959…f24671b`, signed, then verified against
  `--certificate-identity
  https://github.com/karst-net/karst/.github/workflows/deliverables.yml@refs/tags/v0.0.0-signing-test.1`
  and `--certificate-oidc-issuer https://token.actions.githubusercontent.com`,
  with the transparency-log check passing offline. Repository administrators
  must still protect the `v*` tag namespace: OIDC proves which workflow
  signed, protection decides who may cause it to run.
- **The published location.** Producing signed artifacts is not publishing
  them. Nothing yet uploads to a release, and `scripts/release-manifest.sh` —
  which the portal's download page reads — is still wired to nothing and still
  expects a Windows MSI that is Phase 8's.

Phase 4 half-noticed this from the other side, recording that the compose
artifact "cannot walk a self-hoster to a connected node, because a node needs a
setup key, a setup key needs an account, and an account needs the admin
console". The missing packaging is the same observation one layer down: a node
needs to be installed before it can be enrolled, and on Linux there is nothing
to install.

It is also a dependency of work already planned: [01](01-karstdns.md) §7.1
proposes `ExecStopPost=` in the systemd unit as the DNS revert guarantee, and
§5.3 proposes a systemd socket unit to bind port 53 without granting the daemon
`CAP_NET_BIND_SERVICE` — which is how ADR-0012's no-capabilities release gate
stays true. Both assume a unit file that has never been written.

**Add it to the phase, in W6, one engineer-week:**

- `deploy/packaging/karstd.service` — `Type=notify` if the daemon learns
  `sd_notify`, `Type=simple` otherwise; `AmbientCapabilities=CAP_NET_ADMIN`
  only in the kernel-TUN profile; a second unit or a drop-in for the userspace
  profile with no capabilities at all, matching the ADR-0012 gate.
- `deploy/packaging/karstd.socket` — for the resolver's port 53.
- `nfpm` config producing `.deb` and `.rpm` for amd64 and arm64 from one
  description, plus a `karst-control` server package.
- Post-install: create `karst` user, `/etc/karst/`, `/var/lib/karst/` with
  restrictive modes (the netmap cache holds per-pair PSKs), and do **not**
  enable the service automatically without a config.
- A CI job that installs the `.deb` in a container, starts it, and asserts it
  fails cleanly with no config — then succeeds with one.

Test on Debian 12, Ubuntu 24.04, Fedora 41, and RHEL 9. That is the set the
docs will claim, so it is the set CI should build.

## 3. The walkthrough protocol

Claim 12 is the one with teeth. **The walkthrough is run by someone who did not
build any of it.** A colleague from another team, a friend who runs a homelab,
anyone competent with a terminal and ignorant of this codebase.

Rules:

1. They get a URL to the published docs and nothing else. No repo access, no
   Slack, no maintainer in the room answering questions.
2. Three machines: two Linux boxes behind NAT A and a completed non-Linux
   client (macOS in the current plan) behind NAT B. A fourth host with a public address runs the server
   and relay — that is `deploy/compose`, which works today.
3. Everything is recorded: screen capture, and a running log of every moment
   they hesitate, re-read a page, or guess.
4. **Every deviation is a finding.** Not "they got confused, we should improve
   the docs" — a numbered entry with the same discipline as the rest of
   FINDINGS.md, which currently stands at 52 closed and none open. Expect ten
   to twenty from a first walkthrough. That is a healthy result, not a failed
   one.
5. Timebox: if they cannot get a first node connected inside 30 minutes, stop,
   fix, and re-run from the top with a fresh person. A second attempt by the
   same person tests the fix and not the docs.

Run it **twice**: once in W8 with whatever exists (expect it to fail — that is
the point of running it early, when there is time to act) and once in W10 as
the real gate.

## 4. Documentation

The docs are a deliverable of this phase, not a write-up after it. The public
site lives in its own repository, `karst-net/karst-net.github.io`, which GitHub
Pages publishes from the repository root, so there is a place to publish to.

| Doc | Contents | Owner | Week |
|---|---|---|---|
| **Quickstart** | Server up, first node connected, in under 30 minutes | SRE | W7 |
| **Installing the coordination server** | Compose, Kubernetes, and the `.deb`/`.rpm`; TLS; sizing; backup | SRE | W7 |
| **Installing a node** | One page per OS, with the actual installer flow and screenshots | Client owners | W8 |
| **Access control** | HuJSON by example, from "everyone can reach everything" to tag-scoped; how to test a change before applying it | Go 1 | W8 |
| **KarstDNS** | What resolves, split DNS, per-platform behavior, and the troubleshooting section this will need | Rust 1 | W8 |
| **Network lock** | The key ceremony, quorum choice, offline signing, and **the recovery section including the case with no recovery** ([02](02-bedrock.md) §9) | Crypto | W8 |
| **Identity and SCIM** | OIDC setup for Okta/Entra/Authentik/Keycloak, SCIM token, group sync | Go 2 | W8 |
| **Troubleshooting** | Symptom-first: no connection, relay-only, DNS broken, node rejected. Each entry names the command that shows the truth | All | W9 |
| **Uninstalling** | Per OS, complete, including DNS state | Client owners | W9 |

Two standing rules:

- **Every page ends with how to check it worked**, with the exact command and
  the expected output. `karst status` already prints the facts; the docs should
  quote it.
- **No page tells the reader to read the source.** If it needs to, the feature
  is not finished.

## 5. Release artifacts

By W10 a tagged release produces:

| Artifact | Signed | CI |
|---|---|---|
| `karst_<ver>_{amd64,arm64}.deb` / `.rpm` (node + server) | Repo GPG key | Yes |
| `karst-<ver>-macos.pkg`, universal | Developer ID + notarized + stapled | Tag only |
| `karst-<ver>-x64.msi` | Code-signing cert, timestamped | Tag only |
| Container images for `karstd`, `karst-relay`, `karst-control` | cosign | Yes |
| `SHA256SUMS` + detached signature | Yes | Yes |
| SBOM per artifact (CycloneDX) | — | Yes |

The checksums file matters more than it looks: the portal's download page
([05](05-user-portal.md)) tells users to verify, and the docs explain how, so it
has to be there and it has to be correct.

## 6. Phase gate

**Run 2026-09-02, at Phase 5's actual close** rather than at the end of a W10
that never happened on the original schedule. Anything red is either fixed
or moved to Phase 6 **in writing, in PLAN.md**, with the same honesty the
earlier phases used — Phase 4's TURN slip is the model: what moved, when, why,
and what depends on it. Two rows below are red and moved; see PLAN.md's
Phase 5 entry for the same accounting in the plan of record.

| Gate | Source | Status |
|---|---|---|
| Walkthrough completed by an outsider, unaided | §3 | 🔴 **Not run — moved to Phase 6 W1** |
| Every walkthrough finding either fixed or recorded as open | FINDINGS.md | Depends on the row above |
| The twelve claims in §1 all demonstrated | §1 | 🟡 Ten of twelve — claims 10 and 12 moved to Phase 6 |
| No secret material in any REST response, under any role | [03](03-control-api.md) §7 | ✅ |
| Bedrock chain verifies identically in Go and Rust against shared vectors | [02](02-bedrock.md) §12 | ✅ |
| Deprovisioning measured under 30 s in CI — **measured 2026-08-28 at 48.9 s, and blocked on [08](08-scim-and-groups.md) §2's push, not on the test** (FINDINGS.md 67, 68) | [08](08-scim-and-groups.md) §7 | 🔴 **Not met — moved to Phase 6, first item** |
| DNS reverts after `SIGKILL` on Linux and the completed non-Linux platform | [01](01-karstdns.md) §10 | ✅ |
| The NAT matrix still passes with the completed non-Linux client row added | Phase 4's matrix | ✅ — `two-host-test.sh` takes a Mac as either host (2026-08-30) |
| Rust and Go test suites green; `just verify` and `just test-privileged` pass | `justfile` | ✅ |
| axe clean on every console route | [04](04-admin-console.md) §7 | ✅ |

## 7. What the README says afterwards

The README currently opens with "**Status: pre-alpha. Do not deploy this.**
Phase 4 of 7" — and PLAN.md §10 says "self-hosted Linux-to-Linux mesh with a
working console is usable at end of Phase 5 … and that is the milestone worth
naming".

At the gate, that paragraph gets rewritten, and the honest version still says
**no external cryptographic review has happened** — that is Phase 8 now, after
GA, and PLAN.md §12 has already raised the risk for it. "Usable" and "reviewed"
are different claims and Phase 5 only earns the first one. **Not yet drafted
as of 2026-09-02**, and deliberately so: §6's two red rows — the outsider
walkthrough and deprovisioning timing — are exactly the claims "Phase 4 of 7"
would be replaced with an assertion about, so the rewrite waits for Phase 6
W1's walkthrough rather than getting ahead of it. Draft it then, with the
crypto lead signing off on the wording, not just the engineering.
