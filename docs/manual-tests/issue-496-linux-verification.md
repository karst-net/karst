<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Issue #496 Linux verification record

Durable execution record for [#496](https://github.com/karst-net/karst/issues/496),
scenarios SWV-01 through SWV-05 (`docs/manual-tests/02-clients-and-networking.md`,
procedures in `docs/manual-tests/00-command-procedures.md`). **Linux only.**
macOS and Windows are applicable but deferred to a separate pass — not run
here, and not marked `Not applicable`.

Run date: 2026-11-05. Runner: Claude Code (autonomous), on `turing`, a shared
lab host. Everything below used a dedicated, isolated docker-compose project
(`karst496`) with its own ports (control `:39073`, relay `:39443`) and its own
state directory, so as not to touch the host's pre-existing, unrelated
`karst-ne-lab` docker-compose project (an ongoing macOS Network Extension CI
lab — see `docs/operations/macos-network-extension-ci.md`). That project's
eight containers were confirmed running, unmodified, before and after this
work.

## Builds used

| Build | Commit | Why |
| --- | --- | --- |
| `head` | `3abe96e8d7e35d200c33f9ca89b344d25c3aa3e7` | This repo's HEAD at run time; the upgrade target. |
| `baseline` | `e67b50c575ede1c2d713ab62c3707a50f0f790c4` | Already built as a lab image on this host; post-dates the capability-schema fields. |
| `preschema` | `8279d90e4eec944343a49d17a1bd03202a6a6bbe` (parent of `843e714`) | The commit immediately before `843e714` ("fix(relay): gate live service modes on agent compatibility"), which introduced `relay_lifecycle_schema`/`gateway_ingress_schema` reporting. This build reports neither field at all — the only honest way to produce a real SWV-04 rejection, per this record's own instructions not to fake one. |

All three were built via a throwaway multi-stage Dockerfile (same shape as
`deploy/images/karstd.Dockerfile`, extended to also build `karst-cli`),
passing `KARST_VERSION=0.0.0+git.<sha>` / `KARST_REVISION=<sha>` matching the
convention in `.github/workflows/deliverables.yml`. Control and relay reused
the already-built `karst-ne-lab/karst-control:e67b50c` and
`karst-ne-lab/karst-relay:e67b50c` lab images rather than rebuilding Go/Rust
from HEAD — the only functional change to the capability-check logic between
`e67b50c` and HEAD is PR #484's rollout-tracking plumbing (not the rejection
path itself, confirmed by reading the diff), so this does not weaken the
result, but it means the control/relay plane itself was verified at
`e67b50c`, not literally at HEAD. Worth re-running against a HEAD-built
control if that distinction ever matters.

Deployment: `deploy/compose/` (GETTING-STARTED.md §5/README) bootstrapped
with `KARST_RELAY_IP=192.168.68.101 KARST_RELAY_IMAGE=karst-ne-lab/karst-relay:e67b50c`,
brought up as `docker compose -p karst496`, enrolled via the auto-minted
`state/bootstrap.key` (no OIDC/console configured for this pass — see
"Known gaps" below).

## Results

| ID | Status | Evidence |
| --- | --- | --- |
| SWV-01 | **Pass** | [identities-timeline.md §1](issue-496-evidence/identities-timeline.md) |
| SWV-02 | **Pass**, with one caveat | [identities-timeline.md §§2,4](issue-496-evidence/identities-timeline.md); staleness (>15 min) reasoned from the documented rule, not observed live — see below |
| SWV-03 | **Pass** | [swv-03-version-disagreement.txt](issue-496-evidence/swv-03-version-disagreement.txt) |
| SWV-04 | **Pass** | [identities-timeline.md §§3,4](issue-496-evidence/identities-timeline.md) |
| SWV-05 | **Pass for Linux**; macOS/Windows deferred | this record and its evidence directory |

### SWV-01 — software identity report

Enrolled the `baseline` build against the isolated control with compliance
collection left disabled throughout (never configured in any client's
`karstd.toml`). Release, source revision, and the Linux `sha256:<digest>`
artifact identity all populated during ordinary authenticated control sync.
See evidence §1.

### SWV-02 — observed identity freshness and non-inheritance

- **Unknown case**: the `preschema` node, before it ever reported software,
  showed every `software_*` field unset (§2) — not inherited from the other
  enrolled node.
- **Non-inheritance across an upgrade**: after swapping that same node's
  binary to HEAD and restarting, its fields are fully replaced by the new
  build's own release/revision/artifact identity (§4); nothing of the old
  (nonexistent) identity persisted, and the baseline node's artifact hash
  genuinely changed on its own upgrade (§5), not merely re-displayed.
- **Stale (>15 minutes) case**: not observed live. `docs/operations/software-versions.md`
  states staleness is a pure elapsed-time display computation
  (`now - software_observed_at > 15min`) with "aging the display never
  changes a stored observation's timestamp" — i.e., not a server-side state
  transition to exercise, and this isolated deployment has no OIDC/console
  wired up to even render the label (see "Known gaps"). Treating a 15-minute
  `sleep` as disproportionate to confirming a documented display rule, this
  was reasoned from the stored `software_observed_at` timestamp and the
  quoted rule rather than watched in a UI. A future pass with a real console
  attached should watch this directly.

### SWV-03 — local app vs. running engine version

Captured on both throwaway nodes: replacing the installed `karst`/`karstd`
binaries on disk without restarting the daemon makes `karst --version`
report the new build immediately, while `karst version` (querying the live
daemon over its control socket) keeps reporting the pre-upgrade build until
an actual restart. Full transcript in the evidence file.

### SWV-04 — control capability rejection and recovery

The `preschema` build reports no `gateway_ingress_schema` field (defaults to
`0`). Control only exercises that specific gate when a compiled filter rule
for the requesting node has a destination-scoped (CIDR) grant — the default
allow-all policy fixture does not trigger it by itself. Added a `"grants"`
entry to `state/policy.json` naming the preschema node as `"gateway"` for a
test `/24`, then restarted control to pick it up (confirmed by its own log
line `karst: loaded policy from /var/lib/karst/policy.json (N rules)`
— **this policy file is read once at process startup, not live-reloaded**,
which cost real time rediscovering before this record existed).

Result: a genuine `FailedPrecondition` rejection, surfaced identically to the
client (its own retry-loop warning quotes the exact server message) and to
anything reading `control_check_status`/`control_check_capability`/
`control_check_required_schema`/`control_check_reported_schema` — naming the
specific capability and schema gap with actionable upgrade guidance, and
recorded independently of the node's (absent) software identity at the time.
Upgrading that same node to HEAD and restarting cleared the rejection to
`accepted` on the very next sync. See evidence §§3–4.

**Not exercised**: the sibling `relay_lifecycle_schema` gate, which requires
`RelayServices.Publication` to be in `"services"` mode at schema ≥ 2 — an
opt-in relay-allocation feature this minimal compose fixture never
configures. Not attempted; out of scope for this pass, and not needed since
`gateway_ingress_schema` already gave a real result.

### SWV-05 — evidence requirements

This record, `issue-496-evidence/identities-timeline.md`,
`issue-496-evidence/swv-03-version-disagreement.txt`, release/revision
strings and commit SHAs above, and `turing`'s `uname -a`:

```
Linux turing.compute 6.8.0-147-generic #147-Ubuntu SMP PREEMPT_DYNAMIC Thu Sep 24 11:33:16 UTC 2026 x86_64 x86_64 x86_64 GNU/Linux
```

All of the above came from real enrolled agents against a real (if minimal)
control/relay deployment and real in-place binary replacements — no unit
test, mock, or cross-compilation output was used as evidence for any SWV row.

## Known gaps / follow-ups

1. **No console was exercised.** This deployment has no identity provider
   configured (deliberately — `GETTING-STARTED.md` §5's point of the
   auto-minted bootstrap key), so admin-console evidence
   (Machines → Status → Software version) was not visually captured; this
   record cites the same underlying `control_check_*`/`software_*` fields
   the console reads, via direct store inspection, as a documented substitute.
   A pass with OIDC configured should capture real console screenshots.
2. **`KARST_POLICY_FILE` is read once at startup**, not hot-reloaded — worth
   a line in `docs/operations/software-versions.md` or
   `deploy/compose/README.md` so the next person doesn't lose the same time
   this record's author did discovering it.
3. **The documented `"acls"`-with-CIDR-destination syntax in
   `docs/GETTING-STARTED.md` §4.2 was not what produced a `DstCidrs` filter
   rule** — only a `"grants"` entry with a matching `"gateway"` handle did
   (confirmed by reading `server/management/internals/karst/policy/policy.go`'s
   `Compile`, where `d.packetRules()`/ACL rules never populate `DstCidrs`,
   only `d.Grants` does). This is plausibly just this record's author
   misreading which of two destination-CIDR mechanisms is current, but if
   the `"acls"` CIDR-destination path is in fact dead/legacy, the
   GETTING-STARTED text pointing at it is misleading and should be checked.
4. **macOS and Windows SWV-01 through SWV-05 are not run.** Explicitly
   deferred per this pass's scope, not `Not applicable`.
5. **relay_lifecycle_schema rejection path (the sibling of SWV-04's
   gateway_ingress_schema path) was not exercised** — see SWV-04 above.

## Cleanup

The isolated `karst496` compose project, its throwaway client containers
(`issue496-baseline`, `issue496-preschema`), and the three built
`issue496/karst-client:*` images were torn down after this record was
written. Build source trees and intermediate binaries under
`/data/karst-ne-lab/issue496-verification/` on `turing` were removed. The
pre-existing `karst-ne-lab` project's eight containers were re-checked and
confirmed unchanged (`docker ps` before/after this work lists the identical
set, same start times).
