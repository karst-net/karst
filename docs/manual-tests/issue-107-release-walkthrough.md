<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Issue #107 release walkthrough

Durable execution record for [#107](https://github.com/karst-net/karst/issues/107).
Target: **v0.1.0-rc.32**, explicitly selected by the user on 2026-11-01.
Runner: Codex, autonomous. The user waived recruiting an unaided human outsider;
this run must be described as autonomous release validation. Other requirements
remain: released artifacts, the published guide, measured timing, a single TLS
origin, portal downloads, and recorded deviations. Prior rc.21 observations do
not count as rc.32 results. Historical plans remain historical; this record
supplements their walkthrough steps with observable exit criteria.

## Execution and exit criteria

Use [GETTING-STARTED](../GETTING-STARTED.md), in particular Path C and §§7–8,
10–12. Source inspection may diagnose a finding, but a resulting workaround
must be recorded; it cannot silently become an instruction the guide supplied.
Source builds and the source-building CI walkthrough cannot satisfy the
released-artifacts requirement. Record the exact guide revision used. Before
running, distinguish prerequisites from timed installation work.

| Step | Documented action | Exit criteria | Status |
| --- | --- | --- | --- |
| 1 | Select release and guide (§§1–3) | Record tag, resolved commit, guide revision, publication time, asset inventory and runner/date. All installed Karst components come from rc.32 assets; retain full SHA-256 values. | Pass |
| 2 | Prepare hosts and prerequisites (§§1–2, 10) | Record OS/architecture, disposable server and client hosts, network/NAT topology, available privileges, DNS/TLS and IdP prerequisites, and reachable required ports. Use isolated state and services; preserve existing deployments. A missing prerequisite has an explicit disposition. | Pass with recorded fixture limits |
| 3 | Download and verify packages and web assets (§§3, 7) | Start the installation clock before the first cold artifact download. Download matching control, relay and client packages, web tarball, manifest, checksums and signature. Verify signature with the published release key; record fingerprint and output. Compute local hashes and compare against signed checksums and release metadata. Missing checksum coverage is a finding. No source build. | Pass in final clean attempt |
| 4 | Install and configure relay (§6.1) | Packaged executable starts using documented configuration; config check succeeds; identity public key is recorded; TLS listener is reachable; private files have documented restrictive permissions. The initial configuration check reports zero admitted nodes and states that unadmitted connections will be rejected. Record packaged service paths rather than substituting source-build units. | Pass with corrected server-leaf certificate |
| 5 | Install and configure control (§6.2) | Control service remains healthy with persistent state, documented policy, relay identity/registry, and bootstrap-key output. Server pins are captured without secrets; roster refresh stays inside its admission lease. Missing policy does not silently grant access. | Pass |
| 6 | Configure one TLS origin (§§7.1–7.2) | Console `/`, portal `/portal/`, management API, node control channel, and release files work through one origin. Capture HTTP status and browser asset/network evidence. Enrollment needs no unproxied second public port. Portal assets resolve under `/portal/`; API failures are not hidden by SPA fallback. | Pass on final deployment |
| 7 | Install and enroll first node (§§6.3, 8.1) | Released client enrolls through that HTTPS origin using documented pins and bootstrap key. `karst status` reports synchronization and an assigned overlay address. Record UTC start/end and monotonic elapsed seconds; elapsed from step 3 is at most 1,800 seconds. On overrun stop the attempt, record failure, fix findings, and restart with fresh state. Never reset the clock within an attempt. | Pass: 22.362 seconds |
| 8 | Verify a second node and traffic (§11) | Second released client enrolls; both report established peer sessions and expected policy rules. Overlay ping or TCP succeeds with recorded commands, counts and loss. Record observed direct/relay transport and topology; do not infer cross-NAT coverage from same-LAN traffic. First usable peer traffic gets its own timestamp. | Pass: bidirectional 4/4 ping at 34.308 seconds |
| 9 | Exercise portal downloads (§7) | Authenticate through the documented IdP; portal renders real device/session data. Downloads page obtains the rc.32 manifest; following each applicable platform link retrieves the named artifact and its computed hash matches the manifest/release checksums. Capture browser and HTTP evidence. A loaded HTML shell or successful manifest GET alone is insufficient. | Pass: six verified browser downloads on final deployment |
| 10 | Exercise remaining applicable gate workflows (historical Phase 5 claims) | Explicitly record results or scope disposition for three nodes across Linux plus macOS and two NATs; console ACL save and permitted/denied traffic; network lock request/sign/import and client enforcement; user deprovisioning timing. Link separate issue evidence where these are independently tracked. The human waiver does not waive technical coverage. | Not recertified: historical claims outside current issue acceptance |
| 11 | Record deviations and fix guide defects (§12) | Every undocumented substitution, failure or ambiguity has a numbered finding and GitHub issue reference. Documentation fixes are reviewable and the failed step is rerun; installation-affecting fixes require a fresh timed attempt. Separate product failures, missing prerequisites and documentation defects. No unresolved documentation defect is called a pass. | Pass: five findings recorded; documentation fixes validated locally |
| 12 | Preserve evidence, clean up and report | Retain sanitized commands/output, hashes, exact revisions, timestamps, topology and finding dispositions. Remove only this run's services/state and confirm existing services remain healthy. Acceptance matrix distinguishes Pass, Fail, Blocked and Not applicable. Final issue disposition cites evidence and explicitly records the human waiver; close only when the remaining criteria pass. | Pass: evidence saved and temporary deployment removed |

## Individual Path C command exit criteria

The guide's fenced-block step identifiers below make the installation checks
traceable to individual commands. These are required observations, not results.
For this artifact-only run, package installation replaces the three source-build
steps; record the exact package paths and substitutions as deviations from the
source-build instructions. They must not be reported as executed guide commands.

| Guide step | Exit criterion |
| --- | --- |
| `build-rust`, `build-control`, `install` | Not executed: install verified rc.32 distribution packages instead; record package versions, file ownership and executable paths. No locally built executable enters the run. |
| `relay-install` | Released relay executable and packaged service exist at their package-declared paths; service references that executable. |
| `relay-cert` | Certificate and private key exist, match each other, cover the selected relay name/address, and have documented permissions; private key is excluded from evidence. |
| `relay-config` | Configuration names the intended certificate, key, identity, roster, and listeners; run-owned paths and ports are recorded. |
| `relay-check` | `karst-relay check` exits zero with the intended config and reports an empty initial roster rather than silently admitting clients. |
| `relay-pubkey` | Public relay ID and identity key are captured and agree with the control registry entry. No private identity material is published. |
| `relay-start` | Relay service stays active; logs show the intended listener and roster; no bind conflict or restart loop. |
| `control-install` | Released control executable, packaged service and writable persistent-state directory exist with correct ownership. |
| `relays-json` | Registry loads successfully; relay address, TLS name and identity match the deployed relay. |
| `policy` | Documented initial policy parses; enrolled clients later receive expected ingress and egress rules. |
| `management` | Management config loads and uses the run's data directory and selected listener. OIDC values are correct for browser tests. |
| `control-env` | Running service receives documented relay roster, registry, policy and bootstrap-key settings; no setup key or secret is printed to evidence. |
| `control-start` | Service remains active, persists state and refreshes relay roster within the lease; logs show no fatal initialization errors. |
| `control-pins` | Both public pins are captured in the format the client expects and identify this control deployment. |
| `node-install` | Verified released client package supplies daemon, CLI and units; binaries are executable at the unit-declared paths. |
| `node-config` | Config uses this run's key/state/cache/socket paths, expected control pins, setup key and HTTPS origin; permissions restrict secret files. |
| `node-start` | Node service stays active, creates its control identity and cache, enrolls and receives an overlay address. |
| `node-status` | CLI reaches the correct daemon socket and reports synchronized control state; with the second peer, session is established and traffic succeeds. |
| `dns-revert` | If host DNS integration is enabled, stopping the run's node restores its pre-run resolver state; record before/after state. Otherwise record why this command is not applicable. |
| `bootstrap-key` | Control creates a nonempty restricted bootstrap-key file and first enrollment accepts it. Key bytes are never included in committed evidence. |

## Evidence ledger

- Release published: 2026-11-01T15:01:30Z.
- Release URL: <https://github.com/karst-net/karst/releases/tag/v0.1.0-rc.32>.
- Release tag object: `c959e92226edd02fd6ba98d04167aab1457bd5af`.
- Resolved release commit: `a1ad9f0b65248515d7d7d77a6a24e083456f961c`.
- Guide revision used for preparation: local HEAD
  `8df2117168b2de64bdedcae0e656d69093dd2782`; byte-identical to the guide
  published at rc.32. Guide SHA-256:
  `2859b5d6082afa43a2fad943ad8e496583da9f9b65f84a8c9c9382be5193a988`.
- Inventory: GitHub release API confirms 24 uploaded assets, including Linux
  amd64/arm64 deb/rpm packages, two macOS packages, `karst-web.tar.gz`,
  `manifest.json`, `SHA256SUMS`, `SHA256SUMS.asc`, and component SBOMs.
- Full inventory and API digests: [rc.32 assets](issue-107-rc32-assets.json).
- Downloaded-asset checks: [preflight evidence](issue-107-rc32-preflight.json).
  Seven downloaded assets match API hashes; the three Linux amd64 packages
  and web bundle also match `SHA256SUMS`. All six portal manifest entries
  match the checksum list and release API, and use `/releases/` URLs. Portal
  HTML assets use `/portal/assets/` and exist in the released tarball.
  These static checks are supplemented by the final browser evidence below.
- Signature verification: **Pass**. [Signature evidence](issue-107-rc32-signature.json)
  records verification of the detached `SHA256SUMS` signature using OpenPGP.js
  6.3.2 and the release key published at rc.32. Public primary fingerprint:
  `DD5C 7054 DBFA E8D6 9704 95A3 0CFE 3D34 6567 3971`.
  Public signing fingerprint:
  `95E8 4D07 245E E5CD 73F9 EA0D F07F BCFA 8E79 B334`.
- `scripts/documentation-check.sh`: passed, including all 54 fenced-block
  annotations and existing documentation invariants.
- Attempt 1 clock: started `2026-11-01T19:05:55.273101Z`; first node synchronized
  at `2026-11-01T19:09:36.559198Z`, **221.286 seconds**. This diagnostic run
  included dependency repair and used the original guide. Bidirectional traffic was eventually verified at 3,414.796 seconds, outside
  the budget. This is diagnostic evidence, not the final sign-off attempt.
- Host discovery: SSH to `turing` and `lovelace` timed out, including outside
  the filesystem/network sandbox. Neither host has been changed.
- User selected `turing` and authorized powering it on through iDRAC.
  The user located the current instructions at
  `shannon:/home/adrian/code/mycelium/CLAUDE.local.md`. Access succeeded via
  `shannon.local`; credentials remained on that host. Current turing iDRAC
  address is `192.168.70.20`. Redfish reported `Off` and accepted
  `ComputerSystem.Reset` with `ResetType: On` (HTTP 204) on 2026-11-01.
- Local runtime discovery: no `docker`, `colima`, `orb`, `multipass` or `gpg`
  executable found on PATH. Linux systemd/TUN walkthrough cannot run directly
  on this macOS host.
- Current disposition: the final clean attempt passes the scoped issue criteria
  with the documented multihomed workaround. Cleanup is complete; documentation/evidence changes are ready for review.

## Runtime evidence and findings

The [attempt 1 timing and raw sanitized command evidence](issue-107-rc32-evidence/)
includes release verification, package-manager output, relay checks, node
status and failed pings. Text-log line endings and trailing whitespace are
normalized for storage; observed results are retained. The [browser record](issue-107-rc32-evidence/browser.json)
shows real Keycloak login, the two enrolled devices, actual session-history
responses, successful console rendering and all six downloads with matching
SHA-256 hashes. Portal JavaScript/CSS served at `/portal/assets/`; no browser
page errors were observed. A nonexistent release file returned HTTP 404.
The disposable browser fixture accepted Caddy's internal-CA certificate;
this does not demonstrate publicly trusted certificate provisioning.

The host's original Karst service, installed package, stale `/usr/local/bin`
binaries and seven `karst-ne-lab` containers were removed at the user's
explicit request. Their state was archived root-only on turing at
`/var/backups/karst-107-pre-rc32-20261101T190212Z`. Unrelated Docker workloads
remained running. The test uses packaged systemd services plus a dedicated
Caddy container on HTTPS port 35443, relay port 35444 and Keycloak on the
same origin under `/auth/`. The backend control service remains on 33073.
The second Linux node runs in network namespace `karst107b` over
`10.107.0.0/30`; this is a same-host fixture, not evidence for separate physical
hosts or two real NATs. No macOS install is claimed by this run.

| Finding | Observed evidence | Disposition |
| --- | --- | --- |
| F1 / [#506](https://github.com/karst-net/karst/issues/506) | Source-build guide has no complete released-package path; `dpkg -i` left Linux client unconfigured because `zenity`/`pkexec` were absent. | Guide now provides APT installation, verification and packaged-unit instructions; final fresh installation passed with dependencies absent at start. |
| F2 / [#505](https://github.com/karst-net/karst/issues/505) | Original OpenSSL command created a CA leaf, rejected as `CaUsedAsEndEntity`. | Guide adds explicit server-leaf extensions and client certificate-copy instruction; final certificate has CA:FALSE/serverAuth and relay metrics show two admitted clients. |
| F3 / [#509](https://github.com/karst-net/karst/issues/509) | Tailscale INPUT rules drop CGNAT-source traffic arriving outside `tailscale0`; host also has DNS port 53 already bound. | Guide adds coexistence diagnostics and DNS opt-out. Final fixture disables KarstDNS and adds only an INPUT exception scoped to `karst0` and its actual assigned /16. Existing resolver/Tailscale rules remain intact. |
| F4 / [#508](https://github.com/karst-net/karst/issues/508) | Both peers report synchronized control, policy rules and established direct sessions, but overlay ping has 100% loss. Encrypted data-sized UDP packets reach the second namespace. A captured TransportData fragment verifies under the recipient public key; MAC counters alone do not attribute the loss. | Binding the host node to its namespace-facing source address restores bidirectional traffic. Workaround documented and used in final attempt; product fix remains open in #508. |
| F5 / [#510](https://github.com/karst-net/karst/issues/510) | Historical journal pins caused the fresh client to reject the new server identity during attempt 2. | Guide now selects the current systemd invocation; final fresh enrollment passes with historical journal retained. |
| R1 (runner) | Custom socket/JSON flags were initially placed in an unsupported order. | Correct invocation is `karst status --json --socket PATH`; this was outside the guide's default-socket command. |
| R2 (runner) | A diagnostic ping was piped through `tee` without `pipefail`; an intermediate ledger briefly recorded a traffic timestamp despite ping failure. | Timestamp corrected to `failed_first_peer_probe_*`; committed evidence records failed traffic. Future success markers require the probe's exit status. |

## Final clean attempt

[Final evidence summary](issue-107-rc32-final/summary.json),
[timing](issue-107-rc32-final/timing.json),
[executed runner](issue-107-rc32-final/runner.sh), and
[browser evidence](issue-107-rc32-final/browser.json).

- Cold download started **2026-11-01T20:12:38.071156Z** on turing.
- First node synchronized at **20:13:00.433402Z**: **22.362 seconds**.
- Bidirectional overlay traffic verified at **20:13:12.379363Z**:
  **34.308 seconds**, including 4/4 pings each way, zero loss.
- Control/relay/client packages all report `0.1.0-0.rc.32`; installed package
  integrity check `dpkg -V` reports no modified package files. Both running
  nodes independently report the rc.32 source revision.
- GnuPG verifies the release checksum signature; package and web hashes match
  the signed checksum list. The corrected relay certificate has `CA:FALSE`,
  server authentication EKU and key usages. Two clients are connected to it.
- On this fresh deployment, real browser OIDC login, devices/session pages,
  console rendering and all six portal downloads pass again with matching
  manifest hashes and no page errors. Missing release files return 404.
- Exact corrected guide bytes are bound by SHA-256 in the summary; original
  published guide bytes and release commit are recorded above. No Karst source
  build or repository checkout was used to deploy the tested binaries/web apps.
- Before timing, Karst packages/state and the two initially missing desktop
  dependencies were removed. OS tools, cached container images, the test
  network and external IdP were prepared prerequisites. This measures the
  documented installation with those prerequisites, not provisioning a bare OS.

The human-outside-engineering requirement is waived by the user. Separate-NAT
coverage, macOS installation, Bedrock, ACL-console workflows and deprovisioning
from the historical Phase 5 gate are not recertified here; this issue's current
acceptance criteria concern installation timing, the single-origin deployment
and portal downloads. The multihomed product defect remains tracked in #508;
this run validates the explicitly documented workaround, not a code fix.

## Cleanup and disposition

[Cleanup output](issue-107-rc32-final/evidence/cleanup.txt) confirms no Karst
processes, installed unit files, test containers, test namespace or test firewall
rule remain. The seven unrelated containers present before testing remain
running; host DNS resolves external names through its original unbound listener.
Temporary test credentials and CA private material were removed. The root-only
original-state backup remains available, and turing is left powered on.

The scoped autonomous validation passes. The documentation fixes and evidence
are ready for review; publication does not certify the historical independent
reader, non-Linux, two-NAT, or broader phase-gate demonstrations.
