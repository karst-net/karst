<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# macOS Network Extension connectivity CI

The workflow at `.github/workflows/macos-network-extension-connectivity.yml`
is the integration gate for the packaged macOS Network Extension. It is not a
replacement for the existing macOS compile, `utun`, or package-layout jobs:
those do not load a System Extension or put application traffic through
`NEPacketTunnelProvider.packetFlow`.

## Required lab

Provide a protected physical Mac runner with the labels `self-hosted`,
`macos`, and `karst-network-extension`, plus a disposable Linux control,
relay, and peer service on an isolated network. The Mac needs a persistent
console-user session and MDM pre-approval for Karst's System Extension. Do
not use a GitHub-hosted macOS VM for this gate.

Before each run, the root-owned runner-local control program
`/usr/local/libexec/karst-ne-lab` must accept `prepare --scenario direct|relay
--env-file PATH`. It must create a fresh, single-use invitation and 64 KiB
HTTP plus UDP-echo fixtures reachable only at the enrolled peer's
overlay address. The initial scenario must leave the peers able to establish a
direct path; the harness rejects a merely-established relay path. It writes
the invitation to a mode-0600 file owned by the runner,
deletes it after the run, and resets the Mac's test account or APFS snapshot.
It writes a mode-0600 environment file containing only:

- `KARST_CI_INVITATION_FILE` — absolute path to the fresh invitation file.
- `KARST_CI_PROBE_URL` — `http` or `https` URL at the overlay peer's 64 KiB
  fixture.
- `KARST_CI_UDP_HOST` and `KARST_CI_UDP_PORT` — overlay UDP echo endpoint.

For a manual `run_route_churn=true` dispatch, `prepare` additionally receives
`--route-churn` and returns exactly these two extra, non-secret entries:

- `KARST_CI_SUBNET_PROBE_URL` — a 64 KiB HTTP fixture inside the initially
  withdrawn subnet.
- `KARST_CI_SUBNET_ROUTE_PREFIX` — its offered CIDR.

The runner controller must keep that fixture available, while
`mutate --route subnet --state add|remove` changes the disposable control
plane. The workflow waits for the extension’s live route status after each
mutation and performs HTTP traffic after the add. Both mutations must be
idempotent.

The checked-in `scripts/macos-network-extension-lab-handoff.sh` is the sole
parser for that handoff; its portable contract test exercises both ordinary
and route-churn manifests, plus rejected unexpected entries.
The workflow copies those non-secret paths/endpoints into its job environment,
then deletes the file. The invitation itself never enters GitHub variables or
logs. The `macos-network-extension-lab` Environment must hold the signing identity,
installer identity, and both provisioning profiles. Before adding them, give
that Environment an approval/branch policy that admits only trusted `main`
and manually dispatched runs; it must not be available to fork pull requests.
The repository-level `KARST_MACOS_NE_LAB_ENABLED` variable is deliberately
`false` until this provisioning is complete. It is the switch that permits
the scheduled run; the Environment holds the runtime-only values after a job
has been admitted.

## What the job proves

The CI-only `KarstConnectivityCI` executable is a separate SwiftPM target and
is never included in `Karst.app`, and runs as root. macOS delivers provider
messages only from the configuration's owning app, so the harness does not
use them: it stops the saved Karst configuration, leaves the fresh invitation
as the extension's root-only `pending-invitation` file (ADR-0028 item 6),
starts the configuration with `scutil --nc start`, and reads the embedded
engine's `status-json` from its root-only admin socket. It waits for a peer
with the requested transport, then fetches at least 64 KiB over TCP and
verifies a UDP echo through the peer's overlay address.

The saved configuration itself must already exist: launch `Karst.app` once
on the runner's console session and approve its "add VPN configurations"
prompt (MDM cannot pre-approve that one). Every run re-enrolls from its own
invitation, so the configuration persists across runs. Each run also
notarizes the package: `sysextd` refuses an un-notarized Developer ID System
Extension even when installed locally, so the Environment needs
`APPLE_NOTARY_KEY`, `APPLE_NOTARY_KEY_ID` and `APPLE_NOTARY_ISSUER`.
It emits only counts and status;
logs and artifacts redact invitations.

Keep the workflow opt-in until the lab has passed repeated dispatch runs. Set
`KARST_MACOS_NE_LAB_ENABLED=true` only after that, enabling the nightly run.
Promote it to a required, path-filtered PR gate after its flake rate and reset
behavior are understood.

## Transport scenarios

The scheduled run verifies the direct path. Run a second manual dispatch with
`expected_transport=relay` only after the lab bootstrap has prevented a direct
candidate while leaving the disposable relay reachable. The harness checks the
peer's live `transport` value *and* carries the TCP and UDP probes, so a status
display alone cannot satisfy either scenario. Reset the peer and create a fresh
invitation between the direct and relay runs.

## Route-churn scenario

Use the manual `run_route_churn=true` dispatch after direct connectivity is
stable. It adds a subnet route, waits for the provider’s embedded engine to
report the active offer, fetches at least 64 KiB through the newly routed
subnet without a proxy, then removes the offer and waits for the status to
show withdrawal. This is separate from the scheduled direct run until the lab
controller implements the mutation contract and repeated hardware runs
establish its reliability.

## Exit-route scenario

Use the manual `run_exit_route=true` dispatch only after direct connectivity is
stable. `prepare --exit-route` must additionally supply a 64 KiB
`KARST_CI_EXIT_PROBE_URL`, `KARST_CI_EXIT_ROUTE_PREFIX`, and control-plane and
relay probe URL, host, and expected native-interface triples:
`KARST_CI_CONTROL_PLANE_{PROBE_URL,HOST,INTERFACE}` and
`KARST_CI_RELAY_{PROBE_URL,HOST,INTERFACE}`. The exit probe must be reachable
only through the disposable exit. After `mutate --route exit --state active`,
the job verifies the active default route, transfers the exit probe with no
proxy, verifies both control/relay hosts still select their supplied native
interfaces and remain reachable, then withdraws the route and waits for live
status to report its absence. The controller must make both exit mutations
idempotent.
