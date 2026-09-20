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

Before each run, the lab bootstrap must create a fresh, single-use invitation
and 64 KiB HTTP plus UDP-echo fixtures reachable only at the enrolled peer's
overlay address. It writes the invitation to a mode-0600 file owned by the runner,
deletes it after the run, and resets the Mac's test account or APFS snapshot.
The bootstrap publishes only these protected GitHub Environment variables:

- `KARST_CI_INVITATION_FILE` — absolute path to the fresh invitation file.
- `KARST_CI_PROBE_URL` — `http` or `https` URL at the overlay peer's 64 KiB
  fixture.
- `KARST_CI_UDP_HOST` and `KARST_CI_UDP_PORT` — overlay UDP echo endpoint.

The `macos-network-extension-lab` Environment must hold the signing identity,
installer identity, and both provisioning profiles. It must not be available
to fork pull requests.

## What the job proves

The CI-only `KarstConnectivityCI` executable is a separate SwiftPM target and
is never included in `Karst.app`. It uses the saved
`NETunnelProviderManager` to send the fresh invitation, starts a disconnected
session, waits for an interface and established peer, then fetches at least
64 KiB over TCP and verifies a UDP echo through the peer's overlay address.
It emits only counts and status;
logs and artifacts redact invitations.

Keep the workflow opt-in until the lab has passed repeated dispatch runs. Set
`KARST_MACOS_NE_LAB_ENABLED=true` only after that, enabling the nightly run.
Promote it to a required, path-filtered PR gate after its flake rate and reset
behavior are understood.
