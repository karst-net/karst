<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-0062: Form-generated local Relay installation handoff

- **Status:** Accepted
- **Date:** 2026-10-25
- **Related:** #439, ADR-0058, ADR-0059

## Context

The console configures registered backends but previously required an operator
to write the Relay runtime configuration, bind an admission writer, and copy a
public identity into the registration form. Infrastructure connections currently
discover locations; they are not workload provisioning authorities. The existing
supported runtime delivery path is one co-located reference Compose control
service and Relay, sharing local files.

## Decision

Offer an installation form on Relays. Download one Python program with public
endpoint, TLS name, region, declared location and selected Karst image settings
encoded as data. Administrators run it on the existing Linux control host;
there is no configuration-file editing or administrator API credential handoff.
The download itself is not a deployment operation or a readiness report.

Support one reference Compose control replica and one co-located Relay. Require
Python 3.11+, Compose v2, OpenSSL and the deployment's existing trusted Relay TLS
material. Reuse the Relay seed if present; generate a missing seed using the
selected Relay image. Never rewrite management credentials, policy, the legacy
registry, original runtime configuration or TLS material. Reject registry
mismatches rather than silently moving an existing identity. Remote hosts,
provider provisioning, new trust-root distribution, additional local writers,
custom Relay execution settings and Gateway installation are outside this path.

Generate a separate Relay TOML and Compose overlay. Probe the selected control
image without credentials, networking or deployment volumes using
`--relay-installation-capabilities`. Require `managed-roster-v1` before stopping
services. Both image choices are part of the overlay; a supported image is not
inferred from a tag or an environment variable an older binary could ignore.
Validate the normalized merged Compose model, including inherited ports and
mounts. Stop the old Relay and writer before clearing the roster, then bind the
writer to the seed's public identity and start the generated configuration.

`KARST_RELAY_REQUIRE_MANAGED=true` requires a roster path and explicit identity.
In this mode the writer admits only tenants with persisted managed backend
access, using current group membership and existing account/owner checks. An
unconfigured or legacy tenant is denied even when no managed record exists
anywhere. This prevents the installation/registration/configuration gap from
inheriting legacy account-wide admission. Existing configured managed access
continues to work. The default environment behavior is retained for deployments
not opting into this installation contract.

Use a host-local installation lock, atomic private files and explicit preparing,
starting, runtime_started and failed stages. Runtime_started never means ready.
Remove old receipts before a new runtime attempt; a failure cannot leave a
previous receipt masquerading as success. A failed attempt preserves keys and
records retry guidance; successful subprocesses are not automatically rolled
back. Retry identical settings. Changed settings need a separately reviewed
migration instead of silently replacing this installation record.

The installer produces a public registration receipt after control and Relay
containers report running. Importing it fills registration fields, strips
unknown fields and requires administrator review. Match existing registrations
by the public key, never a caller-supplied identity ID. Reuse matching existing
registrations and configurations. Backend API authorization, account ownership
and identity validation remain authoritative. Group access and optional egress
are reviewed/applied through the existing transactional configuration form; no
receipt can create grants or assert end-to-end readiness.

## Alternatives rejected

- Give the downloaded program an administrator token: exposes unrelated account
  administration to a runtime host and turns a public handoff into a secret.
- Treat infrastructure discovery credentials as provisioning credentials:
  expands their authority without a provider lifecycle or spend model.
- Ship a remote roster over an unauthenticated file download: fails the
  provenance requirement and risks cross-account disclosure or replay.
- Start with a legacy unrestricted roster until the form is completed: makes
  an unfinished installation broader than its stated access configuration.
- Rewrite the original Compose file or regenerate trusted keys: makes recovery
  and trust continuity dependent on hidden destructive edits.

## Costs and remaining work

This is a supported local installation handoff, not remote provisioning or an
ongoing authenticated management agent. It restarts control as well as Relay.
Adopting a legacy Relay denies its unconfigured tenants, which is disclosed
before download and apply. The host operator must keep using the generated
Compose overlay; reverting to the old writer or downgrading control can bypass
the new contract. No automatic rollback reopens access. A failed restart can
require local Docker diagnosis and rerunning the handoff.

Existing trusted TLS must already be initialized; this workflow does not solve
initial control deployment or client trust distribution. Installation state is
host-local and is not an audited remote job record. A receipt is public metadata
from a trusted operator handoff, not cryptographic proof of installation. The
console's writer/forwarding observations and client exit consent remain
independent. Remote authenticated delivery, applied-revision acknowledgment,
provider adapters, Gateway agent installation and destination-scoped Gateway
ingress remain follow-up work for #439.
