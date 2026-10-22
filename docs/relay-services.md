<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Relay service associations

ADR-0056 combines Ponor and TURN under one Relay service model. The first
control implementation adds explicit, account-scoped service associations;
service-driven netmap publication is opt-in. An allocation adapter checks TURN
admission and readiness. Companion process management and full transport
verification remain tracked in #404.

## Console

Open **Relays → Services** to inspect or create associations. Choose an existing
Ponor endpoint explicitly, then optionally select a TURN backend, its deployment
type, and its operator. No backend is selected based on region or address.

The service table shows Ponor admission observations separately from TURN
registration and allocation readiness. The console refreshes observations once
a minute. A missing registration remains visible even when the other mode is
present.

Use **Ponor endpoints** and **TURN backends** within Relays for existing backend
administration. The legacy `#/turns` link remains supported. If an older control
server lacks the service API, the Services view reports that error while the
backend views remain accessible. Upgrade control before using associations.
Removing an association does not remove either backend process or registry record.
In service publication mode, endpoints used only by that association are withdrawn
from clients. The console makes the active publication mode explicit.

## Mode lifecycle

**Change modes** sets Ponor and TURN participation explicitly and requires a
connectivity acknowledgment. In service publication mode, disabled endpoints
are withdrawn from subsequent netmaps. In legacy publication mode, flags are
staged and do not change the legacy endpoint set. Disabling TURN pauses later
readiness probes for that association. Existing checks may finish within their
five-second bound. A shared backend stays published/probed while another
association enables it. Disabling both modes retains the service for diagnosis
and later re-enablement; it does not invoke provider process controls.

`PUT /relay-services/{serviceId}/modes` requires both `ponor_enabled` and
`turn_enabled`, plus `acknowledge_connectivity_change: true`. Missing booleans
are rejected rather than interpreted as false. Enabling TURN requires a
configured backend. Active publication is validated transactionally, including
credential configuration and an enabled Ponor bootstrap endpoint somewhere in
the account. A failed update rolls back both flags. Legacy rows acquire
`ponor_disabled: false` and `turn_disabled: false` defaults on upgrade.

Updated agents keep transport workers available when the initial registry is
empty. Ponor connections stop when their published endpoint is withdrawn and
can reconnect after re-enablement. TURN allocations are released when the
selected server is withdrawn/replaced, when their credential expires, or when
fresh credentials are available within sixty seconds of expiry. Ordinary
credential renewal does not rebuild the peer roster on every control poll.
Endpoint changes still reconcile underlay escapes before becoming active.

TURN metadata is refreshed even on an `unchanged` netmap response, as required
by the existing wire contract. Its exclusion from the peer-content hash is
preserved. Clients predating these runtime fixes need restart-based handling of
transport registry changes; live lifecycle behavior requires updated agents.
Mixed-version capability enforcement and complete namespace forwarding tests
remain tracked in #404.

Current agent publication supports UDP `turn:host:port` endpoints, including
IPv6 literals. TCP/TLS TURN endpoints and transport-query URI variants can be
staged and health-probed, but service preview/activation rejects them until the
node worker supports those transports. Allocation health from control does not
establish client protocol support. No TLS endpoint is rewritten to plaintext.

### Agent compatibility

Updated agents declare `relay_lifecycle_schema: 1` on each authenticated netmap
request. Control records the latest declaration for that identity, including
zero after a downgrade. Live service mode changes and activation of staged
disabled modes require schema 1 from every enrolled Karst agent in the account.
Offline agents with missing or incompatible reports block activation: upgrade
and refresh their netmaps, or remove retired agents. Legacy publication and
service publication without mode flags remain compatible with older agents.

Under active schema 2 service publication, an incompatible agent receives an
explicit failed-precondition response. The declaration describes compatibility;
it is neither software attestation nor authorization. It does not revoke cached
configuration or replace policy, Bedrock, identity pins, or packet authentication.

If incompatible agents block recovery, explicitly select legacy publication,
reset the staged mode flags, then select publication again to clear the marker.
Review the legacy endpoints before selecting that authority.

### Downgrade preparation

Mode flags require persistence schema 2. Control stores a `legacy-v2` or
`services-v2` authority marker while returning the ordinary public `mode` plus
`schema_version: 2`. Earlier service-aware control rejects these unknown
markers on netmap reads, instead of silently ignoring disabled modes. Never
overwrite the marker using an older administrative API.

Before downgrading, use updated control to reset both mode flags for every
association (or remove the associations), then explicitly select publication
again. The version marker clears only when no disabled flags remain. Verify
that `schema_version` is absent and review the selected legacy endpoint set
before switching to a pre-service binary. Such older binaries ignore the
service authority table entirely. Keep database backups and retained backend
credentials/identity pins; mode changes do not rotate them.

## TURN allocation observations

Control checks each distinct account/backend association about once a minute,
including staged services. Up to four probes run concurrently, each with a
five-second limit covering DNS, connection and allocation. Each check mints a
short-lived credential using the configured TURN credential authority, attempts
an authenticated allocation, then releases it. Probe logs and stored
observations contain neither credentials nor the allocation address. Normal
backend allocation limits apply to these short-lived checks.

The adapter supports UDP and TCP with `turn:` and TLS with `turns:`. TLS
certificate and hostname verification use the host's system trust roots;
install an internal provider's CA in that store when needed. TURN over DTLS and
unknown URI parameters are reported as unsupported. An unsupported probe does
not alter the backend registry or client wire compatibility.

The `turn_health` field identifies its source as `control_allocation_probe` and
reports a state, observation time, and elapsed milliseconds. States distinguish
allocation readiness, rejection, network failure, timeout, TLS verification
failure, expired/unavailable credentials, and unsupported configuration.
Observations older than three minutes (or from a future clock) become stale,
retaining the previous result and timestamp. Before the first observation, the state is `unknown`.

Allocation readiness is evidence from the **control host's network vantage**.
It does not prove permission/channel establishment to a peer, payload delivery,
every client's reachability, or overlay encryption. A failed check does not
automatically withdraw a backend or disable Ponor presence. Configuration and
publication remain operator decisions; client transport fallback remains local.
The worker starts with the control process and cancels outstanding checks at
shutdown. External provider processes are never started or stopped by a probe.

## Administrative API

The authenticated management API exposes these additive endpoints under
`/api/karst/v1`, using the existing Karst control permissions:

| Method and path | Effect |
|---|---|
| `GET /relay-services` | List this account's associations and per-mode registry presence |
| `POST /relay-services` | Create an explicit association to existing account-local registry records |
| `DELETE /relay-services/{serviceId}` | Delete the association; withdraw its otherwise unused endpoints when service publication is active |
| `GET /relay-services/publication` | Read the persistent authority choice: `legacy` or `services` |
| `POST /relay-services/publication/preview` | Validate and list the service associations without changing publication |
| `PUT /relay-services/publication` | Change authority with `mode` and `acknowledge_connectivity_change: true` |

Members and the narrowly scoped scaler role cannot manage these records. The
request cannot supply an account ID, identity key, credential, or shared secret.
Unknown fields and multiple JSON documents are rejected. Both referenced
registry IDs must belong to the caller's authenticated account.

Example request body (substitute the existing registry IDs):

```json
{
  "id": "primary",
  "ponor_id": "existing-ponor-registry-id",
  "turn_id": "existing-turn-registry-id",
  "backend_kind": "external",
  "backend_operator": "Example TURN provider"
}
```

`id` is a stable service name, 1–64 letters, digits, underscores or hyphens,
starting with a letter or digit. `ponor_id` is required. For a Ponor-only
service, omit all three TURN fields. A TURN association requires both
`backend_kind` (`external` or `coturn-companion`) and an explicit operator name.
The backend kind describes deployment ownership; it does not enable process
management. Multiple associations can reference a shared TURN backend. An
association does not establish that arbitrary multi-backend routing works.

List responses include `ponor_present` and `turn_present`. These indicate
whether the referenced registry records still exist in the same account;
they are **not runtime health results**. An absent optional TURN mode also has
`turn_present: false`; inspect `turn_id` to distinguish it from a missing
configured backend. A legacy registry deletion preserves the association and
reports that mode missing. In service publication mode, subsequent netmaps
withdraw that backend while continuing to publish the other available mode. It never matches a replacement by address, region,
or provider, and one mode's presence does not hide the other's absence.

## Additive migration and rollback

1. Back up the control database using the deployment's existing procedure.
   Export the existing `/relays` and `/turns` records and preserve identity pins,
   shared-secret configuration, registry files, and per-account ownership.
2. Review the desired associations explicitly. A matching region or host does
   not prove association. For a remote provider, identify its operator rather
   than implying that the Ponor operator also owns the TURN server.
3. Upgrade control before using `/relay-services`. Older control versions do
   not expose this API. Existing client wire projections and credential minting
   remain unchanged, so this step requires no client upgrade.
4. Create each association while publication is in legacy mode, then list it and inspect both presence fields.
   An invalid reference returns 422; a duplicate service ID returns 409.
   Existing file-only registry entries must first be represented in the
   account-local registry before they can be associated; do not guess IDs.
5. Use **Preview service publication** (or the preview API). It validates
   account-local references, the configured credential minter, and the supported
   topology. Service publication currently requires at most one distinct shared
   TURN backend per account; multiple associations may reference it. Other
   backend combinations fail explicitly until client dispatch supports them.
6. Review the service list and acknowledge the connectivity change before
   applying service publication. Control revalidates the configuration, persists
   the authority choice, and notifies connected clients. Only referenced
   endpoints are projected into the existing `relays` and `turn_servers` fields;
   pins and credential minting remain protocol-specific. An empty service set
   publishes no Relay endpoints and never falls back to global/legacy entries.
7. To roll back, explicitly restore `legacy` publication before downgrading
   control. This can republish previously omitted legacy endpoints; review the
   old registries first. Older control binaries ignore the publication table,
   so downgrading without this step bypasses the chosen service authority.
   Keep the additive service/publication tables for a later upgrade. Removing
   an association does not stop coturn, contact an external provider or rotate
   keys. In service mode it does change the endpoint set sent to clients.

This stage deliberately retains the legacy `/relays` and `/turns` APIs and
separate client netmap fields. It does not remove legacy configuration,
introduce a new credential authority, or claim completion of the managed TURN
adapter. Bulk configuration migration tooling, lifecycle operations, per-mode
health/accounting, and full transport verification remain required by #404.
