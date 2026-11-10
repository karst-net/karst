<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Estavelle service associations

ADR-0056's addendum settled on Estavelle-only transport fallback: standalone
TURN support (a managed adapter to coturn or an external provider, the other
option ADR-0056 originally left open) was dropped. The first control
implementation adds explicit, account-scoped service associations;
service-driven netmap publication is opt-in. The reference
[Compose deployment adapter](../deploy/compose/README.md#estavelle-deployment-adapter)
and the bare-metal [systemd adapter](../deploy/systemd/README.md#estavelle-deployment-adapter)
each manage the local Ponor process separately from account publication. A
Kubernetes adapter and full transport verification remain tracked in #446.

## Console

Open **Estavelles → Services** to inspect or create associations. Choose an
existing Ponor endpoint explicitly. No backend is selected based on region or
address.

The service table shows Ponor admission observations. The console refreshes
observations once a minute.

Use **Ponor endpoints** within Estavelles for existing backend administration.
If an older control server lacks the service API, the Services view reports
that error while the backend view remains accessible. Upgrade control before
using associations. Removing an association does not remove the backend
process or registry record. In service publication mode, endpoints used only
by that association are withdrawn from clients. The console makes the active
publication mode explicit.

## Mode lifecycle

**Change modes** sets Ponor participation explicitly and requires a
connectivity acknowledgment. In service publication mode, a disabled endpoint
is withdrawn from subsequent netmaps. In legacy publication mode, the flag is
staged and does not change the legacy endpoint set. Disabling the mode
retains the service for diagnosis and later re-enablement; it does not
invoke provider process controls.

`PUT /estavelle-services/{serviceId}/modes` requires `ponor_enabled`, plus
`acknowledge_connectivity_change: true`. A missing boolean is rejected rather
than interpreted as false. Active publication is validated transactionally,
including an enabled Ponor bootstrap endpoint somewhere in the account. A
failed update rolls back the flag. Legacy rows acquire a `ponor_disabled:
false` default on upgrade.

Updated agents keep transport workers available when the initial registry is
empty. Ponor connections stop when their published endpoint is withdrawn and
can reconnect after re-enablement. Endpoint changes still reconcile underlay
escapes before becoming active.

### Agent compatibility

Updated agents declare `relay_lifecycle_schema: 1` on each authenticated
netmap request. Control records the latest declaration for that identity,
including zero after a downgrade. Live service mode changes and activation
of staged disabled modes require schema 1 from every enrolled Karst agent in
the account. Offline agents with missing or incompatible reports block
activation: upgrade and refresh their netmaps, or remove retired agents.
Legacy publication and service publication without mode flags remain
compatible with older agents.

Under active schema 2 service publication, an incompatible agent receives an
explicit failed-precondition response. The declaration describes
compatibility; it is neither software attestation nor authorization. It does
not revoke cached configuration or replace policy, Bedrock, identity pins, or
packet authentication.

If incompatible agents block recovery, explicitly select legacy publication,
reset the staged mode flag, then select publication again to clear the
marker. Review the legacy endpoints before selecting that authority.

### Downgrade preparation

The mode flag requires persistence schema 2. Control stores a `legacy-v2` or
`services-v2` authority marker while returning the ordinary public `mode`
plus `schema_version: 2`. Earlier service-aware control rejects these unknown
markers on netmap reads, instead of silently ignoring a disabled mode. Never
overwrite the marker using an older administrative API.

Before downgrading, use updated control to reset the mode flag for every
association (or remove the associations), then explicitly select publication
again. The version marker clears only when no disabled flags remain. Verify
that `schema_version` is absent and review the selected legacy endpoint set
before switching to a pre-service binary. Such older binaries ignore the
service authority table entirely. Keep database backups and retained backend
credentials/identity pins; mode changes do not rotate them.

## Administrative API

The authenticated management API exposes these additive endpoints under
`/api/karst/v1`, using the existing Karst control permissions:

| Method and path | Effect |
|---|---|
| `GET /estavelle-services` | List this account's associations and Ponor registry presence |
| `POST /estavelle-services` | Create a group-managed association to an existing account-local registry record |
| `DELETE /estavelle-services/{serviceId}` | Delete the association; withdraw its otherwise unused endpoint when service publication is active |
| `GET /estavelle-services/publication` | Read the persistent authority choice: `legacy` or `services` |
| `POST /estavelle-services/publication/preview` | Validate and list the service associations without changing publication |
| `PUT /estavelle-services/publication` | Change authority with `mode` and `acknowledge_connectivity_change: true` |

Members and the narrowly scoped scaler role cannot manage these records. The
request cannot supply an account ID, identity key, or credential. Unknown
fields and multiple JSON documents are rejected. The referenced registry ID
must belong to the caller's authenticated account.

`POST /estavelle-services` always requires `access_managed: true` and at least
one entry in `allowed_groups`; there is no account-wide bypass. Service
publication must already be active and the backend must have a live,
identity-bound admission writer (ADR-0058) before the group-managed
association can be created.

Example request body (substitute the existing registry ID and group IDs):

```json
{
  "id": "primary",
  "ponor_id": "existing-ponor-registry-id",
  "access_managed": true,
  "allowed_groups": ["existing-group-id"]
}
```

`id` is a stable service name, 1–64 letters, digits, underscores or hyphens,
starting with a letter or digit. `ponor_id` is required.

The list response includes `ponor_present`. It indicates whether the
referenced registry record still exists in the same account; it is **not a
runtime health result**. A legacy registry deletion preserves the
association and reports the backend missing. In service publication mode,
subsequent netmaps withdraw that endpoint. It never matches a replacement by
address, region, or provider.

## Additive migration and rollback

1. Back up the control database using the deployment's existing procedure.
   Export the existing `/relays` records and preserve identity pins,
   registry files, and per-account ownership.
2. Review the desired associations explicitly. A matching region or host does
   not prove association.
3. Upgrade control before using `/estavelle-services`. Older control versions do
   not expose this API. Existing client wire projections remain unchanged,
   so this step requires no client upgrade.
4. Install the identity-bound admission writer for each backend and confirm
   its lease is live (`GET /estavelle-services/admission-targets`), and confirm
   the account groups to grant already exist. `POST /estavelle-services` always
   requires `access_managed: true` and at least one allowed group — there is
   no unmanaged bridge to create the association in before groups are
   chosen. Existing file-only registry entries must first be represented in
   the account-local registry before they can be associated; do not guess
   IDs.
5. Use **Preview service publication** (or the preview API). It validates
   account-local references before activation.
6. Review the acknowledgment and switch publication to `services` before
   creating any association: `configureAccess` requires that authority
   already be active. With no services created yet this briefly publishes no
   Estavelle endpoints — it never falls back to legacy/global entries — so
   proceed straight to the next step.
7. Create each association with its `allowed_groups`, then list it and
   inspect the presence field, to restore access without an extended gap. An
   invalid reference returns 422; a duplicate service ID returns 409. Control
   revalidates the configuration and notifies connected clients as each
   association is added. Only the referenced endpoint is projected into the
   existing `relays` field; pins remain protocol-specific.
8. To roll back, explicitly restore `legacy` publication before downgrading
   control. This can republish previously omitted legacy endpoints; review
   the old registry first. Older control binaries ignore the publication
   table, so downgrading without this step bypasses the chosen service
   authority. Keep the additive service/publication tables for a later
   upgrade. Removing an association does not rotate keys. In service mode it
   does change the endpoint set sent to clients.

This stage deliberately retains the legacy `/estavelles` API and separate
client netmap field. It does not remove legacy configuration or introduce a
new credential authority. Bulk configuration migration tooling and per-mode
health/accounting beyond what #440/#444 landed remain required by #446. See
[relay-migration-verification.md](relay-migration-verification.md) for
executed schema-compatibility and direct+Ponor transport verification, and
what it does not yet cover.

## Installation handoff

Estavelles also offers a form-generated installer for the one-Estavelle
co-located reference Compose deployment (ADR-0062). It delivers runtime
configuration and an identity-bound managed-only roster writer without manual
configuration editing. Host-generated public receipts fill registration, then
the same access form controls groups and optional egress. Installation,
registration and traffic readiness remain separate. See the reference Compose
guide for prerequisites, retry stages and the required generated lifecycle
overlay. Remote provisioning, Aven installation and authenticated remote
roster delivery remain outside this handoff.
