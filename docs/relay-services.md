<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Relay service associations

ADR-0056 combines Ponor and TURN under one Relay service model. The first
control implementation adds explicit, account-scoped service associations;
runtime backend management, consolidated health probes, and service-driven
netmap publication remain tracked in #404.

## Console

Open **Relays → Services** to inspect or create associations. Choose an existing
Ponor endpoint explicitly, then optionally select a TURN backend, its deployment
type, and its operator. No backend is selected based on region or address.

The service table shows Ponor admission observations separately from TURN
registration. TURN runtime health is reported as unavailable until a backend
health adapter supplies evidence. A missing registration remains visible even
when the other mode is present.

Use **Ponor endpoints** and **TURN backends** within Relays for existing backend
administration. The legacy `#/turns` link remains supported. If an older control
server lacks the service API, the Services view reports that error while the
backend views remain accessible. Upgrade control before using associations.
Removing an association does not remove either backend.

## Administrative API

The authenticated management API exposes these additive endpoints under
`/api/karst/v1`, using the existing Karst control permissions:

| Method and path | Effect |
|---|---|
| `GET /relay-services` | List this account's associations and per-mode registry presence |
| `POST /relay-services` | Create an explicit association to existing account-local registry records |
| `DELETE /relay-services/{serviceId}` | Delete only the association |

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
reports that mode missing. It never matches a replacement by address, region,
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
4. Create each association, then list it and inspect both presence fields.
   An invalid reference returns 422; a duplicate service ID returns 409.
   Existing file-only registry entries must first be represented in the
   account-local registry before they can be associated; do not guess IDs.
5. For rollback, remove unwanted associations or run the previous control
   version while retaining the additive `karst_relay_services` table. Deleting
   an association does not delete registry records, stop coturn, contact an
   external provider, rotate keys, or withdraw published endpoints.

This stage deliberately retains the legacy `/relays` and `/turns` APIs and
separate client netmap fields. It does not remove legacy configuration,
introduce a new credential authority, or claim completion of the managed TURN
adapter. Review-before-apply migration tooling, lifecycle operations, per-mode
health/accounting, and full transport verification remain required by #404.
