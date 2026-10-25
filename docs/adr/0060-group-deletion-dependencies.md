<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-0060: Review and resolve group dependencies before deletion

- **Status:** Accepted
- **Date:** 2026-10-25
- **Deciders:** Project owner direction in #439
- **Related:** ADR-0058, ADR-0059

## Context

Native group deletion checks inherited management resources, but does not know
Karst's structured access grants, legacy membership mappings or relay admission
records. The console's confirmation counted a partially loaded policy snapshot
and omitted relay dependencies. A group could be deleted while those records
still referenced its identity. Retained immutable invitation history could also
make a group permanently undeletable even after its invitation was revoked.

## Decision

Review group deletion in a form. Load current group membership and dependencies
from access grants/mappings, relays, Gateway routes, DNS, automatic user
assignments and device invitations. Name dependencies and link to their owning
forms. Resolve them there before deletion; do not automatically cascade access
changes. Unavailable data blocks the review. Require an explicit acknowledgment
for an unreferenced group and reload before submitting. A changed impact clears
acknowledgment and requires another review.

Extend native transactional deletion validation to check the current account's
latest policy, relay configurations and retained backend admission restrictions.
Historical policy versions do not block deletion; policy restore already
validates referenced groups. Empty retained relay deny records remain intact.
Existing native dependency checks and authorization remain in force.

Active invitations block deletion. Revoked, expired and exhausted invitations
cannot enroll peers; keep their history without blocking group deletion.
Preserve existing legacy setup-key deletion behavior.

## Alternatives rejected

- A confirmation with a count omits resource identity and can mistake loading
  failures for no dependencies.
- Cascading deletion across policy, relay and inherited management resources
  obscures independent access changes and their review/version contracts.
- Deleting invitation history to remove the dependency loses the audit trail.

## Costs and limits

Review performs several account-scoped reads and can be blocked by an unavailable
service. Administrators must resolve dependencies in multiple owning forms.
Inherited management features outside the console review are still checked by
the server and may reject deletion. Reloading is a freshness check, not a
transactional snapshot across APIs; server validation is authoritative. This
change does not introduce a cross-resource locking/version contract for every
concurrent mutation, nor a cascade operation for deleting in-use groups.
