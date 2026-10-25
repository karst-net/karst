<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-0058: Form-managed group and resource access

- **Status:** Accepted
- **Date:** 2026-10-25
- **Deciders:** Project owner direction in issue #439
- **Related:** #439, ADR-0032, ADR-0055, ADR-0056, ADR-0057

## Context

The console exposed two unrelated group rosters: account device groups and
literal user lists inside policy JSON. Similar names suggested a relationship
that did not exist. Administrators had to edit JSON to grant traffic, and a
registry-group rename could mislead them about which access had changed.
Relay associations also exposed no group restriction, and registering an
endpoint was easily confused with provisioning a running workload.

## Decision

Use account-scoped group IDs for new form-managed access grants. Persist grants
and explicit legacy-group bindings in the existing immutable policy ledger.
Resolve live membership when compiling inbound, outbound and SSH filters and
previewing access. A missing group matches nobody; an unavailable membership
source prevents compilation. Blocked and pending owners are inactive.

Combine Groups and Access controls under Groups & access. Group, user and device
pickers replace configuration entry. Legacy rules remain readable and unchanged;
explicitly mapping a legacy group to a registry group requires an access preview
and acknowledgment. Grant changes use the loaded policy version, not last-write
wins. An empty SSH gate must survive automatic serialization and deletion of the
last form-managed SSH grant.

Provide a relay configuration form for registered, running backends. It selects
allowed groups, optional IPv4/IPv6 internet egress, an explicitly bound Linux
Gateway identity, and route priority. This is registration/configuration, not
cloud provisioning. Provider/cluster provisioning remains unavailable and is
not simulated by a successful configuration response.

Relay group restriction requires a live, operator-installed roster writer bound
to the relay public identity. A capability lease renews only after the writer
successfully replaces its admission roster. Reject group-managed configuration
without a lease renewed within 50 seconds. The default roster refresh is 25
seconds; the relay polls every 5 seconds and expires an unrenewed roster after
90 seconds. Existing sessions revalidate admission on roster replacement.
Endpoint discovery is filtered too, but is not the authorization boundary.

Keep a durable backend-access record after association deletion. Deleting the
service withdraws access instead of re-enabling legacy admission. Reject shared
associations for a newly managed backend until explicitly consolidated. Retain
explicitly registered legacy tenants on a shared relay without granting a new
unregistered tenant access. Use a v3 publication marker so older controllers
reject persistence semantics they cannot enforce.

Create/update/delete the association, backend-access record, managed exit routes
and generated traffic grant in one database transaction. Use service revisions
for access updates and policy versions for ledger writes. No provider is called
from this transaction. Exit offers require local client consent and genuine
forwarding readiness. The explicitly selected Gateway is admitted to the relay
to serve those clients even if it is not a member of a client group.

The current packet-filter contract expresses ingress authorization by source
node and ports, not by destination subnet. Managed exit service therefore also
requires a machine ingress grant to its Gateway. The form's confirmation states
that permitted groups gain all-port access to that machine; an existing SSH gate
still applies. Destination-scoped gateway ingress needs a versioned datapath
contract before these permissions can be separated. Do not describe this
configuration as granting only internet access.

### Alternatives rejected

- Resolve group names to copied user lists at save time: membership changes
  would leave stale permissions, and renames would still be ambiguous.
- Match policy groups and device groups by display name: their membership sets
  can differ and migrating them implicitly can widen access.
- Hide relay endpoints without changing admission: cached endpoints bypass it.
- Mark a relay process as an exit node: internet egress is performed by an
  enrolled Gateway agent; co-location does not establish identity.
- Save policy, routes and associations as separate UI requests: partial failures
  can leave grants or routes that the UI reports as absent.

## Consequences

### Positive

Normal group and resource access administration requires no JSON or raw group
IDs. Renames preserve grants. Current membership controls effective permissions.
Resource configuration is transactional, and unsupported admission capability
fails visibly before an administrator can claim the restriction is active.

### Negative

Legacy policy names require an explicit migration choice. Older controllers
reject the new marker during netmap projection. That marker cannot fence an old
roster writer: operators must not downgrade the admission writer or replace it
with a legacy unrestricted exporter while managed restrictions exist. A deployment must
install an identity-bound admission writer before enabling group-managed relay
access; remote workload provisioning is not implemented. Membership changes now
refresh the entire account while Karst registry grants are present, rather than
relying on the inherited dependency graph, which does not know about them.
Gateway ingress permission is broader than destination-only egress, as explained
above. Already configured legacy global permissions remain additive until
explicitly migrated; adding a narrow grant does not cancel a broad legacy rule.

### Reconsider if

A remote relay management agent supplies authenticated roster delivery, provider
provisioning acquires durable orchestration, the datapath gains scoped Gateway
ingress grants, or membership-driven account-wide refresh becomes a bottleneck.
