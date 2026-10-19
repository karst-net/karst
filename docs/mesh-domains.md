<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Mesh domains, identity, and access

This page records the agreed product model. The explicit root, root rename,
and compliance integration described here require follow-up implementation;
they are not a description of capabilities already shipped.

Tracked work: [ADR reconciliation (#361)](https://github.com/karst-net/karst/issues/361),
[domain implementation (#362)](https://github.com/karst-net/karst/issues/362),
and [client compliance integration (#363)](https://github.com/karst-net/karst/issues/363).

## Default domain and enrollment

Every account has exactly one explicit root mesh domain. New accounts start
with a root named `karst`. Administrators are expected to rename it to suit
their organization; renaming is optional and never blocks first enrollment.
`karst` is a private mesh naming default, not a claim to a public DNS domain.

Every machine belongs to exactly one domain. Enrollment without a selected
domain targets the account root, including after that root has been renamed.
The root's stable ID determines the default; the string `karst` does not.
An invitation targeting a deleted or invalid domain fails enrollment and
requires correction rather than silently placing the machine elsewhere.

The root anchors the account's mesh DNS namespace. A root named `karst`
gives illustrative names `laptop.karst` and `build.engineering.karst`.
It must not accidentally produce a duplicated root such as `laptop.karst.karst`.
The root suffix is appended once to a host label and a root-relative domain
path. Root devices have an empty relative path. Existing accounts retain
their effective suffix and names rather than being forcibly renamed; conflicting
legacy suffix settings require explicit reconciliation before migration.

The root cannot be deleted or reparented. Renaming changes affected DNS
names, including descendants, while preserving domain IDs, machine identities,
role bindings, and policy references. Administrators need a preview of affected
names before confirming a rename. There are no automatic old-name aliases:
online clients change suffix on their next successful configuration refresh,
cached answers may survive their TTL, and offline clients update on reconnect.
Plan the address change accordingly. Rollback is another validated rename;
identities and permissions remain stable.

## Relationships

| Entity | Meaning and relationship |
|---|---|
| Account / organization | Tenant and top-level authority; contains users, machines, domains, and policies. |
| Mesh domain | Naming namespace and delegated administrative scope; one parent except the root. |
| Machine | Enrolled device with stable cryptographic identity; belongs to one domain. |
| User | Account identity; may hold roles in multiple domain scopes. |
| Group / tag | Shared purpose or role for users or machines; may span domains. |
| Access policy | Explicit grants to resources, ports, or SSH, optionally conditioned on device compliance. |

Users do not need membership in a machine's domain to access it. Their
identity, groups, device attributes, and applicable policy determine access.
A user's machines may occupy different domains. Email-domain account linking,
custom ingress domains, and relay tenant isolation (Aquifer) remain separate
concepts; a mesh subdomain does not create a new tenant.

## Administration and connectivity

Account owners and administrators cover the whole domain tree. Delegated
domain administrators manage machines, invitations, and descendants within
their granted subtree and may delegate only within their authority. Moving a
machine requires permission over both source and destination domains.

Domain placement grants no automatic connectivity. Domain administration
grants no automatic SSH or resource access. Network and SSH policies govern
connectivity independently of management permissions. Policy references use
stable identities rather than mutable DNS names. Domain-based policy
selectors, if introduced, need explicit subtree semantics.

## Device compliance and reduced access

An organization may condition particular resource grants on fresh evidence
that a client device meets its requirements. Candidate checks include minimum
OS/client versions, disk encryption, screen lock, and managed-device or endpoint
security status; the implementation must document supported checks and evidence
strength per platform rather than assume all are available.

Compliance is evaluated per device and requirement set, not once per user or
as a universal permission. The same user can have a compliant laptop and a
noncompliant laptop with different effective access. A client must satisfy
both identity-based authorization and the resource's compliance conditions.

Noncompliant, unknown, unsupported, or stale evidence cannot satisfy a required
check. Such devices may retain explicitly granted lower-risk resources and
remediation access, while losing protected resources. Compliance never expands
an identity's existing authority or moves a device to another domain.

Changes and evidence expiry trigger reevaluation, bounded revocation of
existing access, and restoration after fresh passing evidence. Client UI should
explain failed requirements and remediation; administrators need an auditable
decision trail. Detailed evidence collection, trust, privacy, freshness, and
offline enforcement contracts belong in the compliance design work.

See [ADR-0032](adr/0032-hierarchical-mesh-domains-and-admin-assigned-names.md)
for the current architecture contract and historical implementation notes.
