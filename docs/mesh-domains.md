<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Mesh domains, identity, and access

This page records the agreed product model. Explicit-root provisioning,
migration, default enrollment, and root rename preview/confirmation are implemented.
Client convergence is unobserved; device compliance integration remains follow-up work.
[Acceptance validation](mesh-domain-validation.md) records migration, authority,
console and real Go/Rust client DNS coverage, including validation limits.

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

## Rename workflow

Open **Domains**, choose **Rename root**, enter the desired suffix and select
**Preview rename**. This requires account-wide domain-update authority; even a
user delegated administration of the root cannot rename the account suffix.
Preview canonicalizes the suffix, validates device and descendant names and
split-DNS compatibility, reports affected device/domain counts and shows up to
ten before/after names. Confirm that old names will stop resolving, then commit.

The API uses `POST /api/karst/v1/domains/root/rename/preview` with `dns_suffix`,
then `/commit` with the returned canonical suffix, opaque `revision`, and
`confirm_no_aliases: true`. The preview token is bound to the target suffix and
reviewed account naming state. A stale confirmation returns 412 and requires a
fresh preview; invalid names, DNS conflicts or missing confirmation return 422.
Domain creation/deletion, enrollment, placement and DNS-setting writes coordinate
with rename through the account/root lock. The suffix, account settings and
network DNS projections commit in one transaction, advancing naming and network
revisions without rewriting relative peer names, IDs, invitations or authority.

The console reports **committed configuration**, never an acknowledged fleet
cutover. The current client protocol provides no application acknowledgement, so
client convergence is explicitly **unobserved**. Online Karst clients poll the
persisted DNS configuration; streaming management clients are also notified.
Restart or a missed notification does not discard the committed suffix. Existing
answers can remain cached for 60 seconds; offline clients keep their previous
configuration until reconnect. There are no automatic aliases. Verify affected
clients' DNS status and both forward/PTR answers during the maintenance window.

**Preview rollback** starts another rename to the previous suffix with a fresh
revision and confirmation; after a page reload, enter the previous suffix in
**Rename root**. Each committed change advances `naming_revision` and records the
actor and old/new suffix in the audit event. Transaction failures leave the old
configuration intact. If a request fails after commit, reload the domain tree to
check the active suffix before retrying; repeated commits are not replayed.

## Upgrade and migration

Back up the database and stop all management replicas before upgrading. Mixed
old/new writers and downgrade against a migrated database are unsupported.
Startup migrates each account in a transaction before cache warmup or request
handling. It creates an explicit root from the effective legacy suffix, attaches
formerly top-level domains beneath it without changing relative paths, and
backfills machines and enrollment keys that used the implicit root. Existing
machine labels, IDs, addresses, invitation targets, and delegated scopes remain
unchanged. Empty accounts with no configured suffix use `karst`.

If active settings disagree, or graph/resource references are invalid, startup
stops with the affected account and setting/reference in its diagnostic. Review
`settings_dns_domain`, `network_dns`, and the active server `--dns-domain`
fallback against the names clients use. Reconcile conflicts explicitly; do not
silently choose a suffix or delete active resources to make migration pass.
Stale delegation references must be revoked before migration. Historical,
unusable invitations may retain deleted-domain metadata; usable ones must
reference a valid domain. After correction, restart: completed accounts retain
their root IDs and failed account transactions leave no partial root/backfill.

New account creation persists the account and root atomically. Root metadata is
returned by the domains API (`is_root`, `dns_suffix`, `dns_name`), and the root has an empty
relative `path`. `dns_name` is the complete namespace for each visible domain,
including for delegated views that do not list the root. Peer `dns_label` and
domain `path` remain root-relative; the console qualifies them exactly once.
Omitted invitation/enrollment targets use the root's stable ID;
moving a device back to it requires that explicit ID. Legacy suffix-setting
writes cannot bypass the root-rename preview/confirmation flow.

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
