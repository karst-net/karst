<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# NIST SP 800-53 implementation crosswalk

This document is the implementation detail behind the individual-control
selection matrix. It is written for the engineer defining the full system
boundary: it identifies what Karst supplies, what evidence can be collected,
and what must be supplied by the surrounding system. It is not an assertion of
control satisfaction or an authorization decision.

Each heading links to the authoritative [NIST Cybersecurity and Privacy
Reference Tool catalog](https://csrc.nist.gov/projects/cprt/catalog). Consult
the selected control's full statement, supplemental guidance, parameters, and
assessment procedures there; this crosswalk intentionally paraphrases rather
than reproduces the catalog.

## [AC-02 Account Management](https://csrc.nist.gov/projects/cprt/catalog)

Karst consumes IdP subjects and optional SCIM state, maps them to Karst roles
and groups, maintains a separate device lifecycle, and records lifecycle
changes. Blocking or deprovisioning a user stops Karst account use; revoking a
node removes that device's membership. This supports the account inventory,
creation, modification, disablement, notification, and review activities in
the Karst boundary. Evidence is the IdP/SCIM configuration, account/device
records, and administrative audit history.

`AC-02(01)` is shared: SCIM can automate account lifecycle, but the
authoritative source, approval, and reconciliation process belong to the
organization. `AC-02(02)` is only partially aided by short-lived/single-use
enrollment credentials; temporary/emergency account policy remains external.
`AC-02(03)` maps to account blocking/deprovisioning and node revocation.
`AC-02(04)` maps to lifecycle audit events. `AC-02(12)` can consume Karst
telemetry as an atypical-use signal, and `AC-02(13)` maps an organization risk
decision to Karst disablement. `AC-02(05)` and `AC-02(11)` are not Karst
functions: the IdP/application must implement session timeout and usage terms.

## [AC-03 Access Enforcement](https://csrc.nist.gov/projects/cprt/catalog) and [AC-04 Information Flow Enforcement](https://csrc.nist.gov/projects/cprt/catalog)

Karst evaluates default-deny policy against authenticated node/user/group/tag
identity, destination, protocol, and port, then distributes the resulting
policy for stateful client enforcement. Subnet routers add a separate forwarding
boundary: forwarded traffic must originate at the Karst tunnel and target an
advertised prefix. Evidence includes versioned ACL policy, policy-change audit
records, netmap/policy distribution evidence, and denial counters.

The security engineer must select the smallest route and ACL that meet the
need: a `/32` plus a port is materially different from a whole LAN or `/0`
exit route. The destination service still performs application authorization.
`AC-04(04)` is shared only: Karst can enforce metadata-level overlay flows but
does not inspect encrypted application content or replace a DLP/content policy.

## [AC-05 Separation of Duties](https://csrc.nist.gov/projects/cprt/catalog) and [AC-06 Least Privilege](https://csrc.nist.gov/projects/cprt/catalog)

Karst distinguishes client users, administrators, auditors, relay operators,
control service identities, and offline Bedrock authority operators. Auditors
are read/verify/export only; relay operators carry ciphertext without policy
authority; Bedrock signing authority is outside the online console. Bedrock
`enforcing` requires independently signed membership coverage even if the
online control service is compromised. Evidence is role assignment, Bedrock
configuration and signed state, and audit-sink separation.

`AC-06(01)` maps Karst administrative functions to administrative roles.
`AC-06(02)` maps the separation of ordinary user and administrator access in
the Karst service; the host and applications must separately provide
non-privileged operation. `AC-06(05)` and `AC-06(07)` are shared: distinct
roles and audit/policy history support privileged-account governance and
review, while account designation and review cadence remain organizational.
`AC-06(09)` directly maps administrative actions to the audit log. `AC-06(10)`
directly blocks non-administrators from Karst administrative functions, but not
from privileged functions in applications or the operating system.

## [AC-17 Remote Access](https://csrc.nist.gov/projects/cprt/catalog)

Karst provides authenticated PHREATIC sessions between enrolled endpoints,
with encrypted relay fallback and policy-controlled private routes. Subnet
routers extend that access to selected networks; an exit node deliberately
extends it to Internet egress. Evidence is node enrollment state, ACLs, route
offers/consent, relay/path telemetry, and cryptographic protocol documentation.

`AC-17(01)` is shared: Karst metrics and policy can monitor/control its remote
access surface, while the organization owns alerting and response. `AC-17(02)`
is direct for the overlay's confidentiality and integrity. `AC-17(03)` is
shared: routers and exit nodes are managed access points, but their hardening,
administration, and upstream network controls belong to the deployment.
`AC-17(04)` is external because Karst does not authorize privileged host
commands. Mandatory full-tunnel use on a self-administered host likewise needs
endpoint management; Karst intentionally requires local exit-node consent.

## [AU-02 Event Logging](https://csrc.nist.gov/projects/cprt/catalog), [AU-03 Record Content](https://csrc.nist.gov/projects/cprt/catalog), and [AU-12 Generation](https://csrc.nist.gov/projects/cprt/catalog)

Karst generates append-only, hash-chained administrative records for policy,
membership, role/group, enrollment, revocation, relay, Bedrock, and remediation
changes. The record stream supports actor/action filtering, ordered history,
verification, and export. Evidence is the log, hash-chain verification result,
exported records, and the documented event schema.

`AU-03(01)` is shared because the organization decides any additional audit
content and joins Karst records with downstream evidence. `AU-12(03)` directly
covers authorized Karst configuration changes, not all system changes.
`AU-12(01)` is external: host, IdP, application, gateway, and infrastructure
logs are needed for a system-wide, time-correlated trail.

## [AU-06 Audit Review](https://csrc.nist.gov/projects/cprt/catalog) and [AU-09 Audit Protection](https://csrc.nist.gov/projects/cprt/catalog)

Karst supplies an auditor role, filtering, chain verification, export, policy
history, and optional forwarding to an audit sink/SIEM. A local hash chain
makes unexpected modification or deletion detectable when a known head is
available; it is not independent retention. Evidence includes role bindings,
verification output, forwarding configuration, and receiver-side retention.

`AU-06(01)` and `AU-06(03)` are shared through SIEM/audit-sink integration;
correlation rules, alert thresholds, investigation, and response remain with
the organization. `AU-09(02)` and `AU-09(03)` require separately administered
and cryptographically protected storage. `AU-09(04)` maps directly to the
auditor-role restriction. `AU-06(05)` and `AU-06(06)` remain external enterprise
analysis/physical-security functions.

## [CA-07 Continuous Monitoring](https://csrc.nist.gov/projects/cprt/catalog) and [SI-04 System Monitoring](https://csrc.nist.gov/projects/cprt/catalog)

Karst exposes control-plane and node metrics, optional OTel traces, ACL
denials, malformed/decrypt/fragment failures, gateway and route state, relay
reachability, PSK age, and Bedrock equivocation signals. The metrics listener
is loopback-only; an external Prometheus/OTel/SIEM deployment is needed for
durable aggregation and alerting. Evidence is the collector configuration,
dashboards/alerts, retained measurements, and incident records.

`CA-07(04)` uses that telemetry as risk-monitoring input; risk acceptance is
organizational. `SI-04(02)`, `SI-04(04)`, and `SI-04(05)` are shared: Karst
observes its own protocol and produces signals, while real-time analysis,
full host traffic visibility, alert routing, and response are external.
`SI-04(20)` can use Karst audit/telemetry for privileged-user review. Karst
does not inspect application plaintext, provide wireless IDS, or discover all
host services, so `SI-04(10)`, `(12)`, `(14)`, and `(22)` are external.

## [CM-03 Change Control](https://csrc.nist.gov/projects/cprt/catalog) and [CM-05 Change Restrictions](https://csrc.nist.gov/projects/cprt/catalog)

Karst versions access policy, requires the version read when saving to prevent
silent last-write-wins replacement, audits changes and rollbacks, and limits
administrative functions to administrative roles. Evidence is versioned policy,
change/rollback records, role assignments, and deployment change records.

`CM-03(01)` and `CM-03(02)` are shared: Karst documents and exposes changes,
but the organization supplies notification, test/approval workflow, and
validation records. `CM-03(06)` is shared between Karst's documented key
design and organizational cryptography governance. `CM-05(01)` is direct for
Karst authorization/auditing but shared for all other system components.
`CM-03(04)` and `CM-01` are organizational policy/representative functions.

## [IA-02 Organizational Users](https://csrc.nist.gov/projects/cprt/catalog), [IA-03 Devices](https://csrc.nist.gov/projects/cprt/catalog), and [IA-05 Authenticators](https://csrc.nist.gov/projects/cprt/catalog)

Karst delegates human authentication to the organization IdP and maps the
authenticated subject to Karst roles/groups. Each node generates a ML-DSA-87
identity and static ML-KEM-1024 key; peer sessions authenticate those identities
and reject a known handle that presents a different identity. Enrollment
credentials are distinct from long-lived node identity; control-server pins are
provisioned before first contact; node identity is locally sealed; Bedrock
private keys remain offline. Evidence is IdP configuration, enrollment/key
records, pin configuration, Bedrock custody procedure, and protocol tests.

`IA-02(01)`, `(02)`, `(05)`, `(08)`, and `(12)` remain IdP/agency functions;
Karst must not be credited for MFA, PIV acceptance, or human-authenticator
policy. `IA-05(01)` is external because Karst does not manage human passwords.
`IA-05(02)` directly supports public-key authentication for Karst protocol
identities, while human use remains shared with the IdP. `IA-05(06)` is shared:
Karst protects its material as described, but platform, backup, and custody
controls complete the requirement.

## [SC-05 Denial of Service](https://csrc.nist.gov/projects/cprt/catalog), [SC-07 Boundary Protection](https://csrc.nist.gov/projects/cprt/catalog), and [SC-08 Transmission Protection](https://csrc.nist.gov/projects/cprt/catalog)

PHREATIC bounds unauthenticated reassembly and handshake fragmentation, applies
