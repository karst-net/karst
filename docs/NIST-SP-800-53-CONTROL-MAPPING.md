<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# NIST SP 800-53 control mapping

## Scope

This document maps Karst mechanisms and deployment choices to the portions of
NIST SP 800-53 Rev. 5 that Karst can materially help implement. It is intended
to answer two different questions:

1. **What does Karst itself enforce or provide evidence for?**
2. **How does a deployment choice change the strength, scope, or assessor
   interpretation of that control?**

The current NIST control catalog is **SP 800-53 Rev. 5, Release 5.2.0**. NIST
published Release 5.2.0 on 2025-08-27. The authoritative publication and OSCAL
catalog are maintained by NIST:

- [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
- [NIST SP 800-53 OSCAL content](https://github.com/usnistgov/oscal-content/tree/main/nist.gov/SP800-53/rev5)
- [NIST SP 800-53B baselines](https://csrc.nist.gov/pubs/sp/800/53/b/upd1/final)

This is an **implementation mapping, not a certification claim**. Many
800-53 controls are organizational, procedural, physical, personnel, or
application-level controls outside Karst's system boundary. Even for controls
listed below, the organization remains responsible for selecting parameters,
operating the surrounding identity and endpoint infrastructure, retaining
records, assessing effectiveness, and documenting residual risk.

Karst is also currently pre-alpha. The security whitepaper explicitly states
that Karst has no FIPS 140-3 validated cryptographic boundary and has not yet
had an external cryptographic review or penetration test. See
[SECURITY-WHITEPAPER.md §§4-5](SECURITY-WHITEPAPER.md#4-accepted-risks-and-non-goals).

## Interpretation used in this mapping

| Mapping state | Meaning |
| --- | --- |
| **Direct** | Karst provides a technical enforcement or evidence mechanism that directly implements a material part of the control. |
| **Shared** | Karst provides part of the mechanism, but the organization or another system must complete the control. |
| **Configuration-dependent** | Karst can strongly or weakly support the control depending on deployment choices described below. |
| **Gap / external** | The scenario may be achievable only with another product, host control, or organizational process; Karst must not be credited for that external function. |

Individual control and enhancement mappings, including the Low, Moderate, and
High baseline-selection matrix, are maintained in
[NIST-SP-800-53-INDIVIDUAL-CONTROLS.md](NIST-SP-800-53-INDIVIDUAL-CONTROLS.md).

## Configuration choices that change control coverage

These choices recur across the controls below.

### 1. Narrow subnet route vs broad subnet route vs exit node

A subnet router can advertise a single host (`/32` or `/128`) or a narrow
service subnet, while an exit node advertises `0.0.0.0/0` and/or `::/0` and
therefore becomes the path for general Internet egress. Karst still applies
access policy in either case, but the security boundary is very different.
See [UC-07](USE-CASE-ANALYSIS.md#uc-07--configure-a-subnet-router-or-exit-node)
and [subnet routers and exit nodes](subnet-routers-and-exit-nodes.md).

For least privilege and information-flow enforcement, a narrow route plus a
port-scoped ACL is normally stronger than advertising an entire LAN. An exit
node is appropriate when the requirement is to place Internet traffic behind
a managed egress point, but it increases the gateway's trust and monitoring
requirements because the gateway can observe destination metadata and any
unencrypted payload that leaves the overlay.

### 2. Direct peer path vs Ponor relay

PHREATIC provides end-to-end encryption on either path. A relay carries
ciphertext only, so using a relay does **not** weaken payload confidentiality
or peer authentication. It does increase the metadata visible to the relay
operator: peer identifiers, timing, and traffic volume. Direct paths minimize
that third-party metadata exposure. See [UC-08](USE-CASE-ANALYSIS.md#uc-08--establish-and-maintain-peer-connectivity),
[SECURITY-WHITEPAPER.md §1](SECURITY-WHITEPAPER.md#1-protection-goals), and
[THREAT-MODEL.md §7](THREAT-MODEL.md#7-accepted-risks-and-non-goals).

### 3. Kernel-TUN mode vs userspace mode

KarstDNS host integration applies only where the platform networking path can
install and restore host DNS settings. The customer scenarios explicitly call
out that the filtering-DNS recipe requires kernel-TUN mode; userspace mode
must not claim host DNS integration it does not provide. See
[UC-01](USE-CASE-ANALYSIS.md#uc-01--install-and-start-a-client),
[UC-06](USE-CASE-ANALYSIS.md#uc-06--configure-dns-and-private-service-discovery),
and [SC-06](CUSTOMER-SCENARIOS.md#sc-06--parent-implementing-web-filtering-with-time-of-day-rules).

### 4. Bedrock `off`, `advisory`, or `enforcing`

Bedrock changes the trust model for network membership. In `off` mode,
membership authorization relies on the online control plane. `advisory` adds
signed state and detection value but does not reject an uncovered peer.
`enforcing` causes clients to reject peers that are not covered by the signed
Bedrock chain, even if the online control server is compromised. See
[UC-09](USE-CASE-ANALYSIS.md#uc-09--govern-bedrock-network-membership).

Where the control objective is separation of duties or resistance to a
compromised administrator/control service, `enforcing` is the materially
stronger configuration. Bedrock does not replace normal access policy or
human identity authorization.

### 5. Local audit only vs external audit/SIEM sink

Karst provides an append-only, hash-chained administrative audit log and can
export or forward records to an approved sink. The hash chain provides
tamper evidence, but exporting to independently administered storage or a SIEM
improves separation, retention, and resilience against a compromised control
host. See [UC-10](USE-CASE-ANALYSIS.md#uc-10--monitor-investigate-and-prove-administrative-activity).

### 6. Masquerade vs routed return path on a subnet router

With `masquerade = true`, downstream systems see the gateway as the source.
With `masquerade = false`, downstream systems retain the client's overlay
source address, but the destination network must route the overlay range back
through the gateway. See [subnet routers and exit nodes §2](subnet-routers-and-exit-nodes.md#2-forwarding-and-nat-behavior).

This does not change PHREATIC confidentiality. It can, however, change the
quality of downstream attribution and audit evidence: non-masqueraded routing
preserves the originating overlay address for systems that log network source
addresses.

---

## Access Control (AC)

### AC-2 — Account Management

**Mapping:** Shared; Direct for Karst account/device lifecycle mechanisms.

Karst control integrates with an IdP and, where configured, SCIM; maps people
to account roles and groups; supports blocking and deprovisioning; and treats
node lifecycle separately from human account lifecycle. Administrative changes
are auditable. See [UC-03](USE-CASE-ANALYSIS.md#uc-03--add-invite-and-deprovision-a-user),
[UC-04](USE-CASE-ANALYSIS.md#uc-04--enroll-and-manage-a-device), and the
[actor/identity model](USE-CASE-ANALYSIS.md#actors-and-identities).

**Configuration impact:** IdP/SCIM-backed lifecycle is preferable for managed
organizations because disablement and group changes originate in the
organization's authoritative identity system. Local setup keys are enrollment
credentials, not substitutes for ongoing human account governance. Device
revocation must be used in addition to user deprovisioning when the device
itself must immediately lose membership.

**Scenario relevance:** SC-09; also all managed-user scenarios because policy
is evaluated against user/group and node identity.

### AC-3 — Access Enforcement

**Mapping:** Direct; Configuration-dependent scope.

Karst implements explicit default-deny access policy. Administrators grant
named flows between sources and destinations, optionally restricted by ports;
control compiles/distributes the result and clients enforce it with a stateful
packet filter. See [UC-05](USE-CASE-ANALYSIS.md#uc-05--grant-and-validate-connectivity-permissions).

The subnet-router forwarding rules add another enforcement point: forwarded
traffic is accepted only from the Karst tunnel, from the overlay source range,
to the advertised prefix; anything else arriving on the tunnel and reaching
the forwarding chain is dropped. See
[subnet routers and exit nodes §2](subnet-routers-and-exit-nodes.md#2-forwarding-and-nat-behavior).

**Configuration impact:** A rule such as one reviewer to `tag:devbox:3000`,
or one traveler to a printer `/32` on TCP/631, provides substantially tighter
enforcement than granting a group access to an entire subnet. Exit-node use
should be paired with ACLs limiting who may use that gateway; route
distribution alone should not be treated as the authorization decision.

**Scenario relevance:** SC-03, SC-04, SC-07, SC-09.

### AC-4 — Information Flow Enforcement

**Mapping:** Direct; strongly Configuration-dependent.

Karst constrains network information flows through the combination of peer
identity, route distribution, destination ownership, stateful ACLs, and subnet
router forwarding rules. The control plane distributes only the peers, policy,
DNS, routes, and relays needed by a node. See the
[identity lifecycle](USE-CASE-ANALYSIS.md#identity-lifecycle-and-trust-anchors),
[UC-05](USE-CASE-ANALYSIS.md#uc-05--grant-and-validate-connectivity-permissions),
and [UC-07](USE-CASE-ANALYSIS.md#uc-07--configure-a-subnet-router-or-exit-node).

**Configuration impact:**

- A printer `/32` plus TCP/631 ACL is a high-specificity flow rule.
- A file-server route plus SMB/NFS port ACL permits only that service path;
  application authorization still belongs to the file server.
- Advertising a whole LAN creates a broader information-flow path and should
  be used only where that scope is required.
- An exit node intentionally creates the broadest route. It is the right
  design when policy requires managed Internet egress, but it should not be
  selected merely for convenience when a narrow subnet route meets the need.

**Scenario relevance:** SC-02, SC-03, SC-04, SC-07, SC-09.

### AC-5 — Separation of Duties

**Mapping:** Direct for Karst's security-role separation; Shared overall.

Karst distinguishes client user, administrator, auditor, relay operator,
Bedrock authority operator, control service, and node identities. The auditor
is read/verify/export only; the Bedrock authority holds offline signing power
but does not administer online policy; the relay operator forwards encrypted
traffic but has no policy authority or plaintext access. See
[Actors and identities](USE-CASE-ANALYSIS.md#actors-and-identities), the
[authorization model](USE-CASE-ANALYSIS.md#authorization-model-summary), and
[UC-09](USE-CASE-ANALYSIS.md#uc-09--govern-bedrock-network-membership).

**Configuration impact:** Bedrock `enforcing` is the strongest deployment when
an independently held authorization step is required for membership changes.
`off` collapses that membership decision back into the online control plane.
Using a distinct auditor identity and an independently administered audit sink
also avoids treating an administrator's own view of their actions as the sole
evidence source.

**Scenario relevance:** SC-09 and any high-assurance managed deployment.

### AC-6 — Least Privilege

**Mapping:** Direct for network reachability; Shared for host/application
privilege.

Karst's default-deny policy, group/tag scoping, port restrictions, and narrow
route advertisements let administrators grant only the network access needed
for a task. See [UC-05](USE-CASE-ANALYSIS.md#uc-05--grant-and-validate-connectivity-permissions).
The customer scenarios provide concrete least-privilege examples: printer
`/32` + TCP/631 in [SC-03](CUSTOMER-SCENARIOS.md#sc-03--traveler-printing-a-signed-form-on-a-home-printer),
SMB access limited to a family group in
[SC-04](CUSTOMER-SCENARIOS.md#sc-04--traveler-reaching-a-restricted-file-share),
and reviewer-only TCP/3000 in
[SC-07](CUSTOMER-SCENARIOS.md#sc-07--coworker-asking-another-coworker-to-review-a-dev-server).

**Configuration impact:** Prefer the smallest route and smallest ACL that meet
the use case. A whole-LAN subnet route or default route should be treated as a
deliberate privilege expansion. Karst does not replace the destination
application's own authorization; SMB credentials, database roles, and similar
controls remain additive.

### AC-17 — Remote Access

**Mapping:** Direct for the protected remote-access transport; Shared for the
organization's approval and endpoint-management portions of the control.

Karst is explicitly a remote-access/mesh transport: enrolled endpoints reach
private peers or private subnets through authenticated PHREATIC sessions,
using an authenticated relay when direct NAT traversal is unavailable. See
[UC-08](USE-CASE-ANALYSIS.md#uc-08--establish-and-maintain-peer-connectivity),
[SC-01](CUSTOMER-SCENARIOS.md#sc-01--telecommuter-on-untrusted-coffee-shop-wi-fi),
and [SC-09](CUSTOMER-SCENARIOS.md#sc-09--it-replacing-openvpn-or-aws-vpn-with-karst).

**Configuration impact:**

- Ordinary mesh mode protects only traffic sent through the overlay.
- A subnet router extends protected remote access to a selected private CIDR.
- A consented exit node extends the route to general Internet traffic and can
  support a managed-egress or anti-split-tunnel architecture, but Karst's
  control plane intentionally cannot silently force `/0` activation on a
  client. See [subnet routers and exit nodes §3](subnet-routers-and-exit-nodes.md#3-exit-node-privacy).
- On a centrally managed endpoint, the local OS operator can establish durable
  exit-node selection; on a self-administered endpoint, Karst alone cannot
  prevent the local administrator from reconfiguring the host. This boundary
  is explicit in [SC-05](CUSTOMER-SCENARIOS.md#sc-05--parent-monitoring-a-childs-website-activity).

An organization that requires mandatory full-tunnel remote access must combine
Karst with endpoint-management controls that prevent unauthorized local
network/VPN reconfiguration.

---

## Audit and Accountability (AU)

### AU-2 — Event Logging

**Mapping:** Direct for Karst administrative/security events; Shared overall.

Karst records administrative control-plane activity including policy changes,
enrollments, blocks, group/role changes, deprovisioning, relay changes, and
remediation actions. The audit log is explicitly distinct from user browsing
history. See [UC-03](USE-CASE-ANALYSIS.md#uc-03--add-invite-and-deprovision-a-user),
[UC-05](USE-CASE-ANALYSIS.md#uc-05--grant-and-validate-connectivity-permissions),
and [UC-10](USE-CASE-ANALYSIS.md#uc-10--monitor-investigate-and-prove-administrative-activity).

**Configuration impact:** Exporting events to an approved sink broadens the
available evidence and allows organization-defined correlation/retention.
Karst does not inspect or log all application traffic and should not be
credited as a general-purpose network content logging system.

### AU-3 — Content of Audit Records

**Mapping:** Direct for Karst's administrative audit domain.

The audit use case is designed to answer who changed what and to provide an
ordered history that can be filtered by actor and action, verified, and tied
to remediation activity. See [UC-10](USE-CASE-ANALYSIS.md#uc-10--monitor-investigate-and-prove-administrative-activity).

**Configuration impact:** Downstream systems behind a masquerading subnet
router will generally see the gateway source rather than the original overlay
source. If downstream network-source attribution is an audit requirement,
`masquerade = false` preserves the client's overlay address, provided the
return route is correctly configured. See
[subnet routers and exit nodes §2](subnet-routers-and-exit-nodes.md#2-forwarding-and-nat-behavior).

### AU-6 — Audit Record Review, Analysis, and Reporting

**Mapping:** Direct for review/export capabilities; Shared for organizational
review procedures and response thresholds.

Karst provides an auditor role, filtering, chain verification, export, optional
SIEM/audit-sink forwarding, policy history, Bedrock verification, posture,
relay-admission freshness, and path observations. See
[UC-10](USE-CASE-ANALYSIS.md#uc-10--monitor-investigate-and-prove-administrative-activity).

**Configuration impact:** External SIEM integration is the preferred deployment
when cross-system correlation, alerting, independent retention, or separation
from the Karst administrator is required.

### AU-9 — Protection of Audit Information

**Mapping:** Direct for tamper evidence and role separation; Shared for
independent retention/immutability.

Karst's audit history is append-only and hash-chained, and audit access can be
assigned to a read/verify/export auditor rather than an administrator. Bedrock
can also anchor its independently hash-chained membership state to the
administrative audit log. See [UC-10](USE-CASE-ANALYSIS.md#uc-10--monitor-investigate-and-prove-administrative-activity)
and [SECURITY-WHITEPAPER.md §2](SECURITY-WHITEPAPER.md#2-cryptographic-design).

**Configuration impact:** A local hash chain makes deletion or modification
detectable when an expected chain/head is known, but it is not a substitute
for independently protected retention. Forwarding records to a separately
administered sink materially strengthens this control.

### AU-12 — Audit Record Generation

**Mapping:** Direct for Karst's defined administrative events.

Karst's use cases require lifecycle, policy, Bedrock, relay, and remediation
changes to appear in the audit trail. See [UC-03](USE-CASE-ANALYSIS.md#uc-03--add-invite-and-deprovision-a-user),
[UC-05](USE-CASE-ANALYSIS.md#uc-05--grant-and-validate-connectivity-permissions),
[UC-09](USE-CASE-ANALYSIS.md#uc-09--govern-bedrock-network-membership), and
[UC-10](USE-CASE-ANALYSIS.md#uc-10--monitor-investigate-and-prove-administrative-activity).

**Configuration impact:** This mapping is limited to events Karst owns. Host,
application, DNS-filtering, and downstream-resource events must be generated by
those systems.

---

## Assessment, Authorization, and Monitoring (CA)

### CA-7 — Continuous Monitoring

**Mapping:** Direct for Karst security/health telemetry; Shared for the
organization's monitoring program.

Karst exposes control-plane Prometheus metrics, optional OTel traces, node
metrics, route/gateway state, relay/TURN reachability, Bedrock state, PSK epoch
age, ACL denials, MAC/decrypt failures, and Bedrock equivocation indicators.
See [observability.md](observability.md) and
[UC-10](USE-CASE-ANALYSIS.md#uc-10--monitor-investigate-and-prove-administrative-activity).

**Configuration impact:**

- `karst metrics` is available through the root-owned local control socket.
- The optional HTTP metrics listener is deliberately limited to loopback and
  refuses non-loopback configuration, reducing monitoring-surface exposure.
- External Prometheus/OTel/SIEM infrastructure is required for durable
  centralized monitoring and alerting.
- SC-08's geographic/capacity analysis depends on external GeoIP correlation;
  Karst supplies path/relay telemetry but does not itself derive geography.

**Scenario relevance:** SC-08 and managed deployments generally.

---

## Configuration Management (CM)

### CM-3 — Configuration Change Control

**Mapping:** Direct for Karst policy/configuration change mechanisms; Shared
for the organization's approval process.

Karst versions access policy; saving requires the version that was read,
preventing silent last-write-wins replacement; policy changes and rollbacks
are audited. Route, DNS, relay, group, and Bedrock changes are intended to have
reviewable and reversible paths. See [UC-05](USE-CASE-ANALYSIS.md#uc-05--grant-and-validate-connectivity-permissions)
and [operational acceptance criteria](USE-CASE-ANALYSIS.md#operational-acceptance-criteria).

**Configuration impact:** Bedrock `enforcing` adds an independent offline
approval boundary for membership changes; it does not add that approval step
to ordinary ACL/policy changes.

### CM-5 — Access Restrictions for Change

**Mapping:** Direct for Karst administrative authorization; Shared for host and
infrastructure administration.

Karst separates ordinary users from administrators and auditors. Only the
administrator role manages users, groups, policy, DNS, routes, relays, and
settings; Bedrock signing keys are outside the online console entirely. See
[authorization model summary](USE-CASE-ANALYSIS.md#authorization-model-summary).

**Configuration impact:** Using separate service identities and narrowly
scoped automation tokens is preferred over shared human administrator
credentials. Bedrock `enforcing` further prevents the online administrator or
a compromised control service from unilaterally introducing an uncovered
member.

---

## Identification and Authentication (IA)

### IA-2 — Identification and Authentication (Organizational Users)

**Mapping:** Shared; Karst relies on the organization's IdP for human
authentication and applies roles/groups after authentication.

Karst's documented identity model places human authentication at the IdP,
then maps the authenticated subject to an account, role, and groups. See
[Identity lifecycle and trust anchors](USE-CASE-ANALYSIS.md#identity-lifecycle-and-trust-anchors).

**Configuration impact:** IdP-backed authentication should be used for managed
organizational users. Karst does not replace IdP MFA, credential lifecycle,
conditional access, or other organization-defined user-authentication
requirements.

### IA-3 — Device Identification and Authentication

**Mapping:** Direct; strengthened by Bedrock `enforcing`.

Each node has a locally generated ML-DSA-87 identity and static ML-KEM-1024
key. Control records the node under an opaque handle; presenting a different
identity key for a known handle is identity substitution rather than normal
re-enrollment. PHREATIC peers authenticate using these node identities. See
[Identity lifecycle and trust anchors](USE-CASE-ANALYSIS.md#identity-lifecycle-and-trust-anchors),
[UC-04](USE-CASE-ANALYSIS.md#uc-04--enroll-and-manage-a-device), and
[SECURITY-WHITEPAPER.md §2](SECURITY-WHITEPAPER.md#2-cryptographic-design).

**Configuration impact:**

- `off`: online control is the membership authority.
- `advisory`: signed Bedrock state is available for detection/review.
- `enforcing`: clients reject peers not covered by the signed Bedrock chain,
  including peers introduced by a compromised online control server.

### IA-5 — Authenticator Management

**Mapping:** Direct for Karst node/control/relay key material and enrollment
credentials; Shared for human IdP authenticators.

Karst separates short-lived/single-use enrollment credentials from long-lived
node identity, pins both control-service public keys before enrollment, seals
node identity locally, rotates PHREATIC PSK epochs, and keeps Bedrock private
keys offline/outside the console. See [UC-01](USE-CASE-ANALYSIS.md#uc-01--install-and-start-a-client),
[UC-04](USE-CASE-ANALYSIS.md#uc-04--enroll-and-manage-a-device),
[UC-09](USE-CASE-ANALYSIS.md#uc-09--govern-bedrock-network-membership), and
[observability.md §1](observability.md#1-karst-controls-prometheus-metrics).

**Configuration impact:** Administrative setup keys that can enroll multiple
nodes should be more tightly governed than short-lived single-use portal keys.
Bedrock authority keys require independent offline custody. Human password/MFA
management remains the IdP's responsibility.

---

## System and Communications Protection (SC)

### SC-5 — Denial-of-Service Protection

**Mapping:** Direct for protocol-level mitigations; Shared for infrastructure
capacity and upstream DDoS protection.

PHREATIC bounds unauthenticated reassembly, limits handshake fragmentation,
uses address-validation cookies above a load threshold, and avoids protocol
amplification by making the first handshake message larger than the response.
Ponor also performs authenticated admission and rate limiting. See
[SECURITY-WHITEPAPER.md §2](SECURITY-WHITEPAPER.md#2-cryptographic-design)
and the [system component description](USE-CASE-ANALYSIS.md#system-boundary-and-components).

**Configuration impact:** Multiple appropriately placed relays and external
network-level DDoS controls improve availability but are operational choices,
not properties of the PHREATIC cryptographic protocol itself. SC-08's relay
metrics support capacity planning; they do not prevent upstream saturation.

### SC-7 — Boundary Protection

**Mapping:** Direct for the Karst overlay/gateway boundary;
Configuration-dependent.

Clients enforce policy at the overlay endpoint. Subnet routers install a
separate `karst_routes` nftables table that accepts only authorized tunnel-to-
advertised-prefix forwarding and drops other tunnel forwarding attempts. The
metrics HTTP listener is loopback-only and rejects a non-loopback bind. See
[subnet routers and exit nodes §2](subnet-routers-and-exit-nodes.md#2-forwarding-and-nat-behavior)
and [observability.md §3.2](observability.md#32-the-opt-in-loopback-http-listener).

**Configuration impact:**

- Direct mesh access keeps the trust boundary at participating endpoints.
- A subnet router deliberately extends that boundary to a selected LAN/VPC.
- A narrow advertised prefix constrains that extension; a whole-LAN route
  broadens it.
- An exit node becomes an Internet egress boundary and therefore warrants
  stronger hardening, monitoring, and administrative control than an ordinary
  endpoint.

### SC-8 — Transmission Confidentiality and Integrity

**Mapping:** Direct for Karst overlay and control-plane records.

PHREATIC provides end-to-end authenticated encryption for peer traffic using
ML-KEM-1024, ML-DSA-87, AES-256-GCM, and SHA-384. The node-to-control protocol
uses a separate cryptographic record layer with ML-KEM-768, ML-DSA-87,
ChaCha20-Poly1305, and SHA-512, independent of the outer transport. See
[SECURITY-WHITEPAPER.md §2](SECURITY-WHITEPAPER.md#2-cryptographic-design).

**Configuration impact:** Direct and Ponor-relayed paths have the same overlay
confidentiality/integrity property; relaying changes metadata exposure, not
payload encryption. An exit node decrypts the overlay before sending traffic
onto the destination network, so Karst does not claim confidentiality beyond
the gateway for traffic that is not separately protected by TLS/SSH/etc. See
[subnet routers and exit nodes §3](subnet-routers-and-exit-nodes.md#3-exit-node-privacy).

**Scenario relevance:** SC-01, SC-02, SC-07, SC-09.

### SC-8(1) — Transmission Confidentiality and Integrity | Cryptographic Protection

**Mapping:** Direct technically; see SC-13 caveat for validation requirements.

Karst uses authenticated cryptographic record protection rather than relying
on a trusted network segment. The same evidence cited for SC-8 applies.

**Configuration impact:** No configuration may downgrade PHREATIC to plaintext;
the relay never terminates the end-to-end session. However, forwarding beyond
a subnet/exit gateway is outside the PHREATIC security boundary.

### SC-12 — Cryptographic Key Establishment and Management

**Mapping:** Direct for Karst protocol keys; Shared for organizational key
custody procedures.

Karst separates node identity keys, static KEM keys, pairwise/epoch material,
control-service keys, relay identity keys, and offline Bedrock authority keys.
Control pins are provisioned before first contact; node identity is generated
and sealed locally; Bedrock root/authority custody is explicitly separate from
online administration. See [Identity lifecycle and trust anchors](USE-CASE-ANALYSIS.md#identity-lifecycle-and-trust-anchors),
[UC-09](USE-CASE-ANALYSIS.md#uc-09--govern-bedrock-network-membership), and
[SECURITY-WHITEPAPER.md §2](SECURITY-WHITEPAPER.md#2-cryptographic-design).

**Configuration impact:** Bedrock `enforcing` plus independently protected
offline authorities provides a materially stronger key-authorization model
than relying solely on the online control server. Prometheus exposes PSK epoch
age so a stalled rotation mechanism can be detected; see
[observability.md §1](observability.md#1-karst-controls-prometheus-metrics).

### SC-13 — Cryptographic Protection

**Mapping:** Direct for use of modern cryptographic mechanisms, but **not a
standalone federal compliance claim**.

Karst's documented algorithms include NIST-standardized ML-KEM and ML-DSA plus
AES-256-GCM, ChaCha20-Poly1305, SHA-384, and SHA-512. See
[SECURITY-WHITEPAPER.md §2](SECURITY-WHITEPAPER.md#2-cryptographic-design).

**Important limitation:** the same whitepaper explicitly states that Karst has
**no FIPS 140-3 validated cryptographic boundary**. Therefore, where the
organization's SC-13 parameterization or other applicable policy requires a
FIPS-validated module, the current Karst implementation does not by itself
meet that requirement. Algorithm selection and module validation are separate
questions.

### SC-20 — Secure Name/Address Resolution Service (Authoritative Source)

**Mapping:** Direct for authenticated mesh-name data; Shared for external DNS.

KarstDNS answers mesh names from authenticated netmap state, returns
NXDOMAIN for unknown mesh names rather than leaking them to a LAN/global
resolver, and sends split-domain queries only to the designated upstream.
A failed split route returns SERVFAIL instead of falling back to a global
resolver. See [UC-06](USE-CASE-ANALYSIS.md#uc-06--configure-dns-and-private-service-discovery).

**Configuration impact:**

- Kernel-TUN/platform DNS integration is required when Karst is expected to
  control host resolution behavior.
- Userspace mode must not be credited with host DNS enforcement it does not
  provide.
- External upstream DNS is not inherently encrypted by Karst; resolver
  placement and encrypted DNS transport remain a separate decision.
- SC-06's filtering recipe uses Karst only to choose the resolver. Category
  filtering, scheduling, logging, and protection against hardcoded DoH are
  functions of the external resolver/endpoint policy, not Karst.

### SC-23 — Session Authenticity

**Mapping:** Direct.

PHREATIC authenticates peers using their node identities and transcript-bound
cryptographic material. The node-to-control protocol pins the server's static
KEM and identity keys and authenticates a signed ephemeral KEM key. A known
node handle presenting a different identity key is treated as substitution.
See [SECURITY-WHITEPAPER.md §2](SECURITY-WHITEPAPER.md#2-cryptographic-design)
and [Identity lifecycle and trust anchors](USE-CASE-ANALYSIS.md#identity-lifecycle-and-trust-anchors).

**Configuration impact:** Ponor relay use does not terminate or replace the
peer-authenticated PHREATIC session. Bedrock `enforcing` strengthens the
assurance that the authenticated peer is also an independently authorized
network member.

---

## System and Information Integrity (SI)

### SI-4 — System Monitoring

**Mapping:** Direct for Karst-specific security telemetry; Shared for the
enterprise monitoring capability.

Karst exposes counters for malformed traffic, fragment-MAC failures, decrypt
failures, source-address violations, ACL denials, relay drops, and Bedrock
equivocation, plus route/gateway state and relay reachability. Bedrock
equivocation above zero is explicitly documented as an incident indicator.
See [observability.md §3](observability.md#3-karstds-metrics-surface).

**Configuration impact:** Local metrics support host troubleshooting; a
central Prometheus/OTel/SIEM deployment is needed for organization-wide
correlation and alerting. Relay and path telemetry is last-known operational
evidence rather than proof of current state, as documented in
[UC-08](USE-CASE-ANALYSIS.md#uc-08--establish-and-maintain-peer-connectivity).

---

## Scenario-to-control view

This table is the inverse of the control descriptions above: start from a
customer scenario and identify the controls most affected by its deployment
choice.

| Scenario | Configuration choice that matters | Most relevant controls | Control effect |
| --- | --- | --- | --- |
| [SC-01 Untrusted Wi-Fi telecommuter](CUSTOMER-SCENARIOS.md#sc-01--telecommuter-on-untrusted-coffee-shop-wi-fi) | Ordinary mesh vs optional exit node; direct vs relay | AC-17, IA-3, SC-8, SC-8(1), SC-23 | Ordinary mesh protects overlay traffic only. Relay fallback preserves payload protection but exposes relay metadata. Exit-node selection broadens protected/managed routing to Internet egress. |
| [SC-02 Home-region streaming IP](CUSTOMER-SCENARIOS.md#sc-02--vacationer-streaming-with-a-home-region-ip) | Exit node + `/0` route + ACL | AC-3, AC-4, AC-6, AC-17, SC-7, SC-8 | `/0` is intentionally broad and increases gateway trust. Use ACLs to restrict who can select/use the exit. PHREATIC protection ends at the gateway for forwarded Internet traffic. |
| [SC-03 Home printer](CUSTOMER-SCENARIOS.md#sc-03--traveler-printing-a-signed-form-on-a-home-printer) | Printer `/32` vs larger LAN; TCP/631 ACL | AC-3, AC-4, AC-6, SC-7 | A `/32` plus port-scoped ACL is the preferred least-privilege form. A larger subnet is a deliberate expansion. |
| [SC-04 Restricted file share](CUSTOMER-SCENARIOS.md#sc-04--traveler-reaching-a-restricted-file-share) | Group-scoped ACL; subnet scope; masquerade choice | AC-3, AC-4, AC-6, AU-3, SC-7 | Karst restricts network reachability; SMB/NFS authorization remains separate. Non-masqueraded routing can preserve overlay source attribution in downstream logs. |
| [SC-05 Parent monitoring](CUSTOMER-SCENARIOS.md#sc-05--parent-monitoring-a-childs-website-activity) | Parent-operated exit node + host-side monitoring; managed vs self-admin endpoint | AC-17, AU-2, SC-7 | Karst does not provide browsing-history logging. Visibility comes from external gateway tooling. A local administrator can disable/reconfigure their own host, so mandatory routing requires endpoint-management controls. |
| [SC-06 DNS filtering](CUSTOMER-SCENARIOS.md#sc-06--parent-implementing-web-filtering-with-time-of-day-rules) | Kernel-TUN + group-scoped upstream; external filtering resolver | AC-4, SC-20 | Karst selects/scopes the resolver; filtering categories/schedules are external. Userspace mode and hardcoded DoH limit enforcement. |
| [SC-07 Dev-server review](CUSTOMER-SCENARIOS.md#sc-07--coworker-asking-another-coworker-to-review-a-dev-server) | One peer + one port + temporary ACL | AC-3, AC-4, AC-6, SC-8, SC-23 | This is the strongest least-privilege pattern in the scenario set: one source, one tagged target, one port, removable after use. |
| [SC-08 Relay capacity planning](CUSTOMER-SCENARIOS.md#sc-08--it-sizing-relaycoordination-infrastructure-by-client-geography) | Metrics/traces/audit sink; external GeoIP | AU-6, CA-7, SI-4, SC-5 | Karst provides path, relay, and capacity telemetry; geography is external correlation. Central monitoring strengthens continuous-monitoring evidence. |
| [SC-09 Replace OpenVPN/AWS VPN](CUSTOMER-SCENARIOS.md#sc-09--it-replacing-openvpn-or-aws-vpn-with-karst) | IdP lifecycle, groups/ACLs, subnet/exit routes, Bedrock mode | AC-2, AC-3, AC-4, AC-5, AC-6, AC-17, IA-2, IA-3, IA-5, SC-7, SC-8, SC-12, SC-13, SC-23 | Clean replacement can map legacy VPN access into identity-, group-, route-, and port-scoped policy. Bedrock enforcing adds independent membership authorization. No protocol bridge exists. |

## Controls that Karst should not be credited with by itself

The following are common places where a VPN/overlay product is over-credited.
Karst can contribute evidence or transport, but the control objective belongs
elsewhere:

- **Application authorization:** Karst can allow or deny network reachability,
  but it does not replace SMB/NFS/database/application authorization.
- **Endpoint security:** root compromise is outside Karst v1's protection
  claim; OS hardening, EDR, patching, disk encryption, and prevention of local
  VPN/DNS changes remain endpoint controls. See
  [SECURITY-WHITEPAPER.md §4](SECURITY-WHITEPAPER.md#4-accepted-risks-and-non-goals).
- **General web/DNS content filtering:** SC-06 is a composition recipe with an
  external filtering resolver, not a Karst content-security feature.
- **Mandatory full tunnel on self-administered hosts:** Karst intentionally
  requires local consent for `/0`; an organization requiring a non-bypassable
  tunnel needs endpoint-management enforcement in addition to Karst.
- **FIPS 140-3 module validation:** Karst uses standardized algorithms but
  presently has no validated cryptographic module boundary.
- **Physical, personnel, training, contingency, supply-chain, and privacy
  program controls:** these are primarily organizational/system lifecycle
  controls and are not satisfied merely by deploying Karst.

## Evidence maintenance guidance

This mapping should be kept evidence-driven as Karst changes:

1. Link each claim to a stable Karst document/spec/test describing the
   implemented behavior.
2. When a scenario changes, update both
   [CUSTOMER-SCENARIOS.md](CUSTOMER-SCENARIOS.md) and the affected control
   entries here.
3. Do not upgrade a **Shared** mapping to **Direct** because an external tool
   appears in a deployment recipe.
4. Do not claim SC-13/FIPS compliance until a validated cryptographic boundary
   actually exists and the applicable deployment uses it.
5. Treat Bedrock mode, route scope, exit-node activation, DNS mode, audit-sink
   configuration, and masquerade behavior as assessor-visible security
   configuration, not incidental implementation detail.
