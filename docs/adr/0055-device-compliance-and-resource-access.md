<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-0055: Device compliance and resource access

- **Status:** Proposed — design for #363; no compliance enforcement shipped
- **Date:** 2026-10-19
- **Deciders:** TBD
- **Related:** [#363](https://github.com/karst-net/karst/issues/363),
  [ADR-0032](0032-hierarchical-mesh-domains-and-admin-assigned-names.md),
  [ADR-0031](0031-managed-device-mode-reconsiders-adr-0024.md),
  [implementation contract](../../spec/device-compliance-v1.md)

## Context

Two devices belonging to the same user need different access when only one
meets organizational requirements. Domain placement expresses naming and
administration; it must not become a quarantine mechanism. Identity grants
still determine the maximum access a device can receive.

The repository has two existing meanings of posture, neither of which provides
this contract for Karst traffic:

| Component | Existing behavior | Reuse and gap |
| --- | --- | --- |
| `server/management/server/posture/checks.go` | Version, OS, location, network-range and process checks over peer metadata | Reuse validation ideas; these inputs are not verified device attestations. |
| `server/management/server/types/account.go`, `validatePostureChecksOnPeer` | Inherited policies filter sources through `SourcePostureChecks`; missing referenced check objects are skipped | Preserve legacy behavior separately; new mandatory references must fail closed. |
| `server/management/internals/karst/policy/policy.go` | Accept-only union of grants, separate SSH gate and routed CIDR egress | No compliance inputs or resource guardrails today. A condition on one accept rule can be bypassed by another accept rule. |
| `server/management/internals/karst/control/netmap.go`, `compileFilter` | Compiles Karst policy from peer identity and addresses | Does not invoke inherited posture evaluation. |
| `bins/karstd/src/control.rs`, `login` | Sends hostname and OS/platform inventory metadata | No fresh compliance evidence protocol; OS version and client version are not populated there. |
| `web/console/src/posture.ts` | Displays cryptographic session suite observations | Keep separate from organizational device compliance. |
| `bins/karstd/src/engine.rs`, `reconfigure` | Clears reply-flow permissions; preserves established SSH admissions intentionally | Compliance needs a separate mandatory gate that also applies mid-session. |

These observations describe the merged code at the start of #363, not a claim
that inherited Go clients lack their own collectors. #162's proposed macOS
managed-mode detection controls application lifecycle; it does not prove MDM
compliance or organizational ownership.

## Decision

Introduce tenant-scoped requirement sets and destination resource guardrails.
Every matching guardrail is mandatory, independent of which accept rule grants
access. Resource matches include destination node selectors, ports and routed
CIDRs. Overlaps combine requirements with AND. SSH remains an independent
identity admission gate; a mandatory compliance denial overrides a cached SSH
admission without changing ordinary SSH policy-edit semantics.

The access decision is:

`identity grant AND all matching resource requirements AND SSH admission where applicable`

Compliance cannot grant access, change domain membership, or grant administrative
authority. Remediation resources require explicit identity grants and must lie
outside protected resource matches. Policy preview must explain wildcard and
CIDR overlaps; the server rejects configurations that designate remediation
traffic also protected by a mandatory guardrail.

Evidence is bound to an authenticated device and tenant, has explicit provenance
and freshness, and is evaluated by the server. An authenticated device assertion
is not hardware attestation. The first implementation targets self-reported
minimum Karst client version and minimum OS release on Linux, macOS and Windows.
Each platform must have a tested collector and version comparator before it is
advertised as supported. Disk encryption, screen lock, managed status, and
endpoint security remain unsupported until separately implemented. Verified
MDM/EDR evidence requires a tenant-configured provider and explicit device
binding; accepting a client-supplied managed boolean is insufficient.

Use short-lived, resource-scoped permissions enforced at the packet path, with
expiry checked locally even without control connectivity. The proposed constants
and protocol requirements are in the implementation contract. Do not expose
compliance guardrails as usable until reporting, compilation, local expiry,
capability negotiation, and session revocation all work together.

### Alternatives rejected

- Domain moves for quarantine: change naming and administrative scope and cannot
  express per-resource requirements.
- Only add conditions to accept rules: union composition permits bypass through
  an overlapping unconditional grant.
- Treat inherited posture APIs or the session posture dashboard as enforcement:
  neither is connected to Karst's compliance decision path.
- Trust an overall client `compliant` flag: loses provenance, freshness and the
  ability to evaluate organization-specific requirements.
- Revoke only on the next successful sync or SSH connection: disconnected clients
  and established sessions can retain protected access indefinitely.
- Claim MDM presence proves verified compliance: management mode and trusted
  organizational evidence require different bindings and validation.

## Consequences

### Positive

Devices can retain explicitly granted remediation access while protected traffic
fails closed. Same-user devices are evaluated independently. Requirement and
identity explanations remain distinguishable and auditable.

### Negative

Mandatory expiry adds packet-path state and protocol compatibility work. Control
outages remove protected access after the lease expires. Self-reported checks
cannot defend against a device owner who modifies the client; organizations
requiring that threat resistance need verified external evidence. Hostile
resources can ignore their own enforcement, so routed gateway enforcement and
honest receiving endpoints remain part of the trust boundary.

### Reconsider if

A resource cannot enforce expiry at its receiving endpoint or gateway, or a
platform cannot provide safe elapsed-time handling across suspend and restart.
Such a platform must remain unsupported for protected access until resolved.
