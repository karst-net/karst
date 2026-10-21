<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-0056: Four component families with unified Gateway and Relay capabilities

- **Status:** Accepted architecture; implementation consolidation pending #404
- **Date:** 2026-10-20
- **Deciders:** Project owner (issues #403 and #404)
- **Related:** [#403](https://github.com/karst-net/karst/issues/403), [#404](https://github.com/karst-net/karst/issues/404), ADR-0008, ADR-0010, ADR-0014, ADR-0016
- **Supersedes in part:** ADR-0008's separate Relay/TURN component model and ADR-0010's identification of Ponor as both protocol and service. Their other decisions remain in force.

## Context

The component inventory mixes binaries, platform variants, protocols, trust
mechanisms, and deployment roles. Subnet gateways and exit nodes already share
route offers and forwarding machinery, but appear as separate product roles.
Ponor and TURN both carry PHREATIC ciphertext, but have separate configuration
and operational paths. Neither consolidation should change who can decrypt
traffic, authorize a node, enable forwarding, or consent to default-route use.

## Decision

Use exactly four conceptual component families:

| Family | Contents and authority |
|---|---|
| Node agent | Client daemon, CLI/platform UI, PHREATIC sessions, AVEN path selection, local filtering, KarstDNS, and optional Gateway capability |
| Transport infrastructure | One Relay component with Ponor and TURN modes, presence/bootstrap, reflector assistance, and encrypted transit |
| Control services | Coordination server, console/portal, enrollment, policy/configuration distribution, routes/DNS, transport discovery/credentials, and audit |
| Trust tooling | Bedrock signing ceremonies, authority and membership state, verification contracts, and scoped audit anchoring |

A family is neither a binary count nor a host count. Libraries and protocols
serve these families; verification code remains in consumers. External IdPs,
DNS upstreams, SIEMs, and TURN providers are integrations, not extra families.

### One Gateway capability

Gateway is an optional capability of an enrolled node agent. Specific prefixes
provide subnet access; default prefixes provide exit behavior. One node may
serve both. Share route administration, candidate selection, forwarding,
filtering, NAT/return routing, readiness, and diagnostics. Keep route kinds
where their semantics differ: default routes require durable, local consent,
underlay escape routes, and deliberate DNS treatment. Route distribution alone
must never activate an exit. Policy still governs destination access.

### One Relay component, two protocol modes

Relay is the operator-facing component. Ponor remains the Karst protocol for
persistent presence/bootstrap and forwarding; TURN remains the standard
allocation-based transport. They share service configuration, discovery,
health/lifecycle presentation, and accounting without pretending to share wire
formats, identities, authentication, or allocation state.

**Use a managed adapter to coturn or an external TURN provider, rather than
embedding a TURN server in `karst-relay`.** The Relay service model owns the
association, published endpoints, mode enablement, readiness, and lifecycle
status. For self-hosted coturn, deployment tooling manages the companion
process/configuration; for an external provider, the adapter manages the
integration and health, not the provider's process. Control continues minting
short-lived credentials for shared-secret TURN deployments; provider-specific
credentials must have equivalent bounded lifetimes. Never ship a TURN shared
secret to clients. Ponor's signed roster is not a TURN authentication scheme.

Keep external TURN compatibility and the optional TURN mode. Preserve Ponor
presence when TURN carries fallback traffic. Direct paths remain preferred.
One healthy mode must not hide the other mode's outage or admission failure.
Maintain per-mode quotas, bandwidth limits, credential renewal, metadata
disclosure, and failover diagnostics under the shared Relay view.

### Ownership and trust

Control defines and distributes policy; agents enforce packets and routes.
Bedrock independently authorizes identities; enforcing clients verify it.
An online anchor key can anchor audit history, not sign membership changes.
Relay forwards ciphertext. Gateway terminates an overlay session and forwards
inner packets; application encryption may still protect their payloads.
Co-location does not combine keys, privileges, or security claims.

### Delivery and compatibility

[Component architecture](../COMPONENT-ARCHITECTURE.md) records current interfaces,
source evidence, the migration contract, and the documentation inventory.
This ADR changes documentation and the target architecture only. #404 delivers
the unified runtime/configuration/API/UI model. Existing CLI commands, route
kinds, registries, wire fields, ports, deployment profiles, and identity pins
remain valid until that migration is implemented and documented. No protocol
or cryptographic change is authorized merely by renaming a component.

### Alternatives rejected

- **Seven peer components:** duplicates the client/gateway and Relay/TURN
  machinery and obscures the distinction between a capability and a service.
- **One forwarding service for Relay and Gateway:** collapses ciphertext transit
  and tunnel termination across different privileges and exposure.
- **Embed TURN immediately:** duplicates an established server ecosystem and
  broadens the Relay's attack/maintenance surface without needing new wire behavior.
- **Rename everything at once:** breaks automation, caches, and installed clients
  before a versioned migration exists.
- **Four compulsory processes:** families describe responsibilities, not packaging;
  Bedrock verification and client DNS must remain where enforcement occurs.

## Consequences

### Positive

- One Gateway model covers subnet and exit behavior without duplicating routing.
- One Relay view covers both transports while retaining standard TURN providers.
- Four families make ownership and deployment choices easier to explain.
- Independent trust and local enforcement boundaries remain explicit.

### Negative

- The adapter must correlate service health and accounting across processes and
  external providers; unified terminology alone does not deliver that behavior.
- Migration spans persistence, APIs/netmaps, clients, UI, deployment, and metrics.
- Route kinds and transport modes still require different handling and tests.
- Old command and field names must coexist with new presentation during rollout.

### Reconsider if

An external TURN backend cannot provide required admission, quota, credential,
or operational controls, or gateway modes acquire incompatible trust boundaries.
