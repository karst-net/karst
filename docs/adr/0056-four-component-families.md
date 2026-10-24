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

> **Addendum, 2026-10-22 — drop standalone TURN, Relay-only transport
> fallback.** The managed-adapter decision two paragraphs above is
> superseded, not narrowed: Karst drops standalone TURN support entirely
> rather than building the coturn/external-provider adapter. The Relay
> component keeps exactly one transport mode, Ponor, and the "two protocol
> modes" framing in this section's heading no longer describes the target
> architecture.
>
> This was the simpler of the two options the original decision already
> named as open ("whether TURN is embedded or provided through a managed
> adapter to an external server") plus a third not named there at all: drop
> it. It was chosen once the Gateway inventory and Relay Services work
> (#404) made the complexity of a second, independently-authenticated
> transport mode — its own registry, credential minting, health probing,
> and deployment adapter — hard to justify against the coverage it actually
> bought: ADR-0008 §4 already treated TURN as covering networks the
> co-located relay cannot reach, not as a capability most deployments rely
> on, and the Relay service model's own pairing record (`relayservice.Service`)
> turned out not to need a TURN half at all to remain useful — it still
> carries real, non-redundant value as a Ponor-only admin enable/disable
> layer over the raw Ponor registry.
>
> Removed: the `turncred` registry/credential-minting package, the
> `turnhealth` allocation-readiness probe, `TurnID`/`TurnDisabled`/
> `TurnPresent`/`BackendKind`/`BackendOperator` from the Relay service
> association record, the `/turns` and `/turn/*` control API routes, the
> `karst-scaler-turn-k8s` driver crate, the reference Compose `coturn`
> companion service and `bootstrap.sh --turn`, and `karst_control.proto`'s
> `turn_servers` field (now `reserved`, never reused — see that file's own
> comment). Kept, deliberately: the inherited NetBird-fork `TURNConfig`
> legacy channel (`server/management/internals/shared/grpc/token_mgr.go`)
> and `karst-control`'s own `rejectLegacyTurnConfig` guard against it — that
> channel predates and is unrelated to the Karst-specific TURN support
> described in this ADR, was already fatally refused at startup before this
> addendum, and remains so; this addendum does not touch it.
>
> The "Alternatives rejected" list's "Embed TURN immediately" entry and the
> "Reconsider if" condition below about an external TURN backend are now
> moot rather than wrong — there is no TURN backend, embedded or external,
> left to reconsider. [Component architecture](../COMPONENT-ARCHITECTURE.md)
> and [Relay service associations](../relay-services.md) describe the
> resulting Ponor-only shape.
>
> **Addendum, 2026-10-23 — evaluated and reverted BYO external TURN
> (#420).** Issue #420 proposed one narrow exception to the addendum above:
> let a node *use*, without Karst *managing*, an admin-configured external
> TURN server — the control plane would distribute an operator-entered URI
> and long-term credential over the existing authenticated channel, the
> same shape as the Relay roster or DNS resolvers, minting no credentials
> and probing no health itself. PRs #424 (control-plane config/console) and
> #425 (karstd's `turns:` TLS dial path) implemented this.
>
> Reverted on the same trip, before reaching a release: `turns:` (RFC 7065)
> has no post-quantum-safe TLS suite in any real-world TURN server
> implementation, so that one hop would deliberately fall back to a
> classical (non-PQ) key exchange — unlike every other transport Karst
> uses, direct and Ponor alike, which hold a strict PQ bar. A
> harvest-now-decrypt-later break of that hop would expose the long-term
> TURN credential and the server's metadata (the relayed AVEN/PHREATIC
> payload itself stays independently PQ-encrypted end-to-end regardless,
> but credential/metadata exposure alone is enough to fail Karst's own
> bar). PR #427 reverted #424/#425 and went on to delete the client-side
> TURN datapath #418 had left as dead code, the same removal #418 and this
> addendum's own paragraph above already described — `turn_servers` field
> 16 is joined by `karst_control.proto`'s `external_turn` field 23, now
> also permanently `reserved`.
>
> This addendum's own claim that "there is no TURN backend, embedded or
> external, left to reconsider" held again as soon as #427 merged; #420's
> narrow exception did not survive long enough to need its own correction
> here beyond this note. Revisit BYO external TURN only if a real-world
> TURN server implementation ships a PQ/hybrid TLS suite.

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
