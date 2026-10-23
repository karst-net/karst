<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Gateway capability administration

A Gateway is an enrolled node that forwards traffic for authenticated route
grants. Specific prefixes provide subnet access and default prefixes provide
exit behavior. A node may serve both. A group is a set of candidate nodes, not
a separate forwarding device. ADR-0056 retains route kinds wherever consent,
DNS or underlay treatment differs.

## Unified inventory and route administration

Open **Gateways** (`#/gateways`) in the console. Existing `#/routes` links still
work. The inventory resolves existing route declarations, routing groups and
administratively visible enrolled nodes into one row per configured Gateway.
The same node can show subnet, IPv4 default and IPv6 default declarations.
Overlapping group membership does not duplicate a route on that node. Disabled
declarations remain visible. Empty/missing routing groups or unavailable peers
appear as unresolved routes; non-CIDR declarations appear separately instead
of being silently presented as supported Gateway behavior.

The inventory describes configuration, not effective per-recipient eligibility,
route selection or live forwarding. Recorded control connectivity is distinct
from forwarding readiness, which remains `unreported` here. Inspect
`karst gateway status` on the node for local grants/readiness. A connected node
may lack kernel forwarding, nftables, current policy, a usable return path, or
independent Bedrock membership. A declaration does not establish reachability.

The route editor administers subnet and default behaviors through the same
existing route records. Routing groups choose candidate nodes; distribution
groups choose offer recipients; access-control groups and packet policy govern
use. Default routes additionally require durable local client selection:

```sh
karst gateway exit list
karst gateway exit use ROUTE_ID
karst gateway exit disable
```

IPv4 and IPv6 selection remain independent. Creating/enabling a default route,
assigning a routing group, or enabling subnet access does not grant local exit
consent. The legacy `karst exit-node` commands remain supported. The inventory
and editor do not mutate client consent, membership, identity pins or node
forwarding privileges.

## API and persistence

`GET /api/karst/v1/gateways` returns schema version 1:

- `gateways`: visible nodes with stable `node_id`, name, recorded
  `control_connected`, `forwarding_readiness`, and route offers.
- Each offer retains its route ID, identifier, canonical prefix, enabled flag,
  metric and masquerade flag, and its own `forwarding_readiness`. `kind` is
  `subnet`, `default_ipv4` or `default_ipv6`; default kinds declare
  `requires_client_consent: true`.
- `forwarding_readiness` is `unreported`, `ready` or `degraded`, self-reported
  by each offer's gateway over the existing authenticated control channel
  (`KarstRouteObservation.forwarding_active`, alongside the per-route byte
  counters issues #281/#371 already added) and never inferred from
  connectivity or traffic alone: `ready` means the forward-accept rule was
  live in the gateway's own nftables table as of its last report; `degraded`
  means the gateway holds the offer but its last report said the rule was not
  live (e.g. an nftables apply failure); `unreported` means no report has
  ever been received (an older agent, or a grant never installed). A node's
  own `forwarding_readiness` aggregates its offers degraded-first.
- `unresolved_routes` and `unsupported_routes` contain declaration IDs needing
  operator attention. Hidden peer identities are not returned through group
  membership. Results are ordered by node/route ID for stable comparisons.

The endpoint uses the authenticated account/user, never an account query
parameter. It retains the Karst control read gate and independently calls the
permission-aware route, group and administrative peer readers. Missing sources
fail explicitly. Responses use `Cache-Control: no-store` and contain no node
keys or credentials. Go and TypeScript contracts are generated from
`karst-openapi.yml`.

There is no second Gateway database or new route authority. Existing route IDs,
`/api/routes` writes, group records and authenticated netmap fields remain in
use. Existing consoles and automation continue working. An older control
without inventory support shows an explicit inventory error while route
administration remains accessible. Unknown inventory schemas also fail
explicitly; they are not interpreted as an empty configuration. Rolling back
the console does not require a database conversion.

## Existing shared runtime and remaining work

| Concern | Shared implementation and protocol boundary |
|---|---|
| Configuration/persistence | Inherited account route/group records store both specific and default prefixes. Local durable exit consent remains distinct. |
| Advertisement/distribution | `control/routes.go` projects both into authenticated `KarstRouteOffer` fields with role, kind, metric and masquerade. Distribution and access checks retain their existing authority. |
| Validation/selection | `route_offer.rs` validates prefix/kind/gateway roles. `config.rs` and `routing.rs` select candidate ownership; default selection is constrained by local consent. |
| Forwarding/NAT | `gateway.rs` builds one owned nftables ruleset for both kinds, most-specific destination first, preserving operator tables and per-route attribution. Masquerade or explicit return routing remains necessary. |
| Default-route handling | `exit_node.rs` preserves durable local selection; `exit_policy.rs` manages default policy/escape routes. DNS and dual-stack treatment are not collapsed into subnet defaults. |
| Policy/trust | Agents retain packet enforcement and Bedrock verification. Control distribution does not confer membership signing authority or default-route consent. |
| Readiness/failover | Local status reports Gateway readiness; connected candidate filtering and client selection preserve route failover. The inventory's `forwarding_readiness` now self-reports that same local signal over the authenticated control channel (issue #404) — it does not invent one independently. |

The combined namespace test in `aquifer.rs` verifies subnet traffic before exit
consent, default traffic only after consent, and retained subnet reachability
after consent removal on the same Gateway. The
[container runner](../deploy/lab/aquifer/README.md) also executes existing subnet,
failover, crash recovery and independent-family selection scenarios.

Issue #404 still tracks full configuration/deployment migration, richer local
capability configuration, production and mixed-version checks, IPv6/DNS
forwarding and other platform verification. This inventory, the shared
editor, and the `forwarding_readiness` self-report above do not establish
completion of those items.
