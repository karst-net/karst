# Subnet routers and exit nodes

**PLAN.md Phase 6, workstream 6 · W4–W7 · Rust 1, Go 1, Frontend 1.**

This is the detailed plan behind [00-overview.md](00-overview.md) §2 item 6.
It is a re-baseline against the tree on 2026-09-03. The inherited NetBird
route model and Karst's console are farther along than the overview's short
description suggests, but no route created there reaches a Karst node today.
The work is therefore an integration and security-boundary project, not a new
route CRUD project.

## 1. Outcome and scope

An administrator can use the console to advertise an IPv4 or IPv6 subnet
through one or more enrolled gateway nodes, restrict its recipients, and gate
access with policy. A recipient installs the route and reaches the destination
through PHREATIC. A gateway forwards it with masquerading when requested. A
default route is the same data path with one additional invariant: it is never
installed without explicit consent on that client.

In scope:

- static IPv4 and IPv6 CIDR routes;
- one gateway or an HA gateway group, with deterministic metric-based choice;
- recipient distribution groups and access-control groups;
- gateway forwarding and optional masquerade on Linux;
- client selection and withdrawal of `0.0.0.0/0` and `::/0`;
- console/API presentation of readiness, consent, and effective state;
- route changes delivered through the existing netmap push path;
- end-to-end tests for routing, policy, revocation, failover, and rollback.

Out of scope:

- dynamic routing protocols (BGP, OSPF), domain routes, or route discovery;
- Windows, mobile, or FreeBSD gateway mode;
- automatic Internet-exit selection based on latency;
- load balancing across equal gateways; v1 selects one and fails over;
- managing the destination LAN's return routes;
- treating Ponor or TURN relays as exit nodes.

ACL-gated SSH is workstream 7. This work supplies the route and forwarding
foundation it depends on but does not implement the `"ssh"` policy block.

## 2. What already exists

| Layer | Present now | Gap this workstream closes |
|---|---|---|
| Management model/API | `server/route/route.go`, route handlers, persistence, groups, metrics, masquerade, `SkipAutoApply`, and inherited HA selection | Validate and expose Karst-supported combinations; make effective state observable rather than accepting rows Karst ignores |
| Console | `web/console/src/views/routes.tsx` already lists, creates, edits, disables, and deletes CIDR routes | Replace raw group-ID entry, distinguish subnet/default routes, expose policy and gateway readiness, and explain consent/effective state |
| Control netmap | Karst emits peers and host-only `allowed_ips`; policy becomes packet and egress filters | Select the effective inherited routes for this Karst recipient/gateway and project them into the authenticated Karst netmap |
| Node routing | `AllowedIps` does longest-prefix routing and inbound source ownership; `run.rs` diffs and installs off-link host routes | Preserve host ownership while adding advertised prefixes; support selected `/0` routes without capture of control, relay, TURN, or local-LAN traffic |
| Gateway | No Karst gateway lifecycle or forwarding manager | Enable forwarding/NAT transactionally, report prerequisites, and restore only state Karst changed |

The important asymmetry is in
`server/management/internals/karst/control/netmap.go`: `allowedIPsOf` correctly
returns only a peer's `/32` and `/128` identity addresses. Blindly appending
every configured route there would make the prefix both a route and a source
ownership grant for every recipient. Route projection must instead be computed
per recipient and only attach a prefix to the selected gateway peer.

## 3. Decisions to lock before implementation

### 3.1 Reuse the inherited route record

Do not add a parallel Karst route store. The existing `route.Route` remains the
source of truth for CIDR, gateway peer/group, recipient groups, access-control
groups, metric, masquerade, enabled state, and default-route auto-apply policy.
Karst adds projection and status adapters around it. Unsupported inherited
features, especially domain routes, fail validation for the Karst surface
rather than being silently ignored.

### 3.2 Default-route consent belongs to the client

An authenticated control server is allowed to distribute a default-route
offer, not to activate it. Store the accepted exit route ID in root-owned local
node state and expose it through the local `karst`/`karstd` control interface:

```text
karst exit-node list
karst exit-node use <route-id>
karst exit-node disable
```

The console shows whether a node reports an offered or active exit route, but
an administrator clicking in the console cannot manufacture local consent.
This is the necessary interpretation of the phase exit line "a client can
consent to a default route ... from the console": advertisement and policy are
console operations; activation is a deliberate client operation and its
reported result is visible in the console. Change the phase wording rather
than weaken this boundary if product requires every action literally to occur
in the browser.

Consent names the stable route ID, not a gateway peer. HA failover may select a
new gateway without asking again, while switching to a different advertised
exit route may not. Removing or disabling the route withdraws it immediately
but retains dormant consent, so re-enabling the same route is predictable;
deleting it clears consent.

### 3.3 One route projection, two independent gates

A recipient receives a route only when all of these are true:

1. the route is enabled and is a supported CIDR route;
2. the recipient is in a distribution group;
3. the recipient is allowed by the route's access-control groups and compiled
   Karst policy;
4. an eligible, connected gateway is selected;
5. for `/0`, the local client has consented to that route ID.

Distribution answers *who learns the offer*. Policy answers *who may send
traffic*. Keep both checks: treating distribution as authorization turns a UI
configuration convenience into the only security boundary.

### 3.4 Fail closed on ambiguity

- Exact duplicate prefixes from different route IDs are rejected for one
  recipient unless they are members of the same HA route definition.
- More-specific prefixes may coexist with a default route and win by longest
  prefix.
- An unavailable gateway withdraws the route unless `keep_route` explicitly
  requests blackholing during failover. It never falls through to an
  unauthorized local path.
- A gateway cannot advertise the overlay CIDRs, loopback, multicast,
  link-local, or its own underlay/control endpoint ranges.
- A node cannot be both recipient and selected gateway for the same route.
- Route and policy changes must alter `netmap_version`; stale projection is a
  security failure, not a cache optimization issue.

## 4. Wire and data model

Add an explicit route offer to `KarstNetmapResponse`; do not overload peer
`allowed_ips` as the only representation because `/0` consent, status, metric,
and masquerade otherwise disappear at the trust boundary.

Each offer contains, at minimum:

- stable route ID and normalized prefix;
- selected gateway node handle;
- metric;
- kind (`subnet` or `exit`);
- `masquerade` and `keep_route`;
- whether this node is the recipient or gateway;
- an authorization binding sufficient for the node to compile both outbound
  routing and gateway ingress filtering.

The Go projector derives offers from the inherited network-map components for
the requesting peer, rather than reimplementing group and HA semantics from
raw account rows. The selected gateway's peer entry receives the prefix in its
effective cryptokey-routing ownership only after the route passes recipient
authorization. Gateway nodes receive a corresponding forwarding grant but do
not install their own advertised prefix into the TUN.

Update together:

- `spec/karst-control-v1.md` layouts and validation rules;
- `server/shared/management/proto/karst_control.proto` and generated bindings;
- Go/Rust codecs and shared accepted/rejected vectors;
- peer and whole-netmap content hashes;
- full and delta response behavior.

Unknown route kinds, invalid prefixes, a missing gateway, or a route whose
gateway is absent from the authenticated roster fail closed. A bad single
route is reported and omitted without discarding unrelated peers and routes;
duplicate ownership that makes routing nondeterministic rejects the netmap.

## 5. Implementation sequence

### W4 — contract and server projection (Go 1)

1. Write table-driven projection tests first: IPv4/IPv6 subnet, recipient not
   distributed, ACL denied, disabled route, single gateway, HA selection,
   unavailable gateway, duplicate prefix, and paired default routes.
2. Define the route-offer protobuf/spec/vector changes and regenerate both
   languages.
3. Adapt inherited `NetworkMapComponents` output into Karst route offers and
   effective gateway ownership. Include route content in version/delta hashes.
4. Push affected netmaps on route, group, peer-health, or relevant policy
   changes using the existing update channel.
5. Tighten API validation to the supported Karst subset and add an effective
   route/status read model for the console.

### W5 — recipient and gateway data paths (Rust 1)

1. Parse route offers separately from peer identity prefixes; merge only
   authorized recipient routes into `AllowedIps`.
2. Extend `Routes::wanted` with default-route protection. Before installing a
   `/0`, add explicit host routes for the control server, active Ponor relays,
   TURN servers, peer discovery endpoints, and required local gateways so the
   tunnel cannot recursively capture its own transport. Recompute these escape
   routes when endpoints change.
3. Add durable local exit-route consent and local CLI/control operations.
   Config replacement, restart, and missed pushes must preserve the choice;
   route deletion must not leave an active `/0`.
4. Build a Linux forwarding manager for gateway offers: preflight
   `CAP_NET_ADMIN`, IPv4/IPv6 forwarding, nftables availability, and egress
   interface; install narrowly scoped forwarding and masquerade rules; record
   handles/state; remove only rules and sysctls Karst created.
5. Enforce ingress source ownership and destination policy before forwarding.
   A gateway must not become a general router merely because kernel forwarding
   is enabled.

Use nftables atomically on Linux. Do not shell out once per packet or flush an
operator's tables. If the host already enables forwarding, leave that setting
enabled on shutdown; if Karst enabled it, restore its prior value.

### W6 — console and operability (Frontend 1, Go 1)

1. Replace comma-separated group IDs with selectors backed by group and machine
   data; show names while retaining stable IDs.
2. Make "Subnet route" and "Exit route" explicit creation paths. Exit-route
   creation produces the intended IPv4 and/or IPv6 defaults and defaults to
   requiring client consent.
3. Require an access-control selection, preview recipients and eligible
   gateways, warn on missing return routes when masquerade is off, and refuse
   unsupported/domain routes.
4. Show per-route state: offered recipients, selected/standby gateway,
   forwarding readiness, active consenting clients, and last projection error.
5. Add route state to `karst status` and the diagnostics bundle without
   exposing underlay credentials or unrelated host firewall rules.

### W7 — integration, failure tests, and documentation

1. Add Linux network-namespace topologies for one subnet router, one exit node,
   dual stack, and two-gateway failover.
2. Exercise create/update/disable/delete through the real management HTTP API
   and console contract, then wait for push rather than forcing a refresh.
3. Test rollback after daemon crash, malformed netmap, nftables failure, lost
   gateway, expired authorization, and revoked recipient.
4. Document gateway host prerequisites, forwarding/NAT behavior, return-route
   mode, exit-node privacy, recovery, and commands to inspect effective state.
5. Run the exit scenario from published artifacts, not a workspace binary.

## 6. Security and correctness tests

The workstream is not complete without all of these automated assertions:

- A recipient outside the distribution group never receives the route offer.
- A distributed but policy-denied recipient cannot send through the gateway.
- The gateway drops a packet whose authenticated peer spoofs another source.
- The gateway drops a permitted source aimed outside the advertised prefix.
- A non-gateway peer cannot claim the advertised subnet in `allowed_ips`.
- `/0` is offered but not installed before local consent.
- Activating IPv4 exit routing does not implicitly activate IPv6, or vice
  versa; the UI may offer an explicit dual-stack action.
- Control, relay, TURN, and peer underlay traffic remains reachable after `/0`
  activation and does not loop into the tunnel.
- Disabling/deleting a route, removing a recipient from a group, or revoking
  policy withdraws the kernel route and gateway firewall grant on netmap push.
- Masquerade-on has a working return path; masquerade-off works only with an
  explicit simulated LAN return route.
- An HA gateway loss converges to the standby without two peers owning the
  same prefix in one effective netmap.
- Restart restores consent and effective rules; uninstall/shutdown restores
  host state Karst changed and preserves pre-existing state.
- Route mutations change `netmap_version`, and full/delta assembly produces
  identical effective configuration.

Property-test route normalization, overlap, and longest-prefix selection,
including `/0`, `/1`, adjacent prefixes, v4/v6 separation, and duplicate
claims. Add malformed and unauthorized route cases to the shared rejected
vectors.

## 7. Exit demonstration

From a deployment installed from published packages:

1. Enroll a client, two Linux gateways, and a destination host behind them.
2. In the console, create a route to the destination subnet, select the gateway
   group and recipient group, enable masquerade, and attach a policy that
   permits one client and denies another.
3. Show the permitted client reaching the destination, the denied client
   failing, and a spoofed source being dropped at the gateway.
4. Stop the selected gateway and show convergence to the standby; restore it
   without route flapping or duplicate ownership.
5. Create IPv4 and IPv6 exit-route offers. Show that neither default route is
   installed until `karst exit-node use` is run locally, then show Internet
   traffic using the gateway while control and relay connections remain live.
6. Revoke the policy and disable the routes in the console. Show route,
   forwarding, and NAT withdrawal through the pushed netmap, with the host's
   pre-existing forwarding/firewall state intact.

Evidence retained with the phase gate: console screenshots or browser-test
artifacts, API requests, `karst status`, route/nftables snapshots before and
after, packet captures showing the encrypted overlay hop, and CI timings for
withdrawal and failover.

## 8. Definition of done

- The Phase 6 exit line is demonstrably true: an admin advertises a route, a
  client consents to a default route, and an ACL gates both, with the route
  configuration and effective state visible from the console.
- No route CRUD field accepted by the Karst console is silently ignored.
- No default route is activated by server action alone.
- Gateway forwarding is least-privilege, transactional, and reversible.
- IPv4, IPv6, HA failover, policy revocation, and default-route escape paths
  pass in the namespace integration suite.
- Specs, shared vectors, user documentation, operations documentation, and
  diagnostics describe the shipped behavior.
- Any discovered high/critical security finding is fixed and re-tested before
  the public beta gate; lower findings are numbered and scheduled rather than
  buried in this plan.
