<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Gateway operations: subnet access and exit egress

<a id="subnet-routers-and-exit-nodes"></a>

Gateway is one optional node-agent capability, with specific-prefix (subnet)
and default-route (exit) behaviors. A node can provide both. See
[ADR-0056](adr/0056-four-component-families.md) and
[component architecture](COMPONENT-ARCHITECTURE.md) for the four-family model.
The legacy document path, route kinds, status fields and `karst exit-node`
commands remain valid. Unified configuration/API/UI work is pending #404;
this reference describes the current implementation.

Operations reference for the feature `plans/phase-6/06-subnet-routers-and-exit-nodes.md`
implements: advertising an IPv4 or IPv6 subnet through one or more gateway
nodes, and offering `0.0.0.0/0`/`::/0` as a client-consented default route.
For how it fits together end to end, see that plan; this document is what an
operator needs once it is running — what a gateway host needs, what actually
crosses the wire, how to recover it, and how to see its effective state.

## Route ownership, DNS and platform scope

Control approves/distributes route offers to authorized recipients; local
agents enforce policy and select the effective Gateway. Default-route offers
need durable local consent. A Gateway must not install its own advertised
prefix back through its tunnel; recipients must preserve more-specific routes
and control/peer/Relay escape paths. Do not reuse a consented route ID for a
different destination or trust context during migration.

Choosing an exit route alone does not select a private DNS resolver or promise
that DNS takes the exit. Review KarstDNS mesh/split/global upstream settings,
the upstream's reachability, and both address families. Mesh queries must retain
their local handling; failed split DNS must not leak to a global resolver.

The forwarding prerequisites below are for Linux. macOS recipient consent is
described in §3. Supported client platforms and userspace networking do not
imply support for hosting a forwarding Gateway; #404 must validate and publish
the hosting/recipient platform matrix. Existing recovery timing is in §4.

## 1. Gateway host prerequisites

A node advertised as a route's gateway needs, on Linux:

- **`CAP_NET_ADMIN`** — the same capability `karstd` already needs to manage
  its own TUN device and cryptokey routes. Nothing additional to grant if the
  node is already running as a subnet recipient or an ordinary peer.
- **`nft` on `PATH`** — `karstd` shells out to it (`gateway.rs`), atomically,
  once per reconciliation (`nft -f -`, one transaction: a flushed table plus
  every current grant), never once per packet. It probes `nft --version`
  before touching anything else, so a missing binary is reported as a
  readiness error rather than a partial, silently-broken forwarding state.
- **IPv4 and/or IPv6 forwarding** — `karstd` enables
  `/proc/sys/net/ipv{4,6}/.../forwarding` itself if a route needs the family
  and the host has not already turned it on. It only flips what it needs: an
  IPv4-only route never touches the IPv6 sysctl.
- **A `DOCKER-USER` accept rule for the return leg, if the host also runs
  Docker.** Docker installs its own `ip filter` table with a `FORWARD` base
  chain at `priority filter` (0) and **`policy drop`** — a *separate* table
  from `karst_routes` (below), evaluated *after* it at the same `forward`
  hook, since `karst_routes`'s own chain registers at `priority filter - 10`.
  An `accept` verdict in `karst_routes` does not stop Docker's table from
  independently evaluating — and, if nothing in `DOCKER-USER` matches,
  dropping — the same packet. Docker's own docs call for exactly this: add
  the host's own accept rules to `DOCKER-USER`, which runs before Docker's
  own rules. The outbound leg needs `iifname "karst0" accept`; the **return**
  leg needs the mirror, `oifname "karst0" accept` — easy to add only the
  first and consider the host fixed, since outbound (client → gateway →
  internet) now visibly works while the return leg fails silently (issue
  #345): the gateway's own forwarding accept-rule counter increments, but
  `karst0`'s kernel TX counter never does, because Docker's table drops it
  one hook-priority later. `karstd` never touches `DOCKER-USER` itself — an
  operator table, same as any other.

None of this is preflighted against a route that never arrives — readiness is
reported per reconciliation, in `karst status`'s `[routing]` block
(§5 below), not as a one-time startup check.

## 2. Forwarding and NAT behavior

A gateway's forwarding grant lives in its own nftables table (`karst_routes`,
family `inet`), never touching an operator's own tables or rules. For each
route the node is the gateway for, it installs:

- a `forward` hook rule accepting traffic whose **inbound interface is the
  Karst tunnel**, sourced from the tunnel's own overlay range, destined for
  the advertised prefix;
- a matching return-path accept for established/related connections leaving
  the tunnel;
- a final `drop` for anything else arriving on the tunnel interface that
  reached the chain — a gateway forwards authenticated overlay traffic to the
  one prefix it was authorized for, and nothing else. Enabling kernel
  forwarding does not turn the host into a general router.

**With `masquerade = true`** (the common case), a `postrouting` NAT rule
rewrites the source address of forwarded packets to the gateway's own address
on the destination network. The destination host sees ordinary traffic from
an on-link neighbor and needs nothing beyond its own default route to answer
it — this is what every namespace integration row in `bins/karstd/tests/
aquifer.rs` exercises, and it is the right default for a client reaching a
subnet it does not otherwise know how to route back to.

**With `masquerade = false`**, no NAT rule is installed. Forwarded packets
keep the client's real overlay source address (`100.64.0.0/10` or the
account's IPv6 ULA range). The destination network must have an explicit
route back to that range through the gateway, or replies never arrive —
requests would appear to succeed at the gateway and simply vanish. This is
the *return-route mode* the plan's own console work warns about: turning off
masquerade is a statement that the destination network's own routing already
accounts for the overlay, not merely "send packets as themselves." Confirm
the return route exists before disabling masquerade on anything that matters.

## 3. Exit-node privacy

Consenting to a `0.0.0.0/0` or `::/0` offer routes this device's general
Internet traffic through the selected gateway. The gateway is a full traffic
intermediary for that traffic in exactly the sense any VPN exit node is: it
sees cleartext destinations and, for unencrypted protocols, cleartext
payloads. It does **not** see this device's Karst control-plane traffic, its
connections to other overlay peers, or its relay/TURN traffic — those are
carved out from the default route before it is ever installed
(`exit_policy.rs`'s escape rules, computed from the current control server,
relay, TURN, and peer underlay endpoints, and recomputed whenever those
endpoints change), specifically so consenting to an exit route cannot
recursively capture the tunnel's own transport.

Consent is local and durable (§3.2 of the plan): the control server can
*offer* `0.0.0.0/0`/`::/0`, never activate it. A route ID accepted with
`karst exit-node use <route-id>` survives config reload, daemon restart, and
a missed netmap push; the console can report an offered or active exit route
but cannot manufacture consent on a client's behalf. Nothing this section
describes bypasses that gate — routing and privacy exposure begin only after
the local operator has explicitly opted in.

On macOS (ADR-0036) the local operator is the Mac's administrator, with two
equivalent ways to give or withdraw consent: `sudo karst exit-node use
<route-id>` / `disable` (the CLI ships with the package and talks to the
Network Extension's root-only socket), or Karst.app's **Exit node** menu,
which shows this section's disclosure and asks for an administrator's
password; the extension verifies that authorization itself before changing
anything. A non-administrator can see the current exit but cannot change it.

## 4. Recovery

| Situation | What restores it |
|---|---|
| A client no longer wants its exit route active | `karst exit-node disable` — withdraws the kernel default route immediately and clears the durable consent record. Re-selecting the same or a different route needs `exit-node use` again. |
| An operator disables or deletes a route in the console | The next pushed netmap withdraws the kernel route on every affected recipient and the forwarding grant on the gateway — no restart needed on either side. Both leave dormant consent in place for that route ID: the wire carries no distinction between "temporarily disabled" and "gone for good" (a disabled route is simply absent from the offer list, the same as a deleted one), and a recipient cannot safely treat "the server stopped mentioning this ID" as authorization to discard its own durable consent record — §3.2's client-owned-consent boundary cuts both ways. Re-enabling a disabled route never needs re-consent, by construction. Clearing consent for an ID that is gone for good is always available locally: `karst exit-node disable`. |
| The gateway's `karstd` crashes or is restarted | Reconciliation is idempotent at every layer that installs anything, tolerating exactly what a crashed prior instance would have left behind (`Drop` does not run under `SIGKILL`): `nft add table` tolerates the table already existing, a recipient's kernel route is installed with replace semantics, and the exit-policy `ip route`/`ip rule` installs each delete the same spec first. The fresh process rebuilds everything from the current netmap on its own, with no operator action — but see the row below for how long a *recipient already connected to that gateway* takes to notice. |
| A recipient's `karstd` crashes or is restarted | Exit-route consent is read back from `exit_node_state_file` at startup and re-applied without re-running `exit-node use`; subnet routes reappear from the next netmap fetch, the same as any other cryptokey route. |
| A gateway crashes and restarts while a recipient's own session stays up | Slower than every other row in this table, and not a routing-layer property: the recipient's session with the gateway looks established right up until the crash, and PHREATIC's own rule that only the initiator rekeys (`spec/phreatic-v1.md` §7) means the surviving recipient has no reason to dial a fresh handshake until its session reaches `REKEY_AFTER_TIME` (120s). Measured in practice at a little over two minutes end to end. A route or policy change on an already-live session reaches it in seconds (the row above); a peer's own process dying is a session-liveness question, not a route-push one. |
| `karstd` is uninstalled or stopped for good | Only state Karst itself changed is undone: the `karst_routes` nftables table is removed, and a forwarding sysctl Karst flipped from `0` is restored to `0` — one it found already enabled is left alone. Any operator firewall rules and any forwarding sysctl already on before Karst ran are untouched. |
| A route's gateway *group* has more than one member and the currently-effective one goes offline | The server excludes an offline gateway from the route's candidate set entirely once its control-channel session ends (not the row above's `REKEY_AFTER_TIME`, which is a *recipient's own* data-plane session-liveness question, not this one) — the next netmap push carries only the remaining, connected candidate(s), and every recipient's local HA selection (lowest metric, tied by gateway ID) converges on the same one deterministically. Recovery is bounded by netmap refresh latency, typically seconds, not the ~2-minute figure above. If every member of the group is offline, the route is withdrawn entirely rather than offered pointing at nothing reachable. This governs which gateway a route is offered through; it is not liveness-aware selection *within* an already-accepted netmap — a recipient does not re-run selection on its own between pushes. |

### Gateway consent configuration migration

Server-managed nodes accept `node.gateway_exit_state_file` as the canonical
name for local durable exit consent. `node.exit_node_state_file` remains a
supported compatibility alias. Both names resolve relative paths against the
configuration directory and use the same protected file and route-ID format.
Omitting the setting retains the existing platform default. This setting
chooses storage only: it neither enables forwarding nor grants exit consent.
Static rosters do not receive managed route offers and do not use this setting.

Before changing a deployed configuration:

1. Back up the configuration and existing consent file with their owner-only
   permissions intact. Record the resolved path; do not change it.
2. In the existing `[node]` table, replace only the key
   `exit_node_state_file` with `gateway_exit_state_file`, keeping its value.
   Do not add both: the daemon rejects duplicate spellings, even if equal.
3. Upgrade the daemon before using the new spelling. Older daemons reject it
   as an unknown field; the legacy spelling works on both versions.
4. After restarting, inspect `karst gateway exit list` and
   `karst gateway status`. Existing selection is retained; actual exit use
   still requires an eligible authenticated offer and the usual policy checks.

For rollback, restore the legacy key spelling and keep the **current** consent
file at the same path. Do not restore an old consent backup over a later
`gateway exit disable`, which would resurrect withdrawn consent. No file move,
route-ID conversion, permission change, or default-path change is required.
Legacy settings remain supported; no removal version has been scheduled.
This additive migration covers local consent storage naming only; unified
control configuration, route persistence, APIs/UI and Relay migration remain
tracked in #404.

## 5. Inspecting effective state

The Gateway command group combines inspection of subnet and exit routing with
explicit exit-consent actions:

| Command | Behavior |
|---|---|
| `karst gateway status` | Reports the current authenticated subnet/exit offers, local exit selection, forwarding readiness and errors; changes no routing or consent |
| `karst gateway exit list` | Lists eligible exit offers and the current local selection |
| `karst gateway exit use <route-id>` | Gives durable local consent to an eligible default-route offer |
| `karst gateway exit disable` | Withdraws and forgets local exit consent; does not disable Gateway forwarding or subnet routing |

These commands use the protected administrative socket; use `sudo` where the
installed service requires it, and `--socket PATH` for a custom installation.
`gateway exit` actions retain the existing `exit-node` IPC requests, so older
daemons support them. `gateway status` requires an updated daemon; an older
daemon rejects it explicitly and the CLI exits unsuccessfully. Use the existing
`karst status` routing section until the daemon is upgraded. Existing
`karst exit-node list|use|disable` commands remain supported aliases.

`gateway status` uses the same routing report as `karst status`; it lists both
recipient and forwarding roles, not just exit offers. Its `active` field retains
current status semantics: forwarding readiness for Gateway rows and installed,
consented exit use for recipient exit rows. Subnet recipient rows are offers,
not a separate proof of installed kernel routes; inspect `ip route` as below.
Unified configuration, APIs/UI and Relay lifecycle remain pending in #404.

- **`karst status`** — the `[routing]` block reports `gateway_active`,
  `exit_route_active`, `selected_exit`, and the last gateway readiness error,
  if any; each `[[route]]` entry shows the route's role for this node
  (`gateway` or `recipient`), its kind (`subnet` or `exit`), and whether it
  is currently active.
- **`karst exit-node list`** — every currently offered exit route and
  whether it is the one this device has consented to. `selected_offered`
  reports whether the selected route ID is still among them — `false` is
  the operator-visible sign of the dormant, dangling consent described in
  the Recovery table above (§4), clearable with `karst exit-node disable`.
- **`nft list table inet karst_routes`** (root) — the gateway's own live
  forwarding and NAT rules, including per-rule packet/byte counters. A table
  that is empty or missing on a node whose own `karst status` reports it as
  an active gateway is the signature of the routing bug this feature's own
  W7 integration work found and fixed: `Routes::wanted` installing a tunnel
  route over a prefix the node's own gateway forwarding already depended on
  reaching by a real interface, silently destroying that interface's kernel
  route. Worth checking first if forwarding is reported ready but traffic is
  not actually moving. The same per-route egress and ingress counters are
  also available without root or host access, via the console's NOC view or
  `GET /noc/components` (issues #281, #371, #372, "Per-route throughput" in
  `admin-console.md`) — this manual path stays useful mainly for an
  operator without console access.
- **`ip route show`** on a recipient — a subnet route appears as a normal
  route over the tunnel interface; a consented default route appears in a
  dedicated policy-routing table rather than the main table (`ip rule show`
  lists the priority it is installed at), which is what keeps it from
  shadowing the host's own default route for control, relay, and TURN
  traffic.
- **The outbound leg works (`tcpdump` on the gateway's physical interface
  shows a complete round trip) but the client never gets a reply, and
  `ip -s link show karst0`'s `TX` counter never moves** even though
  `nft list table inet karst_routes`'s own per-route `oifname "karst0" ct
  state established,related accept` rules' counters do — this is §1's
  Docker/`DOCKER-USER` gap (issue #345), not a `karstd` bug: check
  `nft list ruleset` for an `ip`/`ip6` table with a `FORWARD` chain whose
  `policy` is `drop` (Docker's, if installed, is the usual culprit;
  firewalld and ufw install their own equivalents), and confirm
  `DOCKER-USER` has an `oifname "karst0" accept` rule, not only the
  `iifname "karst0"` one the outbound leg needs.
