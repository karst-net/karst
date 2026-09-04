<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Subnet routers and exit nodes

Operations reference for the feature `plans/phase-6/06-subnet-routers-and-exit-nodes.md`
implements: advertising an IPv4 or IPv6 subnet through one or more gateway
nodes, and offering `0.0.0.0/0`/`::/0` as a client-consented default route.
For how it fits together end to end, see that plan; this document is what an
operator needs once it is running — what a gateway host needs, what actually
crosses the wire, how to recover it, and how to see its effective state.

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

## 4. Recovery

| Situation | What restores it |
|---|---|
| A client no longer wants its exit route active | `karst exit-node disable` — withdraws the kernel default route immediately and clears the durable consent record. Re-selecting the same or a different route needs `exit-node use` again. |
| An operator disables or deletes a route in the console | The next pushed netmap withdraws the kernel route on every affected recipient and the forwarding grant on the gateway — no restart needed on either side. Disabling keeps dormant consent for that route ID; deleting clears it, so re-enabling a merely-disabled route does not require re-consenting on `/0` clients. |
| The gateway's `karstd` crashes or is restarted | Reconciliation is idempotent at every layer that installs anything, tolerating exactly what a crashed prior instance would have left behind (`Drop` does not run under `SIGKILL`): `nft add table` tolerates the table already existing, a recipient's kernel route is installed with replace semantics, and the exit-policy `ip route`/`ip rule` installs each delete the same spec first. The fresh process rebuilds everything from the current netmap on its own, with no operator action — but see the row below for how long a *recipient already connected to that gateway* takes to notice. |
| A recipient's `karstd` crashes or is restarted | Exit-route consent is read back from `exit_node_state_file` at startup and re-applied without re-running `exit-node use`; subnet routes reappear from the next netmap fetch, the same as any other cryptokey route. |
| A gateway crashes and restarts while a recipient's own session stays up | Slower than every other row in this table, and not a routing-layer property: the recipient's session with the gateway looks established right up until the crash, and PHREATIC's own rule that only the initiator rekeys (`spec/phreatic-v1.md` §7) means the surviving recipient has no reason to dial a fresh handshake until its session reaches `REKEY_AFTER_TIME` (120s). Measured in practice at a little over two minutes end to end. A route or policy change on an already-live session reaches it in seconds (the row above); a peer's own process dying is a session-liveness question, not a route-push one. |
| `karstd` is uninstalled or stopped for good | Only state Karst itself changed is undone: the `karst_routes` nftables table is removed, and a forwarding sysctl Karst flipped from `0` is restored to `0` — one it found already enabled is left alone. Any operator firewall rules and any forwarding sysctl already on before Karst ran are untouched. |

## 5. Inspecting effective state

- **`karst status`** — the `[routing]` block reports `gateway_active`,
  `exit_route_active`, `selected_exit`, and the last gateway readiness error,
  if any; each `[[route]]` entry shows the route's role for this node
  (`gateway` or `recipient`), its kind (`subnet` or `exit`), and whether it
  is currently active.
- **`karst exit-node list`** — every currently offered exit route and
  whether it is the one this device has consented to.
- **`nft list table inet karst_routes`** (root) — the gateway's own live
  forwarding and NAT rules, including per-rule packet/byte counters. A table
  that is empty or missing on a node whose own `karst status` reports it as
  an active gateway is the signature of the routing bug this feature's own
  W7 integration work found and fixed: `Routes::wanted` installing a tunnel
  route over a prefix the node's own gateway forwarding already depended on
  reaching by a real interface, silently destroying that interface's kernel
  route. Worth checking first if forwarding is reported ready but traffic is
  not actually moving.
- **`ip route show`** on a recipient — a subnet route appears as a normal
  route over the tunnel interface; a consented default route appears in a
  dedicated policy-routing table rather than the main table (`ip rule show`
  lists the priority it is installed at), which is what keeps it from
  shadowing the host's own default route for control, relay, and TURN
  traffic.
