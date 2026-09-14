<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Customer scenarios

This is the canonical set of narrative, day-in-the-life scenarios used as the
basis for Karst's use-case and product documentation, including the
non-technical overview on [karst-net.github.io](https://karst-net.github.io).
Where [docs/USE-CASE-ANALYSIS.md](USE-CASE-ANALYSIS.md) describes the system
in terms of actors, components, and formal use cases (UC-01 through UC-10),
this document describes the same system in terms of the people asking for it,
and is meant to be stable: new scenarios should be added here first, then
traced into UC entries, ADRs, and outward-facing copy, rather than invented
independently in marketing text.

Each entry states the scenario in plain language, the Karst mechanism that
actually provides it (with a cross-reference), a minimal configuration sketch
where one clarifies, and — matching this project's [stated
policy](../README.md#beta-caveats-stated-plainly) of disclosing what it does
not do — an explicit note where the scenario is **not** something Karst
supports today, rather than stretching an existing feature to imply it does.

One scenario in this set, SC-06, is *not* currently achievable with Karst.
SC-05 looked the same way at first — a feature request evaluated and
declined ([ADR-0023](adr/0023-declining-device-activity-visibility-for-account-owners.md))
— until a follow-up proposal led to a working recipe using an
already-shipped feature instead ([ADR-0024](adr/0024-exit-node-routing-reconsiders-adr-0023.md)).
Both are kept in the basis set deliberately, including the history: they are
realistic asks, worth tracking, and the honest answer — a decline, a
recipe, or a genuine gap — belongs in documentation next to the scenarios
Karst handles outright, not omitted because it's inconvenient or because the
answer changed once.

## SC-01 — Telecommuter on untrusted coffee-shop Wi-Fi

**Actor:** a remote employee working from a Starbucks, airport lounge, or
other shared network they do not control.
**Goal:** reach internal systems (an internal wiki, a VPC-only database, a
build server) without exposing that traffic to the local network operator or
other clients on the same access point.

**Mechanism:** this is Karst's ordinary operating mode — [UC-08, "Establish
and maintain peer connectivity"](USE-CASE-ANALYSIS.md#uc-08--establish-and-maintain-peer-connectivity).
The coffee-shop Wi-Fi is just an IP transport to the client; PHREATIC
end-to-end encryption and Bedrock-anchored peer identity ([UC-09](USE-CASE-ANALYSIS.md#uc-09--govern-bedrock-network-membership))
mean the local network's trustworthiness is irrelevant to the overlay's
confidentiality or peer authentication. AVEN attempts a direct path first and
falls back to the Ponor relay when the local NAT or a captive portal's
filtering prevents that ([UC-08](USE-CASE-ANALYSIS.md#uc-08--establish-and-maintain-peer-connectivity);
see the NAT matrix in the [README](../README.md)).

**Caveats:**
- The client still needs ordinary Internet reachability on the hostile
  network first — Karst does not get a device past a captive portal.
- Unless an administrator has also routed this user through an exit node
  ([UC-07](USE-CASE-ANALYSIS.md#uc-07--configure-a-subnet-router-or-exit-node)),
  Karst protects the overlay flows it carries; it does not become a
  general-purpose "hide my browsing from this Wi-Fi" consumer VPN by default.
  That is a deliberate default — see SC-02, where the same exit-node
  mechanism is used on purpose.
- Per the [threat model §7](THREAT-MODEL.md), metadata (who talks to whom,
  when, how much) is not hidden from an on-path relay operator, though it was
  never visible to the coffee shop's network to begin with once the overlay
  is up.

## SC-02 — Vacationer streaming with a home-region IP

**Actor:** someone traveling outside their home region who wants a streaming
catalog (e.g., a show's next season) gated by an IP-based regional check, and
wants their traffic to appear to originate near their home ZIP code.
**Goal:** route web traffic through a device on their home network so the
destination sees a residential IP address from their normal region.

**Mechanism:** an **exit node** at home — a Karst client running on a home
router or always-on machine, advertising a consented default route
([UC-07](USE-CASE-ANALYSIS.md#uc-07--configure-a-subnet-router-or-exit-node);
[docs/subnet-routers-and-exit-nodes.md](subnet-routers-and-exit-nodes.md)).
The traveling client explicitly consents to the `0.0.0.0/0`/`::/0` route,
which Karst requires and never applies silently. Traffic exits to the
Internet from the home network's own residential IP address, not from a
relay or datacenter range — which is the practical difference from a
commercial VPN's location-spoofing, whose IPs are datacenter ranges that
streaming providers routinely detect and block.

**Configuration sketch:** the home device is placed in a routing group and
offers the default route; an access-policy entry restricts who may consent to
and use that exit route to the household's own devices/group, following the
least-privilege pattern in [UC-05](USE-CASE-ANALYSIS.md#uc-05--grant-and-validate-connectivity-permissions).

**Caveats:**
- **This is a general capability of the exit-node feature, not something
  built or marketed as a streaming-geolocation bypass.** Whether it complies
  with a given streaming service's terms of use is between the traveler and
  that service; Karst is a transport, not an opinion on that question.
- All of the traveler's exit traffic now transits the home network's own
  upload/download caps and the home ISP's traffic-shaping policy — a
  meaningful difference from a datacenter VPN under load.
- The exit-node operator (in this case, the traveler's own household) is the
  one who can observe destination metadata for that traffic, per the
  exit-node caveat in [UC-07](USE-CASE-ANALYSIS.md#uc-07--configure-a-subnet-router-or-exit-node).

## SC-03 — Traveler printing a signed form on a home printer

**Actor:** a traveler who has a signed PDF (e.g., a permission slip) and
wants to print it on a printer physically at home, reachable only on the home
LAN.
**Goal:** reach the printer's network service (IPP/AirPrint, or a
vendor web UI) from outside the home network, without exposing the rest of
the home LAN.

**Mechanism:** a **subnet router** advertising the printer's `/32` (or a
narrow CIDR containing just the printer) rather than the whole home LAN
([UC-07](USE-CASE-ANALYSIS.md#uc-07--configure-a-subnet-router-or-exit-node)),
scoped further by an access-policy rule limiting the flow to the printer's
port (typically IPP/631) and to the traveler's own node
([UC-05](USE-CASE-ANALYSIS.md#uc-05--grant-and-validate-connectivity-permissions)).
This is the scoped-route pattern deliberately called out in that use case:
advertise the destination that's actually needed, not the whole LAN, and gate
it with policy rather than relying on network topology alone.

**Caveats:** the printer itself does not become a Karst node — a gateway
device on the same LAN as the printer (a home router or always-on machine
running `karstd`) is the one that advertises the route and forwards to it.

## SC-04 — Traveler reaching a restricted file share

**Actor:** a traveler who needs a document sitting on a home or office file
share (SMB or NFS) that only specific users are meant to access.
**Goal:** reach the share from outside the local network, with access
limited to the same set of authorized users the share already restricts.

**Mechanism:** same subnet-router pattern as SC-03
([UC-07](USE-CASE-ANALYSIS.md#uc-07--configure-a-subnet-router-or-exit-node)),
combined with a group-scoped access-policy rule
([UC-05](USE-CASE-ANALYSIS.md#uc-05--grant-and-validate-connectivity-permissions)).
Following the worked-example style in the
[migration guide](MIGRATING-FROM-WIREGUARD-TAILSCALE.md#3-worked-wireguard-to-karst-policy-example):

```json
{
  "groups": {
    "group:family": ["alice@example.com", "bob@example.com"]
  },
  "tagOwners": {
    "tag:home-nas": ["group:family"]
  },
  "acls": [
    { "action": "accept", "src": ["group:family"], "dst": ["tag:home-nas:445"] }
  ]
}
```

Karst's ACLs are default-deny, so anyone not in `group:family` is denied the
share by the mesh itself, independent of whatever share-level authentication
the file server also performs — the two controls are additive, per
[UC-05](USE-CASE-ANALYSIS.md#uc-05--grant-and-validate-connectivity-permissions).

**Caveats:** the share's own user authentication (e.g., SMB credentials)
still applies; Karst's ACL controls network reachability to the port, not
the file server's own authorization.

## SC-05 — Parent monitoring a child's website activity

**Actor:** a parent who wants visibility into what websites their child's
device is visiting while enrolled in the family's mesh.
**Goal:** see a log or report of the child's web activity.

**Not currently supported.** Karst does not inspect, log, or report the
content or destination hostnames of a client's traffic, by design — see the
threat model's stated non-goal that "[metadata is not
protected](THREAT-MODEL.md#7-accepted-risks-and-non-goals)" from a *relay*
operator's perspective, which is a different thing from an admin console
*feature* to surface that data to an account owner. No such feature exists.
The [audit log](USE-CASE-ANALYSIS.md#uc-10--monitor-investigate-and-prove-administrative-activity)
records administrative control-plane events (policy changes, enrollments,
blocks) — not a user's browsing history — and that distinction is
intentional: an enrolled device's owner is not meant to be surveilled by the
account administrator as a matter of course.

**Decided, not just unbuilt.** [ADR-0023](adr/0023-declining-device-activity-visibility-for-account-owners.md)
evaluated this as a tracked feature request (GitHub issue #150) and declined
it: extending the administrator role to surface a device's own activity to
its account owner, without a disclosure requirement designed in, would break
the client-user/administrator authority boundary the rest of the
[identity model](USE-CASE-ANALYSIS.md#actors-and-identities) depends on. The "parent as administrator,
child as enrolled user" relationship is not the employer/employee
relationship the audit log (UC-10) was built around, and reusing it would
extend a fleet-management primitive into surveillance over a person.

**A concrete recipe exists, using an already-shipped feature.**
[ADR-0024](adr/0024-exit-node-routing-reconsiders-adr-0023.md) revisited this
after a proposal to force traffic through the *relay* — which cannot work;
Ponor is verified to derive no session key and never see payload content
(`spec/ponor-v1.md` §11/§13.3), so it can only ever add the same
mesh-peer-traffic metadata already disclosed in
[THREAT-MODEL.md §7](THREAT-MODEL.md#7-accepted-risks-and-non-goals), never
a website. The **exit node** (UC-07), by contrast, already sees cleartext
destinations and TLS SNI hostnames by construction — that's inherent to
being the box that un-wraps overlay traffic onto the real Internet
(`docs/subnet-routers-and-exit-nodes.md` §3), not a new capability.

What makes this work without any new Karst feature is that Karst already
separates two roles this scenario conflates: the *enrolled Karst user* of a
device, and the *local operator* who holds administrator rights on it. A
parent who sets up and administers a child's computer already **is** its
local operator, distinct from the child's enrolled-user identity. The parent
runs `karst exit-node use <route-id>` once, as the machine's administrator,
pointing at an exit node they run — durable across restarts
(`docs/subnet-routers-and-exit-nodes.md` §4) — and the child's own
unprivileged OS account cannot reach the root-only control socket
(`bins/karstd/src/ipc.rs`) needed to disable it. Visibility then comes from
ordinary host-side tooling (DNS logs, SNI inspection, or a logging proxy) on
the parent's own gateway — nothing Karst needs to build.

This does not reach a device whose enrolled user is *also* its own local
administrator (a self-administered, personally-owned machine): no
client-side VPN, Karst included, can prevent a local admin from
reconfiguring their own machine, and Karst deliberately keeps it that
way — see ADR-0024's decision not to let the control plane force exit-route
activation, which would reopen exactly the disclosure problem ADR-0023
declined.

## SC-06 — Parent implementing web filtering with time-of-day rules

**Actor:** a parent who wants to block categories of websites for a child's
device, with different rules at different times of day (e.g., no
non-homework sites on school nights after 8pm).
**Goal:** category- and schedule-based content filtering.

**Not currently supported, on two independent axes:**

1. **No time-of-day dimension exists in the policy engine.** The access-policy
   schema ([UC-05](USE-CASE-ANALYSIS.md#uc-05--grant-and-validate-connectivity-permissions);
   `spec/karst-control-v1.md`) expresses `accept` rules over groups, tags, and
   ports — there is no schedule, time window, or day-of-week field to attach
   to a rule. A rule is either in the compiled policy or it isn't.
2. **No content/category filtering exists.** Karst's ACLs authorize network
   flows to IP-and-port destinations, not domain categories. Even if a
   destination-based rule were written, most modern websites sit behind
   shared CDN/anycast infrastructure, so blocking "a website" by IP is
   unreliable in a way that doesn't apply to the printer- or file-share-style
   destinations in SC-03/SC-04, which have stable, specific addresses.
   KarstDNS ([UC-06](USE-CASE-ANALYSIS.md#uc-06--configure-dns-and-private-service-discovery))
   resolves mesh names and directs split-domain queries to designated
   upstreams, but has no category-blocklist concept either.

This is a genuine gap rather than a scenario Karst quietly half-supports: if
it's prioritized, it most plausibly lands as a scheduled-policy extension to
the access-policy engine plus a DNS-based filtering upstream wired through
KarstDNS's split-DNS mechanism — not as a stretch of the existing ACL or
routing primitives.

## SC-07 — Coworker asking another coworker to review a dev server

**Actor:** two telecommuting coworkers, one of whom has a web app running
locally (e.g., `localhost:3000`) and wants the other to look at it without
publishing it to the public Internet.
**Goal:** point-to-point reachability to one port on one machine, scoped to
one other person, for as long as it's useful.

**Mechanism:** this is Karst's simplest happy path —
[UC-08](USE-CASE-ANALYSIS.md#uc-08--establish-and-maintain-peer-connectivity)
between two already-enrolled nodes, scoped by an access-policy rule naming
just that port and that reviewer:

```json
{
  "acls": [
    { "action": "accept", "src": ["reviewer@example.com"], "dst": ["tag:devbox:3000"] }
  ]
}
```

AVEN attempts a direct path between the two peers and falls back to the
Ponor relay only if both are behind restrictive NATs
([README](../README.md) NAT matrix). Unlike a public tunneling service (e.g.,
ngrok), the dev server is never exposed to the open Internet — reachability
is limited to the named peer by the ACL, and the relay (when used) carries
PHREATIC ciphertext, not a plaintext HTTP proxy.

**Caveats:** this scenario is intentionally ephemeral in practice — a tag or
rule scoped to one reviewer and one port is easy to add and remove, and
should be removed once the review is done rather than left as a standing
grant, per the least-privilege framing in
[UC-05](USE-CASE-ANALYSIS.md#uc-05--grant-and-validate-connectivity-permissions).

## SC-08 — IT sizing relay/coordination infrastructure by client geography

**Actor:** a company IT/infrastructure team deciding where to deploy relays
and how to size them, based on where its clients actually are and how much
traffic they generate.
**Goal:** understand the geographic distribution of client connections and
traffic volume well enough to place and size relays.

**Mechanism:** the relay registry carries an optional `region` field per
relay (`spec/karst-control-v1.md` §5.4), which an administrator sets when
registering a relay ([UC-02](USE-CASE-ANALYSIS.md#uc-02--bootstrap-the-control-plane-and-relay)),
and clients report bounded, authenticated last-known path observations
(direct/relay/unreachable, endpoint, epoch) that control exposes as
telemetry ([UC-08](USE-CASE-ANALYSIS.md#uc-08--establish-and-maintain-peer-connectivity)).
Combined with relay-side connection/admission metrics
([docs/observability.md](observability.md)) and audit records of relay
registration and roster freshness
([UC-10](USE-CASE-ANALYSIS.md#uc-10--monitor-investigate-and-prove-administrative-activity)),
an IT team has the raw signal needed to see which relays are loaded, which
regions are underserved, and where a client's actual last-known endpoint sits.

**Caveats:**
- **Karst does not itself do GeoIP resolution of client public IP addresses
  as a built-in analytics feature.** The `region` field is an operator-set
  label on a *relay*, not a computed property of a *client*. Turning observed
  client endpoint IPs into geography is the IT team's own correlation step
  (an external GeoIP source), not something the control plane computes today.
- Per the threat model, relay/path telemetry is "last-known," not
  proof of current state ([UC-08](USE-CASE-ANALYSIS.md#uc-08--establish-and-maintain-peer-connectivity));
  treat sizing decisions as directional, not as a real-time traffic map.
- This is exactly the kind of visibility the threat model discloses relay
  operators have by default (peer identifiers, timing, volume — [§7](THREAT-MODEL.md#7-accepted-risks-and-non-goals)):
  useful for capacity planning, not evidence of payload content.

## SC-09 — IT replacing OpenVPN or AWS VPN with Karst

**Actor:** a company IT department currently running a traditional VPN
concentrator (OpenVPN, AWS Client VPN, AWS Site-to-Site VPN) and evaluating
Karst as a replacement.
**Goal:** stand up Karst so it does the job the legacy VPN was doing —
remote access to internal resources, or reachability into a VPC — without
retaining the old system's protocol.

**Mechanism:** this is the same shape as the existing
[migration guide](MIGRATING-FROM-WIREGUARD-TAILSCALE.md), generalized: an
OpenVPN server or AWS VPN Gateway is conceptually replaced by
`karst-control` plus a `karst-relay`
([UC-02](USE-CASE-ANALYSIS.md#uc-02--bootstrap-the-control-plane-and-relay)),
and reachability into resources the old VPN gave access to (a VPC, an
on-prem subnet) is replaced by an **exit node or subnet router**
([UC-07](USE-CASE-ANALYSIS.md#uc-07--configure-a-subnet-router-or-exit-node))
placed inside that network, gated by the same default-deny access-policy
model as every other scenario in this document
([UC-05](USE-CASE-ANALYSIS.md#uc-05--grant-and-validate-connectivity-permissions)).
Karst's user/device lifecycle and IdP integration
([UC-03](USE-CASE-ANALYSIS.md#uc-03--add-invite-and-deprovision-a-user),
[UC-04](USE-CASE-ANALYSIS.md#uc-04--enroll-and-manage-a-device)) replace the
legacy VPN's certificate or PSK distribution process.

**Caveats — read literally, "facade" has two possible meanings, and only
one is real:**
- **Replacement (what this scenario means):** Karst runs alongside the old
  VPN during a validation window and then takes over, per the [clean-cutover
  procedure](MIGRATING-FROM-WIREGUARD-TAILSCALE.md#4-clean-cutover-procedure).
  This is real and supported in spirit, though — unlike WireGuard/Tailscale —
  **no dedicated OpenVPN or AWS VPN migration guide exists yet**; today's
  guide only covers WireGuard and Tailscale concept mapping. Writing an
  OpenVPN/AWS-specific version of that guide (translating OpenVPN's
  certificate-based peer model or AWS's VPN Gateway/route-table model into
  Karst groups, tags, ACLs, and routes) is a documentation gap this scenario
  should be used to close.
- **Protocol-level facade (Karst terminating OpenVPN or IPsec/AWS VPN
  connections and re-emitting them as PHREATIC, or vice versa):** **not
  possible and not planned.** Karst has no interoperability bridge with any
  other VPN protocol — the README states this plainly for WireGuard
  specifically ("no WireGuard interoperability... a post-quantum handshake
  cannot talk to a WireGuard peer"), and the same is true of OpenVPN and
  AWS's IPsec-based VPN by the same argument: PHREATIC's handshake shares no
  wire framing with any of them. There is no planned bridging layer between
  Karst and any other VPN protocol.

## Cross-reference summary

| Scenario | Primary mechanism | Formal use case(s) | Status |
| --- | --- | --- | --- |
| SC-01 Untrusted Wi-Fi telecommuter | Ordinary mesh connectivity | UC-08, UC-09 | Supported |
| SC-02 Home-region streaming IP | Exit node, consented default route | UC-07, UC-05 | Supported |
| SC-03 Print on home printer | Subnet router, port-scoped ACL | UC-07, UC-05 | Supported |
| SC-04 Restricted file share | Subnet router, group-scoped ACL | UC-07, UC-05 | Supported |
| SC-05 Monitor child's browsing | Exit node run by the machine's local operator | UC-07 | Supported today if the admin is also the device's local operator — see [ADR-0023](adr/0023-declining-device-activity-visibility-for-account-owners.md) / [ADR-0024](adr/0024-exit-node-routing-reconsiders-adr-0023.md) |
| SC-06 Web filtering + time-of-day | — | — | **Not supported** |
| SC-07 Coworker dev-server review | Peer connectivity, narrow ACL | UC-08, UC-05 | Supported |
| SC-08 Geo sizing of relays | Relay `region` field, path telemetry, metrics | UC-02, UC-08, UC-10 | Supported, with caveats |
| SC-09 Replace OpenVPN/AWS VPN | Control plane + relay + exit node, migration procedure | UC-02, UC-05, UC-07 | Supported (needs a dedicated migration guide); protocol-level facade not possible |
