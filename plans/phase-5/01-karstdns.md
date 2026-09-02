# KarstDNS

**PLAN.md §7 · W1–W7 · Rust 1, with Rust 2/3 taking the macOS and Windows
integrations inside their own client weeks.**

## 1. Historical starting point (superseded)

> **Re-baselined 2026-08-27.** This section's original inventory is obsolete.
> `karst-dns`, its netmap configuration, resolver/split-DNS policy, `karst dns`
> commands, and transactional Linux host integration (`systemd-resolved`,
> NetworkManager, and `resolv.conf`) are implemented and tested. The remaining
> Phase 5 DNS work is macOS and Windows host integration plus package-level
> install/upgrade/uninstall and recovery testing. Userspace mode deliberately
> has no host DNS integration. DoH/DoT upstream transport remains out of scope.

`crates/karst-dns/src/lib.rs` is five lines: a license header, a doc string,
and `#![forbid(unsafe_code)]`. It has no dependencies and no code. Everything
below is new.

What *does* exist is the naming half. Every node already has a `dns_name` in
the netmap — `KarstNetmapResponse.dns_name` (field 5) for self,
`KarstNetmapPeer.dns_name` (field 3) for each peer — assigned by the control
server from the peer's DNS label and the account's zone
(`control/netmap.go:57`, `DNSZone`), and both are folded into the netmap
version hash (`netmap.go:355`, `:436`, `:445`). `karstd` parses them, stores
them, and prints them in `karst status`.

**So the names exist and nothing resolves them.** Phase 5's job is the
resolver, the configuration that reaches it, and the five platform mechanisms
that point the host at it.

## 2. Deliverables

| # | Deliverable | Weeks |
|---|---|---|
| 2.1 | `spec/karstdns-v1.md`, normative | W1 |
| 2.2 | Netmap DNS configuration on the wire, both ends, vectors regenerated | W2–W3 |
| 2.3 | `karst-dns` crate: message codec, authoritative mesh zone, forwarder, cache | W2–W4 |
| 2.4 | Stub resolver wired into `karstd`, kernel and userspace modes | W4 |
| 2.5 | Split DNS | W4–W5 |
| 2.6 | Linux host integration: `systemd-resolved`, `resolv.conf`, NetworkManager | W5–W6 |
| 2.7 | Failure-mode handling: flap, leak, captive portal | W6 |
| 2.8 | `karst dns` CLI, `karstd` config surface, docs | W7 |

macOS `/etc/resolver` + `scutil` is [06](06-macos-client.md) §5. Windows NRPT
is [07](07-windows-client.md) §6. Both consume the same crate and the same
netmap fields; only the host-configuration shim differs.

## 3. Specification first

Write `spec/karstdns-v1.md` in W1, before the code, matching the four existing
specs in structure and normative language. It is short — this is not a new
cryptographic protocol, it is DNS — but three things need to be normative
because two implementations (node and server) must agree:

1. **The name grammar.** `<hostname>.<aquifer>.karst.` Which characters a
   label may hold, how a conflicting hostname is disambiguated, and that
   comparison is case-insensitive ASCII. The server already normalizes labels
   via `server/dns/dns.go`'s `invalidHostLabel` regexp and IDNA handling;
   the spec records what the node may assume rather than re-deriving it.
2. **Which questions the resolver answers authoritatively** and which it
   forwards — §5 below. Getting this wrong in either direction is a leak or a
   black hole.
3. **The netmap `KarstDNSConfig` encoding and its contribution to the version
   hash** — §4.

State two non-goals in the spec so they are decisions rather than gaps:
DNSSEC validation (the mesh zone is authenticated by the control channel, not
by signatures over RRsets) and encrypted upstream transport (DoH/DoT). Both
are defensible later; neither is Phase 5.

## 4. The wire change

### 4.1 Proto

Add to `server/shared/management/proto/karst_control.proto`:

```protobuf
message KarstDNSConfig {
  // Global upstream resolvers, in preference order. Empty means "keep
  // whatever the host had": the node configures the mesh zone and nothing
  // else, which is the safe default for a laptop on someone else's network.
  repeated string nameservers = 1;
  // Search domains pushed to the host resolver.
  repeated string search_domains = 2;
  // Split-DNS routes: match_domain -> resolvers reachable over the mesh.
  repeated KarstDNSRoute routes = 3;
  // The mesh zone, e.g. "aquifer.karst.". Authoritative suffix for §5.
  string zone = 4;
  // False disables host resolver configuration entirely. The node still
  // answers on its stub address for anything that asks it directly.
  bool magic_dns = 5;
}

message KarstDNSRoute {
  string match_domain = 1;
  repeated string resolvers = 2;
}
```

and one field on the response:

```protobuf
  KarstDNSConfig dns_config = 14;   // KarstNetmapResponse
```

Field 14 — 13 is `relays`. Check the number against the file before writing it;
these notes are eight weeks stale by the time anyone reads them.

### 4.2 The version hash, and the vectors it breaks

`karst-control-v1.md` §5.5 defines `netmap_version` as the leading eight bytes
of SHA-256 over a length-prefixed canonical encoding. DNS configuration must be
in it — a node holding a stale nameserver list must not be told its map is
unchanged. Extend the construction after the relay block, with a separator, for
exactly the reason the relay block has one:

```
LP("karst-dns") ||
LP(zone) || BE32(magic_dns ? 1 : 0) ||
LP(nameservers[0]) || … ||
LP(search_domains[0]) || … ||
each route's LP(match_domain, resolvers[0], …)
```

This is a **breaking change to the version construction**, the second one; the
first was the relay block on 2026-08-18. It touches, and all of these must land
in one commit or the netmap fails to validate across the pair:

- `server/management/internals/karst/control/netmap.go` — the `writeField`
  sequence, plus `netmap_test.go`
- `bins/karstd/src/netmap.rs` — the mirror construction and its tests
- `spec/karst-control-v1.md` §5.5 — the construction, plus a compatibility
  note in the same form as the 2026-08-18 one
- `spec/vectors/karst-control-v1.json` — regenerated
- `crates/karst-control-client/tests/vectors.rs` and
  `server/…/control/vectors_test.go` — both read those vectors

**Land this in W3 and not later.** It is the one change in the phase that
requires the Rust and Go halves to move together, and the cost of doing it
while the tree is quiet is a day.

### 4.3 Server side

`NetmapHandler` grows a `DNS` source alongside `DNSZone`. The fork already
stores nameserver groups and DNS settings per account
(`server/management/server/http/handlers/dns/`, `server/dns/`), so the work is
projection, not storage: read the account's nameserver groups and DNS settings,
filter to those the requesting node is in scope for, and emit `KarstDNSConfig`.

One rule worth writing as a test: **a disabled nameserver group must not appear
in any node's config**, and toggling one must move `netmap_version`. The
symptom of getting that wrong is a node that keeps resolving through a resolver
an admin has switched off, with the console showing it as off.

## 5. The resolver

### 5.1 Crate shape

```
crates/karst-dns/src/
  lib.rs        // Resolver, Config, and the public surface karstd drives
  message.rs    // wire codec — question, RR, name compression
  zone.rs       // authoritative answers for the mesh suffix + PTR
  forward.rs    // upstream selection, timeouts, retry, in-flight dedup
  split.rs      // longest-suffix routing table
  cache.rs      // negative and positive caching, TTL clamping
  host/         // host resolver configuration, one module per mechanism
    mod.rs      resolvconf.rs  resolved.rs  networkmanager.rs
    macos.rs    windows.rs
```

**Dependency: `hickory-proto` for the message codec only, not the resolver.**
It is `MIT OR Apache-2.0`, so it clears `deny.toml` and ADR-0007's GPLv2
compatibility constraint. Take the codec and write the ~400 lines of policy
above it ourselves; pulling `hickory-resolver` would bring a second async
runtime configuration, a second cache, and a system-configuration reader whose
behavior we would then have to constrain. Hand-rolling the codec instead is
not worth it: name compression and the escaping rules are exactly the kind of
parsing that has a CVE history, and there is a `#![forbid(unsafe_code)]`,
fuzz-tested, widely-used crate for it. **Add a fuzz target anyway** —
`fuzz/fuzz_targets/dns_message.rs`, matching the existing targets — because the
resolver parses attacker-controlled upstream responses.

### 5.2 What it answers, and what it must not

| Question | Behavior |
|---|---|
| `A`/`AAAA` for `*.<zone>` matching a netmap peer | Authoritative answer from the netmap, TTL 60 |
| `A`/`AAAA` for `*.<zone>` with no matching peer | **Authoritative NXDOMAIN.** Never forwarded — forwarding a mesh name to the LAN resolver publishes the internal hostname to whoever runs it |
| `PTR` in `100.64.0.0/10`'s `in-addr.arpa` and the account ULA's `ip6.arpa` | Authoritative from the netmap; NXDOMAIN for an unallocated address in-range |
| `CNAME`, `TXT`, `SRV`, `MX` for `*.<zone>` | `NOERROR` with an empty answer section — the name exists, that type does not. Not NXDOMAIN: NXDOMAIN means the *name* does not exist and poisons a client's cache for the A record too |
| Anything under a split-DNS `match_domain` | Forwarded to that route's resolvers, over the mesh |
| Everything else | Forwarded to the configured upstreams, or to the host's pre-existing upstreams if `nameservers` is empty |
| A query arriving with `RD=0` | `REFUSED`. This is a stub resolver, not a recursive one, and answering iterative queries makes it an open resolver on the mesh |

Three details that are easy to get wrong and each get a test:

- **Case.** Compare names case-insensitively, and echo the question section
  back byte-for-byte as asked. A client doing 0x20 randomisation drops an
  answer whose question section it cannot match.
- **EDNS0.** Preserve the requester's payload size on forwarded queries, and
  set `TC` correctly on UDP truncation so the client retries over TCP. Listen
  on TCP as well as UDP; a netmap with two hundred peers produces an answer
  that does not fit 512 bytes and some clients still assume it does.
- **Upstream loop.** Refuse to forward to any upstream that is the stub
  address itself, at configuration time, with a clear error. A host
  integration that writes `nameserver 100.100.100.100` into `resolv.conf` and
  then reads `resolv.conf` back as its upstream list is a loop that presents
  as a hung machine, and it is a mistake we will make at least once during
  W5.

### 5.3 The listening address is a problem, twice

**First: `100.100.100.100` is inside the address space we allocate from.**
Accounts get "a /16 out of 100.64.0.0/10" (`bootstrap.go:329`,
`control/netmap.go:35`). `100.100.0.0/16` is a legal allocation and it
contains the stub address; an account allocated that /16 will eventually assign
`100.100.100.100` to a node, and that node's own resolver will shadow it while
every other node routes its DNS traffic to a peer.

Fix on the server, in the allocator, not on the node: **exclude the
`100.100.100.100/32` host address from assignment, and refuse to allocate an
account the `100.100.0.0/16` prefix at all.** The second is coarser than
necessary and it is the one worth doing, because a reserved hole inside an
otherwise contiguous /16 is a footgun for every future feature that iterates
the prefix. Test: allocate accounts until the allocator would reach
`100.100.0.0/16` and assert it skips.

**Second: binding it needs privileges the daemon may not have.** ADR-0012's
release gate runs `karstd` with *no capabilities at all* and reads the kernel's
record back to prove it (`bins/karstd/tests/userspace.rs`). Binding UDP/TCP 53
needs `CAP_NET_BIND_SERVICE`, and the address must exist on an interface.
So there are two modes and the crate must support both:

| Mode | Resolver socket | Notes |
|---|---|---|
| Kernel TUN | Host socket bound to `100.100.100.100:53`, with the address added to the TUN device | Needs `CAP_NET_BIND_SERVICE` or a systemd socket unit passing the fd. Prefer the socket unit: it keeps the release gate's claim intact |
| Userspace (`smoltcp`) | A listener *inside* the userspace stack, no host socket at all | Free — the stack already terminates TCP for SOCKS5 (`socks5.rs`). The resolver is another in-stack listener |

The userspace mode is the easier of the two and should be built **first**, in
W4, because it needs no privileges and so no privileged test harness. The
kernel-TUN path then reuses the same `Resolver` behind a different socket.

### 5.4 Split DNS

Longest-suffix match over `routes`, evaluated before the global upstreams. Two
rules:

- A route whose resolvers are unreachable **fails the query with `SERVFAIL`
  rather than falling back to the global upstream.** A split-DNS route exists
  because that domain's answers are internal; leaking the question to a public
  resolver on failure is the exact disclosure the feature prevents.
- The mesh zone always wins over any route, even one that claims a suffix
  covering it. A route for `.karst.` is a configuration error; log it once and
  ignore it.

## 6. Host integration — the actual work

Five mechanisms, each with its own way of being wrong. All behind one trait so
`karstd` never branches on platform:

```rust
pub trait HostResolver {
    fn apply(&mut self, cfg: &HostConfig) -> Result<Revert, DnsError>;
    fn revert(&mut self, r: Revert) -> Result<(), DnsError>;
    fn observe(&self) -> Result<HostState, DnsError>;   // for `karst dns status`
}
```

| Mechanism | Detect by | Apply | Notes |
|---|---|---|---|
| `systemd-resolved` | `/run/systemd/resolve/stub-resolv.conf` exists **and** the D-Bus name is activatable | `org.freedesktop.resolve1.Manager.SetLinkDNS`, `SetLinkDomains` with the mesh zone as a routing-only domain (`~zone`) | The correct integration. Routing-only domains give split DNS for free. Use D-Bus directly (`zbus`), not `resolvectl` — shelling out to a binary that may not be installed is how this breaks on a minimal image |
| NetworkManager | `org.freedesktop.NetworkManager` on the bus and it manages the TUN device | Per-device DNS via the D-Bus API | NM and resolved often coexist; prefer resolved when both are present, and record why in the code |
| `resolv.conf` rewrite | Fallback when neither is present | Write, atomically, via a temp file and `rename(2)` | Preserve the original by copy, not by move — `/etc/resolv.conf` is frequently a symlink into `/run`, and moving it breaks whatever manages it |
| macOS | Always | A file per domain in `/etc/resolver/` — the zone and every search domain — then `dscacheutil -flushcache; killall -HUP mDNSResponder` | Implemented, `host/macos.rs`. **Not `scutil`**: a `SCDynamicStore` value lives only as long as the session that set it, so a `scutil` child process would have its entry dropped the moment it exits. The global search list therefore remains unimplemented — [06](06-macos-client.md) §5 |
| Windows | Always | NRPT rule via registry, or the `DnsClientNrptRule` PowerShell cmdlets | [07](07-windows-client.md) §6 |

**Test each on the distributions we claim to support, not on one.** The
difference between Debian's `resolvconf`, Ubuntu's stub-resolved, Fedora's
resolved-with-NM, and Alpine's bare file is the whole difficulty of this
section.

## 7. The three classic failure modes

PLAN.md §7 names these and says each gets a test. Concretely:

### 7.1 Stale resolver config after a flap

If `karstd` dies without reverting, the host is left pointing at a resolver
that is not listening, and **every DNS lookup on the machine fails** — which is
indistinguishable, to the person it happens to, from "the internet is broken".
This is the single worst bug this workstream can ship.

- Persist the `Revert` to `/var/lib/karst/dns-revert` at apply time, before the
  change is made. **Settled 2026-08-29, by GitHub issue [#67](https://github.com/karst-net/karst/issues/67).** This originally
  said `/run/karst/dns-revert.json`, and both halves of that were wrong: the
  record is length-prefixed binary rather than JSON, and `/run` is reclaimed by
  the unit's own `RuntimeDirectory=` on every stop — including the stop where
  `ExecStopPost=` failed, which is the only stop the record exists for. The
  units carry `StateDirectory=karst` so the directory exists and persists on a
  packaged and a hand-installed host alike. NetworkManager's snapshot stays
  under `/run`: it describes settings on a TUN device the kernel destroys with
  the daemon, so outliving the boot would make it wrong rather than useful.
- On startup, if a revert file exists and the config it describes is still in
  place, restore it before doing anything else.
- Ship the systemd unit with `ExecStopPost=` calling `karst dns revert`, so an
  ordinary stop reverts even on a crash-restart loop.
- Test: `SIGKILL` the daemon mid-session in a netns, restart, assert the host
  config is the original. Then assert the same across a reboot by leaving the
  revert file and starting cold — which needs the durable location above; under
  `/run` this row could not be written at all.

### 7.2 Leaks

`bins/karstd/tests/leakscan.rs` already exists (459 lines) and scans for
secrets in logs and traces. Add a DNS leak test of a different kind, as
`bins/karstd/tests/dns_leak.rs`: in a netns with a *hostile* upstream resolver
that logs every question it is asked, resolve a mesh name and assert the
upstream saw nothing. Then resolve a split-DNS name with the mesh route down
and assert the same.

### 7.3 Captive portals

A captive portal hijacks DNS. If the node is up and the mesh zone is claimed,
the portal's own hijack still works for everything else, which is the correct
outcome — but the node will also keep trying to reach a control server it
cannot reach.

The behavior to specify and test: when the upstream returns an answer for a
name the portal does not own with a TTL of a few seconds and a private
address, **do nothing special**. Do not attempt portal detection. The failure
mode to avoid is a resolver that "helpfully" bypasses the portal and leaves
the user unable to log in to the network at all. The test asserts that with a
hijacking upstream, mesh names still resolve correctly and non-mesh names
return whatever the portal said, unmodified.

## 8. Surfaces

- **`karstd` config** (`bins/karstd/src/config.rs`): a `[dns]` table —
  `enabled`, `stub_address`, `accept_netmap_config`, `upstream` override,
  `host_integration = "auto" | "resolved" | "resolvconf" | "networkmanager" |
  "macos" | "none"`. `"none"` is important: a machine whose DNS is managed by
  something we do not know about should be able to run the resolver and be
  pointed at it by hand. `"macos"` is the `/etc/resolver` directory and is what
  `"auto"` selects there; naming it off macOS is refused rather than accepted,
  because those files would be real state on a host whose resolver never reads
  them.
- **`karst dns status`**: what the node believes the host config is, what the
  host config actually is (`observe()`), which upstreams are in use, cache
  counters, and the last five failed lookups with their reason. Add
  `Command::DnsStatus` to `karstd::ipc` and a line to `karst-cli`'s `USAGE`.
- **`karst dns query <name>`**: resolve through the node's own resolver and
  print the path taken — authoritative / split route / upstream. This is the
  first thing anyone debugging a DNS problem will want and it costs an hour.

## 9. Tests

| Level | What | Where |
|---|---|---|
| Unit | Codec round-trip, zone answers, NXDOMAIN vs NODATA, longest-suffix match, cache TTL clamping | `crates/karst-dns/src/*` |
| Fuzz | Upstream response parsing | `fuzz/fuzz_targets/dns_message.rs` |
| Integration | Resolver over the userspace stack; netmap config applied and re-applied on delta | `bins/karstd/tests/dns.rs` |
| Privileged | Real netns, real TUN, real `systemd-resolved`; apply, revert, kill-and-recover | `bins/karstd/tests/dns_host.rs`, new `just test-dns` in `test-privileged` |
| Leak | Hostile upstream sees no mesh question | `bins/karstd/tests/dns_leak.rs` |
| Aquifer | One of the twelve topologies resolves a peer by name and opens the TCP connection to the resolved address rather than a literal | `bins/karstd/tests/aquifer.rs` |

The aquifer row is the one that proves the feature end to end, and it is the
cheapest of the six to add because the topology already exists. Do it in W6,
not W7.

## 10. Exit criteria

1. A node resolves every peer's `<hostname>.<aquifer>.karst.` name to both its
   v4 and v6 mesh addresses, and the reverse.
2. A mesh name is never sent to a non-mesh resolver, proved by a test with a
   logging upstream.
3. Killing the daemon and restarting it leaves the host's DNS configuration as
   it found it, proved after `SIGKILL`.
4. `systemd-resolved`, NetworkManager, and bare `resolv.conf` hosts each pass
   the privileged suite.
5. A split-DNS route resolves an internal name through a resolver reachable
   only over the mesh, and `SERVFAIL`s rather than leaking when that resolver
   is down.
6. Turning MagicDNS off in the console removes the host configuration within
   one netmap poll and leaves the machine's original resolvers working.
