# KarstDNS v1

KarstDNS is the node-local recursive stub authenticated by the Karst control
channel. It is deliberately a policy resolver, not a general-purpose DNS
server: the control netmap supplies the mesh zone and all forwarding policy.

## Name grammar

A mesh name is `<label>.<zone>.`, where `zone` is `KarstDNSConfig.zone` and
`label` is one node's DNS label as assigned by the control server
(`server/dns/dns.go`'s `GetParsedDomainLabel`, `server/management/server/types/account.go`'s
`GetPeerHostLabel`). The node may assume the following about a label it
receives on the netmap; it does not re-derive any of it:

- IDNA/Punycode-converted to ASCII, then reduced to `[a-zA-Z0-9-]` — any other
  character becomes a hyphen — then lowercased and truncated to 58 characters.
- **Unique within the account.** A hostname that collides with an existing
  label is disambiguated by the server with a numeric suffix, `-1` through
  `-999`, appended to the base label.
- Comparison against a query name is ASCII-case-insensitive, without regard
  to a trailing root dot. A label is already lowercase on arrival, so this
  matters only for the name a client asks with, not for the ones a peer
  publishes.

## Configuration

`KarstDNSConfig` is carried in every non-unchanged netmap response. `zone` is
the authoritative mesh suffix; `magic_dns` controls whether host integration
claims that suffix. `nameservers` are global upstreams in preference order.
`routes` are suffix-specific upstreams. Addresses include their UDP/TCP port.

The server projects only enabled nameserver groups that apply to the receiving
peer. Primary groups become global upstreams; non-primary group domains become
split routes; groups that enable search domains contribute their domains. DNS
configuration is part of `netmap_version` in KARST-CONTROL v1 §5.5, so an
enable, disable, or resolver change reaches a node on its next poll.

## Resolution policy

Names are compared ASCII-case-insensitively, without a trailing root dot.
Questions are echoed in their original wire form. The resolver refuses a query
with `RD=0`.

| Question | Result |
| --- | --- |
| A/AAAA for a known `hostname.zone` | authoritative mesh records, TTL 60 |
| A/AAAA for an unknown name under `zone` | authoritative NXDOMAIN |
| Other type for a known mesh name | authoritative NOERROR/NODATA |
| PTR for an allocated `100.64.0.0/10` or ULA mesh address | authoritative PTR |
| PTR for an unallocated address inside those ranges | authoritative NXDOMAIN |
| Matching split-DNS suffix | forward only to that route |
| Any other name | forward only to global or preserved host upstreams |

Mesh names and in-range mesh reverse names are never forwarded. A failed split
route produces SERVFAIL; it never falls back to global upstreams. The mesh
zone takes precedence over every split route. A route that covers the mesh
zone is rejected. An upstream equal to the stub address is rejected at config
time to prevent recursion.

## Transport

The authoritative response TTL is 60 seconds. The daemon listens on UDP and
TCP and uses the requester's EDNS payload limit for UDP truncation, setting TC
when required. The wire codec is hickory-proto; forwarding, route selection,
caching, and host configuration remain Karst-owned policy.

In kernel-TUN mode the listener is a host socket bound to the configured stub
address. In userspace mode both listeners live inside the encrypted overlay
stack instead; no host socket is opened and host DNS integration is always
`none`. A userspace node therefore cannot replace the host's working resolvers
with an address that only overlay peers can reach.

## Host safety

Host integration is transactional. Before changing host DNS the daemon writes
a revert record to `/run/karst/dns-revert` (resolv.conf's original bytes) or
`/run/karst/networkmanager-dns-revert` (NetworkManager's applied-connection
snapshot); on startup, or when `karst dns revert` is run without a daemon at
all, it restores any still-applied record before applying new configuration.
A normal stop invokes the same revert path, via the systemd unit's
`ExecStopPost=` (`deploy/systemd/karstd.service`). The Linux integration
order is systemd-resolved, NetworkManager, then an atomic resolv.conf
rewrite. The latter preserves a symlink target by copying the original
contents rather than moving the link. `systemd-resolved`'s own `RevertLink`
needs no durable record: a link's DNS state is scoped to the link itself and
disappears with it.

When `magic_dns` changes from true to false, host integration is reverted in
the same netmap application and the original resolvers remain usable.

## Non-goals

Two things this version deliberately does not do, recorded as decisions
rather than gaps:

- **DNSSEC validation.** The mesh zone is authenticated by the control
  channel — every record in it arrived over an authenticated netmap — not by
  signatures over RRsets, so there is nothing for DNSSEC to add to a mesh
  answer. A forwarded answer is not validated either; it is passed through
  exactly as the configured upstream returned it (see Resolution policy).
- **Encrypted upstream transport (DoH/DoT).** Forwarded queries go out in
  plain DNS over the resolvers `KarstDNSConfig` names, whether that is the
  open internet or, for a split route, a resolver reachable only over the
  mesh. Both are defensible extensions for a later version; neither is
  required for the mesh zone's own authentication, which is what this
  version's threat model depends on.
