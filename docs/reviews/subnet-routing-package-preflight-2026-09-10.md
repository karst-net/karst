# #109 published-package routing preflight

This is retained **preliminary** evidence for GitHub issue #109, not a claim
that its live six-step acceptance demonstration is complete. It was run on
2026-09-10 in a temporary local network-namespace topology. It did not
inspect, modify, restart, or connect to the Shannon deployment.

## Release material

The candidate was GitHub release `v0.1.0-rc.13`, tag commit
`b752e30da80ac749cb9447a110633b6e2bd7a683`. The following release assets were
downloaded and verified with the release's `SHA256SUMS`:

The detached `SHA256SUMS.asc` also verified against the checked-in release key
(signing subkey fingerprint `95E8 4D07 245E E5CD 73F9 EA0D F07F BCFA 8E79 B334`).

| Asset | SHA-256 |
| --- | --- |
| `karst-client-linux_0.1.0-0.rc.13_amd64.deb` | `3c8d28b7af98cc2e1c2016c089656d1fa99ad1acd604c1236e56fc8e5162bf3d` |
| `karst-relay_0.1.0-0.rc.13_amd64.deb` | `edaf2437f566488d54d474cfccc94c5b0d8fc202f158edf1dd479e1ada52eea8` |

The extracted daemon reported `karstd v0.1.0-rc.13`. The test process used
only `karstd`, `karst`, and `karst-relay` extracted from those packages.

## Isolated topology results

The coordination fixture was compiled from the same signed tag, not from the
post-tag checkout. This matters: a current fixture contains the later SSH
policy fields in the authenticated netmap hash, which rc.13 correctly rejects
as a hash mismatch. Matching the fixture to the released wire contract avoids
calling a deliberate cross-version rejection a routing regression.

| Namespace row | Result | Elapsed | What it demonstrates |
| --- | ---: | ---: | --- |
| `a_recipient_reaches_a_subnet_entirely_through_its_peers_gateway_forwarding` | pass | 10.99 s | Recipient reaches an otherwise isolated destination through the packaged gateway. |
| `a_recipient_reaches_the_internet_only_after_locally_consenting_to_an_exit_offer` | pass | 8.52 s | An exit offer is inert until local `karst exit-node use`. |
| `selecting_one_ip_familys_exit_route_does_not_activate_the_other` | pass | 3.06 s | IPv4 and IPv6 default-route consent is independent. |
| `a_recipients_route_follows_its_effective_gateway_to_a_standby` | pass | 8.16 s | Recipient follows an effective-gateway change to standby. |
| `route_changes_converge_through_push_not_restart` | pass | 9.46 s | Create/update/disable/re-enable/delete all arrive on the push path. |

The last row measured creation at 0.1 s, update at 1.1 s, disable at 0.1 s,
re-enable at 1.0 s, and deletion at 0.1 s, each within its 10-second push
bound.

## Reproduction boundary

`bins/karstd/tests/aquifer.rs` accepts `KARST_AQUIFER_BIN_DIR`. When set, it
requires every launched Karst product (`karstd`, `karst`, and `karst-relay`)
to exist in that one directory, preventing a package check from silently using
a workspace binary. The normal CI path remains unchanged when the variable is
unset.

The rc.13 run additionally used a temporary source archive at the rc.13 tag
for its Go test fixture; this aligns the fixture's control-wire hash with the
published clients. It is a reproducible package compatibility test, not a
substitute for a published control-plane image or console deployment.

## Published rc.14 material

`v0.1.0-rc.14` was published from `5d2cfe3bb6b48464586197d3094e148c68aedf3b`
after this preflight. Its selected Linux packages were checked against the
release manifest and its detached manifest signature verified with the same
checked-in release key.

| Asset | SHA-256 |
| --- | --- |
| `karst-client-linux_0.1.0-0.rc.14_amd64.deb` | `223fef4e2f0b72f37f21851e13a1c5f1c6b9192db9a2a1fe761b55ce9a6bf591` |
| `karst-relay_0.1.0-0.rc.14_amd64.deb` | `82b1946e06d4b53c5c6a3a40e9cdc76be438495f8996ae6708d8650423780260` |

The release's immutable image digests are
`ghcr.io/karst-net/karst-control@sha256:37527716860a2edc18e318a167f4c3b50e68ad7f3f90a56741b8e51d6dc81f8d`
and
`ghcr.io/karst-net/karst-relay@sha256:650818697ed23b3c1fc133bb6774c64b117e1ebce0dbe654065b0e71b1ff1a26`.
This release contains `4bf677e` (`management: promote bootstrap account's
first operator`), removing the administrative blocker described for rc.13.

The five isolated package rows were rerun against these rc.14 packages and
passed: subnet forwarding (5.40 s), explicit exit consent (8.63 s),
single-family default-route consent (3.15 s), effective-gateway standby
selection (8.27 s), and pushed create/update/disable/re-enable/delete
convergence (11.46 s total). The latter measured 0.1 s, 0.1 s, 1.2 s, 0.0 s,
and 0.1 s respectively, all within its 10-second bound. These remain local
namespace tests, not the required real control-plane demonstration.

## Still required before closing #109

- Run the actual six-step drill against published client packages **and**
  published control/relay artifacts through the real console and management
  API.
- Demonstrate allowed and denied recipients, injected source-spoof rejection,
  a real selected-gateway loss and recovery, and control/relay survival under
  active IPv4 and IPv6 exit routing.
- Revoke the policy and disable offers, retaining before/after route,
  nftables, and host-state snapshots, packet captures, console/API evidence,
  release image digests, and withdrawal/failover timings.

The isolated rows above reduce release-package risk, but intentionally do not
close the issue.

## Local published-control-plane exercise (rc.14)

After rc.14 was published, a separate temporary Docker Compose project was
created on the local host. Its control, relay, identity-provider, and TLS edge
ports were bound only to loopback. It used the published control and relay
image digests above and package-derived rc.14 client binaries. This project
was distinct from, and made no connection to, the Shannon deployment.

The real identity-provider Authorization Code plus PKCE flow produced an
operator token, and the published control API returned `200 []` for the empty
route list. Four package nodes enrolled and received overlay addresses.

The exercise also established an important policy boundary. Generic management
`/api/policies` records do not compile into Karst packet filters. A versioned
`PUT /api/karst/v1/policy` does; selectors must be the cryptographic peer keys,
not management peer record IDs. After a fresh netmap, the allowed recipient
had two ingress and two egress rules, while the denied recipient had zero
rules and retained default-deny behavior. This verifies that real policy
projection distinguishes the two recipients without recording credentials,
keys, or pins in this document.

### Unresolved transport blocker

The same local topology cannot yet perform the required end-to-end packet
demonstration. Every package peer remains `connecting` with no selected
transport and zero transmitted or received bytes. A permitted ICMP attempt
from the allowed recipient to the gateway overlay address fails; a capture on
the gateway container observed no UDP/51820 datagram during that attempt.
The relay TCP listener itself was reachable from the client container, and
the node logs did not report relay-connection or invalid-node-handle warnings.
At the time of the exercise, all four nodes had no TCP socket to the relay
listener, and the package diagnostic report had no relay-health entry. This
places the failure before either peer discovery or a data-plane handshake: no
home-relay connection was being maintained. The control server logged loading
the relay registry from `KARST_RELAY_REGISTRY_FILE` at startup; whether that
registry actually reached the node's netmap was not checked at the time.

Consequently, this environment cannot truthfully demonstrate data forwarding,
source-spoof rejection, selected-gateway failover and recovery, withdrawal,
or control/relay preservation under active IPv4 and IPv6 exit routing. It was
retained as a reproducible published-artifact investigation record, not as
a completed validation of the packaged claim, pending the root-cause work
below.

## 2026-09-11 root cause and fix

The `karst109rc14-*` containers from the exercise above were left running and
were used, unmodified, to root-cause the transport blocker rather than
re-deriving it from scratch.

**The netmap carried zero relays, not a registry the node ignored.** Reading
`/proc/net/tcp` inside `karst109rc14-allowed` showed exactly one established
TCP connection — the control-plane session (`172.19.0.3:33073`) — and no
socket, past or present, to the relay's overlay address (`172.19.0.4:443`).
`karst status` and the full container log (all four nodes, from boot) contain
zero occurrences of the word "relay" anywhere. `karst-relay` was independently
confirmed reachable: `openssl s_client` from inside the client container
completed a TLS handshake against it directly. So the transport blocker was
never a network-reachability problem; the node was never told the relay
existed.

The control server's own log contradicts the assumption in the entry above:
it loaded the registry from `relays.json` correctly, at `23:49:46` on
2026-09-10 — over three hours before the first client container in this
topology started. The registry was not late; it was not being read.

The cause is in `server/management/internals/karst/control/netmap.go`
(`Handle`'s per-node response assembly). The account-scoped, DB-backed
`RelayStore` is supposed to be an override that a node's static, file/env-
configured `Relays` list falls back to only when the account has not written
its own registry — that is what the field's own doc comment says, and what
`bootstrap.go`'s comment ("static relays remain a fallback for accounts that
have not created an account-scoped registry") promises. The code instead
switched on whether `RelayStore` was *configured*, not on whether its
per-account query returned anything:

```go
relays := h.Relays
if h.RelayStore != nil {
    relays, err = h.RelayStore.NetmapRelays(relayreg.WithAccount(ctx, accountID))
    ...
}
```

`bootstrap.Install` constructs `RelayStore` unconditionally in every real
deployment (`bootstrap.go:187-191,241`), so this condition is always true and
the static list is permanently unreachable dead code — for every account that
has not also called the relay-registry HTTP API, which this reference
docker-compose deployment (by design; see its own comments on `relays.json`)
never does. `TurnStore`/`TurnServers` had the identical pattern one block
below it. Neither path had a test for the empty-store case; the only existing
test for either (`TestNetmapCarriesTurnServersFromTheStore`) covered exclusively
the case where the store already holds an entry.

Fixed by falling back to the static list only when the store's per-account
result is empty, for both `Relays` and `TurnServers`, with two new tests per
store (`TestNetmapCarries*FromTheStore`, already-covered case, and
`TestNetmapFallsBackToStatic*WhenStoreIsEmpty`, the bug this closes) added to
`netmap_test.go`. The `karst109rc14-*` containers were left exactly as they
were — they are pinned to the published `v0.1.0-rc.14` images and are
retained as the pre-fix evidence trail, not patched in place. Confirming this
fix restores relay connectivity requires a new release tag built from a
commit that includes it, then repeating the isolated and live-topology
exercises above against that tag; this session did not do that rebuild-and-
republish cycle, so the six-step demonstration in plan §7 is still open.
