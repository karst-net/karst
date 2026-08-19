<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Karst implementation findings

First reviewed 2026-08-15. Re-verified against the working tree on 2026-08-18,
again after the Phase 4 discovery work later that day, and again on 2026-08-19
after the NAT matrix was extended and measured.

This report records defects found by tracing implementation paths and their
tests. It does not treat the plan or source-code comments as proof that a
feature is correct.

All nine original findings are closed. The re-review and the Phase 4 work that
followed it added sixteen more, and fifteen of those are closed — most found by
building the thing the finding above them asked for, and the most recent found
by counting what the test matrix did *not* cover.

**One remains open: 27**, and like 24 before it, it is a decision rather than a
defect — NAT64/DNS64 cannot be added to the matrix without taking on a
dependency, and which one is a project choice. Finding 24 was not a code defect — it recorded that
Phase 4's third exit criterion could not be met by the mechanism the plan named
for it. The recommended restatement was accepted on 2026-08-19 and PLAN.md now
carries both the new wording and the original, struck through.

| # | Severity | Finding | Status |
|---|---|---|---|
| 1 | Critical | Netmap cache sealed with a public-derived key | Fixed 2026-08-15 |
| 2 | High | Identity persistence precedes enrolment authorization | Fixed 2026-08-18 |
| 3 | High | AVEN candidate state unbounded | Fixed 2026-08-18 |
| 4 | High | AVEN never selects a confirmed path | Fixed 2026-08-16 |
| 5 | High | The AVEN integration is not driven by the daemon | Superseded by 10 |
| 6 | Medium | `CallMeMaybe` accepted from any UDP source | Fixed 2026-08-16 |
| 7 | Medium | Tag-collision handling overwrites the existing route | Fixed 2026-08-15 |
| 8 | Medium | Cache-file permissions not repaired on overwrite | Fixed 2026-08-18 |
| 9 | Operational | Public project status is materially stale | Fixed 2026-08-18 |
| 10 | High | Nothing ever sends a `CallMeMaybe` | Fixed 2026-08-18 |
| 11 | High | A released path never reached the datapath | Fixed 2026-08-18 |
| 12 | Medium | No PHREATIC relay data path, so there is no upgrade | Fixed 2026-08-18 |
| 13 | Medium | `karst-control-v1.md` does not describe the wire it now has | Fixed 2026-08-18 |
| 14 | Low | Relay reconnect has no backoff once established | Fixed 2026-08-18 |
| 15 | Medium | A stale configured endpoint pre-empts the relay | Fixed 2026-08-18 |
| 16 | Medium | Relay TLS could not be configured for a self-signed relay | Fixed 2026-08-18 |
| 17 | High | The packet filter is stateless, so no TCP flow completes | Fixed 2026-08-18 |
| 18 | Low | A relay that cannot be reached logs nothing | Fixed 2026-08-18 |
| 19 | High | A node advertises its candidates once and never again | Fixed 2026-08-18 |
| 20 | High | Discovery is asymmetric: only the node that probes first gets a path | Fixed 2026-08-18 |
| 21 | High | Two nodes both behind NATs never get a direct path | Fixed 2026-08-18 |
| 22 | High | A reflexive address refreshed at the NAT's own timeout is a coin flip | Fixed 2026-08-18 |
| 23 | Medium | The tailnet fixture's NAT masqueraded but did not filter | Fixed 2026-08-18 |
| 24 | Operational | Phase 4's third exit criterion is not achievable as written | Resolved 2026-08-19 — criterion restated |
| 25 | Medium | The NAT matrix was missing the common symmetric/port-restricted pairing | Fixed 2026-08-19 |
| 26 | Medium | Vendoring pruned test fixtures a retained test still needed | Fixed 2026-08-19 |
| 27 | Operational | NAT64/DNS64 needs a dependency decision the matrix cannot make for itself | **Open** — needs a decision |

## Open

### 27. Operational: NAT64/DNS64 needs a dependency decision the matrix cannot make for itself

PLAN.md §6 lists NAT64/DNS64 as a matrix row. It is the only unbuilt row that
cannot be built with `nft` alone, because **Linux has no in-tree NAT64**.
nftables translates addresses within a family; NAT64 (RFC 6146) translates
between IPv4 and IPv6 headers, which is a different operation and is not in
mainline. So the row costs a dependency, and which one is a project decision
rather than a test-authoring one.

| Option | What it is | Cost |
|---|---|---|
| `jool-dkms` 4.1.11 | The reference NAT64, an **out-of-tree kernel module** | Builds per kernel. Kernel headers are present here, so it would build on this machine — but every CI image and every contributor's kernel becomes a build dependency, and a DKMS failure surfaces as a test failure rather than as a missing package |
| `tayga` 0.9.2 | **Userspace** NAT64 over a TUN device | No kernel dependency, no DKMS, installs as an ordinary package. Stateless (RFC 6145) with a configured address pool rather than stateful RFC 6146 |
| DNS64 half | `bind9` or `unbound`, both packaged | Cheap either way, and separable from the NAT64 half |

**Recommendation: `tayga`, and only if the row is judged worth a dependency at
all.** The matrix's job is to characterise a *topology*, and what this row needs
to establish is what a node observes when its datagrams cross a
family-translating middlebox — which reflexive address it is given, and whether
that address is usable by a peer. Stateless translation with a pool answers that
as well as stateful translation does, and it costs an ordinary `apt install`
rather than a kernel module in every CI image.

**Against building it at all**, stated because it is the stronger argument than
it first looks: this row measures a topology Karst may not need to traverse. An
IPv6-only node reaching an IPv4-only relay is real, but the relay registry can
name IPv6 relays, and `Nat::Ipv6Direct` already covers the case where both ends
have IPv6. The row's unique content is *mixed-family* peer-to-peer, and the
honest fallback there is the relay, which is already asserted to work by the
UDP-blocked row.

**Not built, pending that decision.** The row is cheap once the dependency is
chosen — the topology is the existing three namespaces with an IPv6 inside and
a translator in the middle — so this is a decision waiting on an answer, not
work waiting on effort.

## Closed

### 26. Medium: vendoring pruned test fixtures a retained test still needed

`server/management/server/auth` failed with a **segmentation fault** inside
`crypto/rsa`, three frames deep in a dependency, on a test that had passed
before the fork was vendored.

The cause was two discarded errors and a missing directory:

```go
keyData, _ := os.ReadFile("test_data/sample_key")
key, _ := jwt.ParseRSAPrivateKeyFromPEM(keyData)
...
tokenString, _ := token.SignedString(key)   // key is nil
```

`314ae66` vendored NetBird "pruned to the management server" and removed
`test_data/`, while keeping the test that reads it. `ReadFile` failed, the
error went to `_`, `ParseRSAPrivateKeyFromPEM(nil)` returned nil, its error
went to `_` as well, and signing with a nil key faulted. The companion
`jwks.json` was missing too, which is why the run also logged "could not get
keys from location" — the HTTP fixture server was returning a 404 page where
JSON was expected.

**This was not caused by any Karst change**, and it was confirmed by running
the same test on `main` before the branch's work, where it fails identically.
It is recorded because it made the README's "155 Go tests" claim untrue and
because it would have been inherited into any future baseline.

**Fixed by removing the fixture rather than restoring it.** The test now
generates a throwaway 2048-bit RSA key per run and serves the matching JWKS
from its own `httptest` handler, so there is no file to go missing and the
failure mode is gone rather than repaired.

Restoring the fixtures was the first fix and it was the wrong one, for a
reason that had nothing to do with the bug: it commits an **RSA private key to
a public repository**. It would be a throwaway used by one test, and it would
still trip secret scanning, and it would still be in the history permanently —
history being the part that cannot be undone later. Generating the key costs a
few milliseconds a run. It was caught before the commit was pushed, which is
the only reason the choice was still available.

The transferable lesson is about pruning rather than about this test. **A
prune that removes data is a change to every test that reads it**, and neither
the compiler nor a passing build catches it: the code still compiles, the file
is merely absent at run time. A vendoring step that drops directories should
be followed by running the suite it pruned, which is what would have caught
this at the moment it was introduced.

### 24. Operational: Phase 4's third exit criterion was not achievable as written

**Resolved 2026-08-19 by restating the criterion**, not by building anything.
The new wording admits an explicit port mapping on either side; the pair
otherwise relays without loss and both nodes report why. The original wording is
kept struck through in PLAN.md so the change is legible. The analysis that
prompted it follows.

PLAN.md's Phase 4 exit reads "a peer behind symmetric CGNAT reaches a peer
behind a different symmetric CGNAT", and the planned mechanism is
birthday-paradox port prediction (`aven-v1.md` §12.4). **Prediction requires the
NAT's port allocation to be predictable, and measurement says the ones that
matter are not.**

One socket, twenty-four destinations, a fresh topology per flavour:

| nftables rule | Distinct external ports | Adjacent steps within ±8 |
|---|---|---|
| `masquerade` | **1** of 24 | n/a — one mapping, reused |
| `masquerade fully-random` | **24** of 24 | **0** of 23 |
| `masquerade random` | **24** of 24 | **0** of 23 |

The two symmetric flavours scatter across the whole ephemeral range with no
locality whatever — sample deltas of −48061, +47375, +30529. There is no window
of any practical width to probe. This is not a Linux quirk to be routed around
either: RFC 6056 *recommends* unpredictable transport-port selection precisely
so that off-path attackers cannot guess a flow, so the NATs that are hardest for
us are the ones that are behaving correctly.

Two further points make prediction weaker than it first appears, both of which
hold even against a NAT that allocates sequentially:

1. **A port-restricted symmetric NAT filters on source port as well as
   destination.** Guessing the peer's external port correctly is not enough —
   our probe still arrives from a source port the peer's NAT never saw, and is
   dropped. The coincidence needed is two-sided, not one-sided, which is a
   different and much worse probability than the birthday argument assumes.
2. **§7.5's normative rate rule forbids the technique's shape.** "A node MUST
   NOT emit more probe traffic to a peer than that peer has authenticated
   itself to it." A blast of *N* probes on the strength of one `CallMeMaybe`
   violates it, and relaxing it hands an authenticated-but-malicious peer — the
   one §1.1 explicitly allows inside the tailnet — an *N*-fold amplifier aimed
   at any address it cares to name.

**What is and is not affected.** A symmetric NAT goes direct against a
publicly-reachable peer (row 4) and against an address-restricted cone (row 5).
It fails against another symmetric NAT (row 6) **and against a port-restricted
cone (row 8)** — and row 8 is the common real pairing, a CGNAT subscriber
talking to somebody on a home router.

**Those two failures are not the same, and an earlier version of this finding
wrongly treated them as one.** Published analysis of the technique splits them:

| Pairing | Technique | Result |
|---|---|---|
| hard ↔ easy (row 8) | 256 sockets one side, 256 random probes the other | **64%, under 2 seconds** |
| hard ↔ hard (row 6) | same, both sides | **0.01% after 20 seconds**; 99.9% needs ~170,000 probes each side |

So the recommendation below applies to **row 6 only**. Row 8 is winnable and the
measurement above does not argue against it — that measurement shows there is no
*sequential* structure to predict, which rules out the cheap heuristic and
leaves the random-probe method, whose arithmetic is favourable precisely because
only one side is randomising.

Row 8 carries an architectural cost that belongs in the estimate. The technique
needs the hard side to hold **many sockets simultaneously**, because a socket is
what earns a distinct external mapping toward the one address the easy side is
reachable at; many destination ports from one socket does not substitute,
because a port-restricted symmetric NAT admits a packet only from the exact
source its mapping was created toward. That is in tension with `aven-v1.md` §4's
single shared socket, and it means the winning socket has to become the datapath
socket — a `karstd` datapath change, not a `karst-disco` one.

**Recommended resolution — a decision for the project, not for this report.**
Restate the criterion around what is achievable and verifiable:

> A peer behind symmetric CGNAT reaches a peer behind a different symmetric
> CGNAT **when at least one of the two NATs offers an explicit port mapping
> (PCP, NAT-PMP or UPnP-IGD)**; otherwise the pair falls back to the relay
> without loss, and both nodes report the reason.

Port mapping is already in the phase's work list, in the same bullet as
prediction. It is deterministic where prediction is probabilistic, it is
testable against a third-party server rather than one we wrote (`miniupnpd`
speaks NAT-PMP and PCP and drives nftables), and it produces a stable
advertisable port instead of a guess. **The recommendation is to build port
mapping and drop prediction**, rather than to build both.

### 25. Medium: the NAT matrix was missing the common symmetric/port-restricted pairing

The tailnet fixture covered seven topologies and reported five direct. It had a
symmetric NAT facing nothing, facing an address-restricted cone, and facing
another symmetric NAT — but **not facing a port-restricted cone**, which is the
single most likely real pairing: a CGNAT subscriber talking to somebody on an
ordinary home router.

The omission was not neutral. It let PLAN.md state that row 6 was the only case
needing further work, which is wrong, and it inflated the direct-connection rate
from 63% to 71% by leaving out a row that fails.

It also hid the more useful half of the analysis. Row 6 (hard/hard) is not
winnable; row 8 (hard/easy) is, at 64% in under two seconds by published
analysis of the same technique. Treating them as one case meant the achievable
one was being conceded along with the unachievable one.

Fixed by adding `Shape::SymmetricAndPortRestricted` and the row
`a_symmetric_nat_and_a_port_restricted_peer_stay_on_the_relay`, which measures
the failure rather than assuming it: the pair establishes on the relay and is
held under observation for 75 seconds, failing if either end ever claims a
direct path. The expectation flips when the technique is built.

The general lesson is the one finding 23 already taught in a different form. A
matrix is an argument about *coverage*, and a missing row is invisible from
inside it — the seven that existed all passed, and the number they produced was
wrong because of the one that did not exist.

### 8. Medium: cache-file permissions were not repaired or checked on overwrite

**Fixed 2026-08-18.** `write_secret_bytes` now writes a newly created `0600`
temporary file beside the cache, synchronizes it, and atomically renames it
over the old file. A failed write leaves the previous cache intact; a
successful write repairs a pre-existing permissive mode. `load_cache` now
checks the mode and refuses an existing group- or world-readable cache.

`overwriting_a_readable_secret_repairs_its_permissions` and
`a_readable_cache_is_refused` cover the write- and read-side cases.

### 2. High: identity persistence and data-plane key rotation preceded enrolment authorization

**Fixed 2026-08-18.** `LoginHandler.Handle` now validates identity and
data-plane keys without writing, authenticates any OIDC token, and calls
`LoginPeer` before `Nodes.Register` creates an identity or rotates its keys.
The registration path repeats validation before it writes, so direct callers
retain the same safety check.

`TestRejectedLoginDoesNotPersistAnIdentity` and
`TestRejectedLoginDoesNotRotateDataPlaneKeys` pin the two failure paths:
invalid credentials cannot create an orphan record or replace the keys of an
already registered node.

### 13. Medium: `karst-control-v1.md` did not describe the wire it had

**Fixed 2026-08-18.** `spec/karst-control-v1.md` §5.4 now specifies
`disco_key` (field 9 of `KarstNetmapPeer`) and the `KarstRelay` registry
(field 13 of `KarstNetmapResponse`), including relay pinning and replacement
semantics. §5.5 gives the ordered, length-prefixed content-hash construction,
including its `karst-relays` separator and relay fields.

The vector generator and generated JSON now carry an explicit compatibility
note: version values before the relay hash term are intentionally incompatible.
That makes the five regenerated values an explained protocol change rather
than unexplained fixture churn.

### 9. Operational: the public project status was materially stale

**Fixed 2026-08-18.** `README.md` said "Early Phase 1" and "no daemon, no
tunnel, no control plane", and listed handshake, datapath, relay, DNS, control
plane and console as not started. Five of those six existed and four had
end-to-end tests.

- Impact was two-sided, and the second half is the one that mattered: users,
  reviewers and security researchers received a false picture of the deployment
  and attack surface, *and* the document understated what a reader was being
  invited to review. A security project that undersells its surface gets less
  scrutiny of it.
- It now states the actual status (pre-alpha, Phase 4 of 7), what runs, the test
  and model counts, and six named limitations with spec references — including
  the ones this phase added, such as Ponor deriving no session key and
  symmetric-to-symmetric NAT not connecting.
- It also links [FINDINGS.md](FINDINGS.md) directly, so the open defects are one
  click from the front page rather than discoverable only by reading the tree.

Two claims in the old text were wrong in the other direction and were corrected
while checking rather than copied forward: the minimum Rust version (1.85 in the
README, 1.88 in `Cargo.toml`) and NetBird described as a possible fork
"if the Phase 0 spike confirms it", which it did, in Phase 3.

### 21. High: two nodes both behind NATs never got a direct path

**Found 2026-08-18** by extending `tests/tailnet.rs` to the topology that is not
exotic: two laptops on two home networks. It is the ordinary deployment and it
never left the relay. **Fixed the same day** by building `aven-v1.md` §7.6.

Neither node could learn its own **mapped** address, so neither could advertise
one the other could reach:

- Its interface addresses are private and unroutable from the far side.
- `Pong.observed` (§7.2) would supply a mapped address, but only once a probe
  has crossed — and no probe could cross, because neither had an address to
  probe. The reflexive mechanism needed a working path to bootstrap a working
  path.
- The relay could have told a node what it looks like from outside, and could
  not: Ponor had no frame for an observed address, and the relay speaks TCP,
  whose NAT binding is not the UDP one AVEN needs.

**The fix is a reflector**: a UDP service a relay MAY run, keyed by a 32-byte
`reflect_key` the relay mints per Ponor connection and hands over inside TLS
after its ML-DSA-65 signature has verified. A node sends `Reflect` **from the
socket PHREATIC and AVEN already share** and is told the source address the
reflector saw.

Three decisions in it are worth keeping:

- **Request and reply are the same size — 65 bytes each** — which is what the
  nineteen bytes of `pad` in `Reflect` buy. The natural encoding, `Ping`/`Pong`'s
  shape, gives 46 in and 65 out: a factor of 1.4, which is small, and small is
  not the same as one. An amplification factor above 1.0 on a service every
  relay in a public pool operates is a contribution to somebody else's attack.
- **The reflector answers to the source address**, which is the *inverse* of
  §7.1's rule for `Pong` and not a contradiction of it: a `Pong` answers a
  question about the peer's address, where trusting the source lets an attacker
  redirect a probe; a `Reflection` answers a question about the sender's own,
  where the source is the entire content of the answer.
- **The key's lifetime is the connection**, with no expiry field and no refresh
  message. Both ends already agree on when a connection ends; every additional
  lifetime mechanism would be a second opinion about that.

Verified end to end: `two_nodes_behind_nats_punch_through_with_a_reflector`
passes in **ten seconds**, with each node holding the other's *mapped* address
rather than its private one. Checked against the defect — removing `[reflect]`
from the relay's configuration fails that row **and only that row**, because
every other topology reaches a direct path without it.

Cost, stated: this closes the NAT-to-NAT case for endpoint-independent mapping
and does **not** close symmetric-to-symmetric, which still needs port
prediction. A server-reflexive address is the mapping toward the reflector, and
on a symmetric NAT no peer can use it.

### 22. High: a reflexive address refreshed at the NAT's own timeout is a coin flip

**Found 2026-08-18** while building finding 21's fix, by packet capture rather
than by reasoning — and it is the more transferable of the two.

The first implementation refreshed `Reflect` every **30 seconds**, matching
§7.5's other repeat intervals. Linux's `nf_conntrack_udp_timeout` is also
**30 seconds**. So each refresh raced the expiry: the binding survived some
intervals and was rebuilt with a *different* external port on others, and the
node's own log showed its mapped port alternating between `51820` and a random
one on an otherwise idle flow.

The consequence is worse than a wasted datagram. The node advertises an address
it is no longer sending from, its peers probe a port nothing is listening on,
and the pair never converges — which is exactly the symptom finding 21 was
supposed to have removed.

An isolated three-namespace reproduction was built to test the alternative
explanations first, and it cleared them: at six-second intervals the mapping is
stable, at thirty it is stable *in isolation*, and neither an unsolicited peer
probe nor six concurrent destinations from the same socket disturbs it. What
the capture then showed was one flow, one socket, and a mapping that moved
anyway.

- Fix: `REFLECT_INTERVAL_MS` is **10 seconds**, and `aven-v1.md` §7.5 now states
  the rule rather than the number — *a reflexive address is only true while the
  binding that produced it is alive, and nothing tells the node how long that
  is.* Refresh at well under the shortest timeout expected, not at it.
- Generalisation worth keeping: **a keepalive interval equal to the timeout it
  defends against is not a keepalive.** It is a race, and it fails
  intermittently, which is the hardest way for it to fail.

### 23. Medium: the tailnet fixture's NAT masqueraded but did not filter

**Found 2026-08-18** by packet capture, after finding 22's fix left the pair
still on the relay. A fixture defect rather than a product one, and recorded
because it made a port-restricted cone behave like a symmetric NAT — which would
have been read as a product limitation.

`nat_in_front_of` installed a `masquerade` rule and nothing else. So a peer's
probe to the NAT's outer address was delivered **to the NAT namespace itself**,
which has no listener: the kernel answered ICMP unreachable and, the part that
matters, *confirmed a conntrack entry for it.* That entry occupied the reply
tuple `(peer:51820 → outer:51820)`, so when the inside host later sent to that
same peer, masquerade could not keep port 51820 and allocated a random one.

The capture is the whole finding in two lines — the same node, the same socket,
two destinations:

```
10.98.0.3.51820 > 10.98.1.2.51820     ← probing the peer's private address
10.98.0.3.26444 > 10.98.0.2.51820     ← probing the peer's mapped address
```

Each side then advertised the address it learned from the reflector while
sending from a different port, and the two directions never met.

- Fix: an `input` chain that accepts `established,related` on the outer
  interface and drops the rest. A DROP at filter priority 0 runs well before
  conntrack's confirm hook, so the entry is never confirmed and the tuple is
  never taken. That is also what a real NAT does.
- Why it matters beyond the fixture: **a masquerade rule alone is not a NAT.**
  `crates/karst-disco/tests/nat_matrix.rs` already pins the forwarded half of
  this — *"an unsolicited datagram does not cross"* is what makes a topology a
  NAT rather than a router — and the tailnet fixture had been built without the
  equivalent for traffic addressed to the NAT's own address.
- With it, the doubly-NATed row converges in ten seconds instead of never.

### 20. High: only the node that probed first ever got a direct path

**Found and fixed 2026-08-18**, by codifying the live run as
`bins/karstd/tests/tailnet.rs` — the third defect that test has produced, and
the second it produced before it first passed.

Nothing learned a candidate from an incoming probe. A node acquired candidates
from exactly two places: the endpoint its netmap named, and a `CallMeMaybe`. So
in the ordinary case where one side advertises first:

1. A advertises. B learns A's address.
2. B probes A. A answers, because it holds the disco key — answering needs no
   candidate of its own.
3. B confirms a path and goes direct. **B then stops advertising**, correctly:
   it has what it needed.
4. A has no candidate for B, and nothing will ever give it one.

A stayed on the relay indefinitely while B was direct. Observed on two real
daemons, and then reproduced by the test in 150 seconds of not converging.

**The address an authenticated `Ping` arrived from is now a candidate.** It is
better evidence than a `CallMeMaybe`, which is a claim: this datagram actually
made the journey. It is recorded as a *candidate* and not a path, so confirming
it still takes this node's own `Ping` and the `Pong` that answers — §7.1 is
untouched and a peer that lies here spends probes and nothing else.

Note the interaction with finding 19, because the two look similar and are not.
This is about a node that has *no* candidate and no prospect of one; 19 is about
an advertisement that was sent and lost. The tailnet test catches this one and
does **not** catch 19, because the fixture drops nothing — 19 is carried by
`karst-disco`'s unit tests, where loss can be expressed. Neither fix subsumes
the other.

### 19. High: a node advertised its candidates once and never again

**Found and fixed 2026-08-18**, from an asymmetry in the live run: one daemon
reached `transport = "direct"` and the other sat on `"relay"` for minutes.

`Engine::should_advertise` was edge-triggered on `advertise_pending`, which
`set_local_candidates` sets only when the candidate list actually *changes*.
On a host whose interfaces are stable that happens once, at startup. Measured
directly: one advertisement on the first poll, and **zero** over a simulated
hour.

An advertisement is a datagram and datagrams are lost. A peer that missed the
only one ever sent never learns where its counterpart is, and the pair stays on
the relay indefinitely. The ways to miss it are all ordinary:

- The peer had not yet been given the disco key — it enrolled later, so at the
  moment the advertisement was relayed it held no key for the sender and
  dropped it. **This is what a node joining an existing tailnet does**, and it
  is exactly what was observed.
- The peer restarted.
- The relay was briefly unavailable.

`should_advertise` now also fires while no direct path is confirmed, at the
re-probe interval. `spec/aven-v1.md` §7.5 gained the rule as a MUST NOT: a node
must not advertise only on change.

**The reasoning was already in the file, one function above.** The re-probe
sweep repeats itself and says why — *"without this a node that settles on a
relay at boot stays there until something else disturbs it"*. Telling a peer
where you are and asking where it is are the two halves of one job, and only one
of them was being repeated. The tests pin both directions: making it edge
triggered again fails `a_node_with_no_path_keeps_saying_where_it_is`, and
removing the stop condition fails `a_settled_pair_stops_advertising`.

**Why no test caught it:** the existing test asserted the *old* rule — "nothing
changed, so nothing more is said" — and was correct about the property it was
protecting, which is that re-enumerating interfaces must not produce an
advertisement per poll. That property survives; the baseline it assumed did not.
A test can be right about its subject and wrong about the world.

### 17. High: the packet filter was stateless, so no TCP flow could complete

**Found and fixed 2026-08-18**, by two real daemons carrying real traffic for
the first time. Every layer's unit tests passed and the feature did not work.

`PacketFilter::evaluate` was a pure function of `(rules, peer,
destination_port)`. A rule therefore matched a packet's **destination** port and
nothing else, so for the policy PLAN.md §4.3 uses as its own example —
`{ "action": "accept", "src": ["group:sre"], "dst": ["tag:prod:22,443"] }`:

- `A → B:22` has destination port 22. Permitted.
- `B:22 → A:54321`, the reply, has destination port 54321. **Denied.**

Observed end to end: A sent 7 packets, B received all 7 and its egress filter
denied 12 — the SYN-ACK and its retries. Both ends reported
`state = "established"` and `transport = "direct"` throughout. The tunnel was
working perfectly and carrying nothing.

`crate::flow` now tracks connections per peer. A flow is recorded **only when a
rule permits a packet**, so nothing an attacker sends can open one — a packet no
rule permits is dropped before it gets there — and the flow then permits exactly
the reverse five-tuple.

**The stateless alternative was tempting and is wrong**, which the tests are
built to show. "Permit a packet whose *source* port matches a rule" needs no
state at all and would have made a TCP connection work. It also grants a
permitted peer the right to reach **every** port on this node by choosing its
source port — the old hole in "allow anything from port 53". A grant of
`A → B:22` must not become a grant of `B → A:*`. Substituting that shortcut
fails three of the five tests in `tests/acl_flows.rs`, and the two it fails
first are the security ones.

Three details worth keeping:

- **Per peer, behind its own lock**, so the datapath keeps the property §3.4
  measured: two peers never contend. The critical section is a hash lookup, and
  it is taken beside the session lock this path already takes rather than being
  a new kind of contention.
- **Bounded and expiring.** Flows are state a peer's traffic makes this node
  allocate, so they are capped at 4096 per peer with a two-minute idle timeout,
  reclaiming expired entries before evicting live ones.
- **Cleared on reconfiguration.** A flow is a cached permission. Sessions and
  endpoints are deliberately carried across a netmap change so an unrelated edit
  does not cost a rehandshake; carrying the flow table with them would mean an
  ACL edit that withdrew access left every connection it withdrew still
  working — a revocation that does not revoke.

Verified on the setup that found it: `RECEIVED: hello over the tunnel`, with
`acl_denied_out = 0` at both ends where it had been 12.

**The lesson is about the test, not the code.** Nine NAT matrix rows, six relay
tests, four discovery tests and 174 unit tests did not find this, because none
of them had a *reply* — and a reply only exists once something upstream is
holding a connection open. `tests/acl_flows.rs` is the test that should have
existed, and it is four lines of packet construction.

### 18. Low: a relay that could not be reached logged nothing

**Found and fixed 2026-08-18**, in the same run. `relay_worker` treated a failed
`connect` as a reason to back off silently, so a node with a mistyped
`relay_ca_file`, an unreachable relay, or an identity absent from the relay's
roster looked exactly like a node with nothing to say. The only symptom was a
peer stuck on `state = "connecting"`, which names none of those.

It cost a diagnosis immediately: the first end-to-end run failed with no output
at all, and adding one line produced `invalid peer certificate:
CaUsedAsEndEntity` — a fixture using a CA certificate as the relay's leaf.

Now reported once per outage rather than once per attempt, with the relay's
address and the error, plus a line when it comes back.

### 17. High: the packet filter is stateless, so no TCP flow can complete

**Found 2026-08-18**, by two real daemons carrying real traffic for the first
time. Every layer's unit tests pass, and the feature does not work.

`PacketFilter::evaluate` is a pure function of `(rules, peer,
destination_port)` — no connection state, no `&mut self`, no map. A rule
therefore matches a packet's **destination** port and nothing else. So for the
policy PLAN.md §4.3 uses as its own example:

```
{ "action": "accept", "src": ["group:sre"], "dst": ["tag:prod:22,443"] }
```

- `A → B:22` has destination port 22. Permitted.
- `B:22 → A:54321`, the reply, has destination port 54321. **Denied.**

Observed end to end: node A sent 7 packets (`tx_packets = 7`), node B received
all 7 (`rx_packets = 7`) and its egress filter denied 12 (`acl_denied_out = 12`
— the SYN-ACK and its retries). The TCP connection timed out. Both ends
reported `state = "established"` and `transport = "direct"` throughout: the
tunnel was working perfectly and carrying nothing.

- Location: `bins/karstd/src/filter.rs`, `PacketFilter::evaluate`
- Impact: **no TCP connection can complete under any port-scoped ACL.** That is
  the primary use of the feature, and the example in the plan. A policy with no
  port scoping (`dst: ["*:*"]`) works, which is why nothing noticed.
- Why no test caught it: the filter's own tests assert that a rule permits and
  denies the packets it should, and it does. `tests/datapath.rs` drives engines
  with `PacketFilter::unrestricted`. Nothing exercised a *reply*, because a
  reply only exists when something upstream is holding a connection open.

PLAN.md §4.3 says the policy language is "Tailscale-compatible in shape so the
concepts transfer". Tailscale's filter is stateful — return traffic on a flow it
permitted is allowed — and that is load-bearing rather than incidental. Shape
compatibility without it means a policy that reads identically behaves
completely differently.

**Not fixed here, deliberately.** Connection tracking in the datapath is a
design decision with real consequences: where the state lives, how it is bounded
against an attacker who opens flows, and how it interacts with a datapath whose
whole performance story is that peers do not share a lock (§3.4). The narrower
alternative — permit a packet whose *source* port matches an egress rule — is
two lines and is not obviously right either, because it grants more than the
policy says. Either deserves to be chosen rather than patched in.

### 15. Medium: a stale netmap-configured endpoint pre-empted the relay

**Found while building finding 12's relay path, fixed 2026-08-18.**
`Engine::via` preferred a direct endpoint whenever one existed, and a
netmap-configured endpoint exists from startup — so a peer whose *published*
address had gone stale was unreachable even with a relay configured and the
peer connected to it.

The root cause was ownership: **nothing owned the configured endpoint.** AVEN
probed it (`Disco::reconcile` seeded it as a candidate) and so knew perfectly
well that it did not answer, but `release_endpoint` withdrew only paths AVEN had
*installed*, and this one arrived from the control plane. The information
existed and no code could act on it.

Discovery now **adopts** the configured endpoint at reconcile — records it as
the endpoint the datapath is holding — which is what gives it the standing to
withdraw it. Probing an address nobody owns produces a measurement and no
consequence.

Two things fell out of it, both simplifications:

- **Release is gated on discovery having given up**, not on "no path chosen".
  `Engine::exhausted` is §7.5's schedule run to its end — immediately, then
  100/300/900. Before that, "nothing chosen" means "not confirmed yet", which is
  the state every peer is in for the second of probing after every roster
  change; withdrawing there would drop a working endpoint onto the relay each
  time the netmap moved. Giving up is safe to act on precisely because it is not
  permanent: the re-probe sweep retries every candidate every 30 seconds, so a
  peer that comes back is found again without anything having to remember it was
  written off.
- **`PathChange::Release` lost its `fallback` field.** Reverting an
  AVEN-confirmed path to the configured endpoint only made sense while that
  endpoint was exempt from discovery. It is not: it is a candidate like any
  other, so by the time a release fires it has been probed and given up on too.
  Reverting would hand the datapath an address discovery had just disproved. The
  release now clears the endpoint and `via` falls through to the relay — one
  rule instead of two.

A peer with **no** disco key is untouched and keeps its configured endpoint,
which is correct rather than an exception: no key means no discovery, ever
(`aven-v1.md` §5.1), so there is nothing to learn from and nothing that could
responsibly take it away. That is also what keeps a static TOML roster working.

The test that pins it drives the real wiring — reconcile, poll to exhaustion,
withdrawal reaching `via`. An earlier version called `add_peer_at` directly and
passed with the adoption removed, which the mutation check caught.

### 16. Medium: relay TLS could not be configured for a self-signed relay

**Found and fixed 2026-08-18** while preparing an end-to-end test against a real
relay, which could not be written because the node had no way to trust one.

`relay_tls::client_config` loaded the operating system's trust store and nothing
else. `ponor-v1.md` §4.2 names three realistic self-hosted deployments and the
system store covers one of them: an internal CA can be installed as a system
root, a certificate for a different hostname is handled by the netmap's
`tls_server_name` — and a **self-signed relay certificate** could only be used
by making that one host a trust anchor for every TLS connection the machine
makes, which is a much larger grant than the problem needs.

- Location: `bins/karstd/src/relay_tls.rs`
- Impact: a self-hoster following the spec's own description of the common case
  had no working configuration. Not a security hole — the failure was closed,
  not open — but a gap between what the specification describes and what the
  implementation permits.

`[control] relay_ca_file` now names a PEM bundle trusted *in addition to* the
system roots. It cannot weaken relay authentication and the reason is
structural rather than a promise: §4.2 already makes the certificate
insufficient on its own, and the ML-DSA-65 identity pinned by the netmap is
what names the relay. What a CA here decides is which certificates the *hop*
will accept.

Two details worth keeping. A bundle that parses to **no** usable certificate is
an error rather than a silent no-op — the alternative is a node configured to
trust a relay's CA that silently does not, reporting every connection as a
verification failure that names the wrong problem. And native roots became
optional only when a bundle supplied some, because a container with no
`ca-certificates` package is a normal place to run a node against a self-hosted
relay, and refusing there would make the setting useless exactly where it is
most needed.

### 10. High: nothing ever sent a `CallMeMaybe`

**Found 2026-08-18, fixed the same day.** Superseded finding 5, which reported
that the daemon did not drive AVEN at all. By the time of the re-review it did —
disco keys loaded from the netmap, the timer polling the scheduler, a Ponor
connection delivering inbound advertisements, confirmed paths reaching the
datapath. The outbound half was missing: `set_local_candidates` had no caller,
`Disco::poll` discarded `Action::Advertise`, and `relay::Connection::send_packet`
was never called. Two nodes running that build never exchanged candidate lists,
so simultaneous open could not occur and discovery was confined to endpoints the
coordination server already knew — the case that did not need AVEN.

Three pieces closed it:

- **Candidate gathering.** `karst_tun::local_addresses` dumps `RTM_GETADDR`;
  `karstd` removes its own overlay addresses. The split is deliberate: scope,
  tentative and deprecated are facts about an address, while "is this the
  tunnel's own address" is a fact only the daemon knows.
- **Reflexive addresses**, §7.2. A node behind a NAT learns its mapped address
  only from a peer that answers a probe.
- **Advertisement carriage.** `Disco::poll` returns relayed messages alongside
  UDP probes; a bounded queue hands them to the relay worker, which owns the
  only Ponor connection.

**`tests/rendezvous.rs` is the part worth keeping.** It runs both ends and moves
the bytes between them, and it exists because every layer below had passing unit
tests for weeks while the join did nothing. The fixture reproduced the same
class of bug immediately: its first draft carried relayed advertisements and
dropped the probes `poll` returned alongside them, and the symptom was one node
confirming a path while the other silently did not.

Two rules came out of implementing it and are now in `spec/aven-v1.md` §7.2:
interface addresses are not displaced by reflexive ones, and where several peers
report, the most-reported wins. The list a node builds goes to *every* peer, so
without the first rule one peer supplying sixteen fabricated `observed` values
decides what this node tells everybody else about itself.

### 12. Medium: there was no PHREATIC relay data path

**Fixed 2026-08-18.** The relay carried discovery messages for a data plane that
had no relay concept at all, so a peer with no direct address was unreachable
rather than relayed — and "seamless relay→direct upgrade" had nothing to upgrade
*from*.

`Output` now names a destination rather than an address, and `Engine::via` is
the single place that chooses between them:

```
a direct endpoint if there is one, the relay otherwise
```

**The upgrade and the fallback are that one rule read at different moments**,
which is why it is two lines rather than a state machine. AVEN already owns
whether a direct endpoint exists — it installs one on a confirmed path and
withdraws it when the path stops answering — so nothing had to be coordinated
between the two. Deciding it in one place is what keeps that true: the previous
code asked `endpoint(peer)` in four places and dropped the packet when it was
`None`, and a relay arm added to three of them would have been a peer that could
receive but not send.

Three things came out of building it that are worth keeping:

- **`inbound_from_relay` is a separate entry point, not a flag.** It learns no
  endpoint (the source is the *relay's* address, and installing it would point a
  peer's traffic at a TLS port that is not a PHREATIC listener), attributes by
  the relay-stamped source rather than by address, and reassembles under a key
  disjoint from every UDP source — which matters exactly during an upgrade, when
  a relayed and a direct stream from one peer are briefly both in flight.
- **A relayed handshake must name the peer the relay says sent it.** Two
  independent bindings — Ponor authenticated a node id, the AEAD resolves a
  `peer_id_hint` — and requiring them to agree is what stops one admitted peer
  from replaying another's handshake under its own relay identity. The test that
  pins it uses a peer the node *holds a key for*; a stranger is refused one step
  earlier by the lookup, so a test using one passes with the check deleted.
- **The connection is split so the two directions cannot block each other.** A
  worker alternating between reading and draining a send queue adds its polling
  interval to every relayed packet, and once this path carries tunnel data that
  interval is the tunnel's latency.

The queue from the datapath to the relay worker is bounded and **drops rather
than blocks**, because these calls happen on the threads carrying the tunnel and
waiting on a dead relay would turn a relay outage into a total outage —
`ponor-v1.md` §7.3 makes the same choice one hop further on. The drops are
counted and reported, because the previous version of this mistake was silent.

`bins/karstd/tests/relay_path.rs` drives both ends: a peer with no endpoint is
reachable, the same peer with no relay is still correctly undeliverable, and a
direct path displaces the relay and gives it back without disturbing the
session. Finding 15 records what this does *not* cover.

### 14. Low: relay reconnection had no backoff once established

**Fixed 2026-08-18** while adding the outbound relay path. Reconnection is now
exponential from one second to a minute, and **the counter resets on a
connection that is actually established, not on the attempt** — resetting on the
attempt is what turns a relay that accepts and immediately closes into an
unthrottled reconnect loop from every node at once, which is the load pattern
most likely to keep it down.


### 1. Critical: the encrypted netmap cache used a public-derived key

**Fixed 2026-08-15**, in `b0f7f63`. `Identity::from_seed` derives `cache_key`
from the identity *seed* under the `karst-netmap-cache-key-v1` label and
zeroizes it on drop; `cache_seal_key` returns it.

The original implementation derived the cache AEAD key from `identity.public`,
so anyone holding a node's ML-DSA public key — which the coordination server
stores, and which is public by definition — and a copy of the cache could
decrypt the netmap, including every per-peer PSK.

`cache_key_is_not_derivable_from_the_public_identity` pins it by computing the
public-derived value and asserting inequality, rather than asserting that the
new value is some particular constant.

### 3. High: AVEN candidate state was unbounded

**Fixed in two parts.** `b0f7f63` capped the probe queue at
`MAX_PATHS_PER_PEER` and added a receive-side rate limit on `CallMeMaybe`, so
`on_call_me_maybe` returns `false` for an advertisement inside
`ADVERTISE_MIN_INTERVAL_MS`.

That left the path set itself unbounded, which the re-review found and
**2026-08-18 closed**. `remove_unconfirmed_candidate` refused to touch a path
with `last_pong_ms.is_some()` and was the only removal, so **every address that
ever answered a single `Ping` was resident for good** — a peer holding a disco
key and an IPv6 /64 could advertise sixteen fresh addresses per interval,
answer one probe each, and grow both the set and the per-tick selection scan
over it without limit. `PathSet::on_pong` re-added a forgotten path by the same
route, bypassing the queue cap entirely.

The bound now lives in `PathSet`, which owns the vector, and
`PathSet::add_candidate` reports what it displaced so the scheduler stays in
step. Eviction order: unconfirmed candidates first and oldest-first, then the
stalest confirmed path, never the path currently in use.

Each clause is pinned by a test that fails when it is removed. Exempting
confirmed paths again fails
`confirming_a_path_does_not_buy_a_permanent_slot`; dropping staleness from the
order fails `the_stalest_confirmed_path_is_the_one_evicted` and
`an_unconfirmed_candidate_gives_way_before_a_confirmed_path`; making the chosen
path evictable fails `the_chosen_path_is_never_the_victim`.

Note that a length assertion alone is not enough, and the first version of the
test made that mistake: exempting confirmed paths and then *refusing* new ones
bounds the length too, by locking the set to whichever sixty-four addresses
answered first — which is a peer pinning us to addresses of its choosing. The
test asserts the set still tracks the peer.

### 4. High: AVEN never selected a confirmed path

**Fixed 2026-08-16.** `PathSet::select` is called on every `Pong` that confirms
a path and on every poll, so a path that goes stale is released rather than
held forever. See finding 11 for the half of this that was still missing.

### 5. High: the AVEN integration was not driven by the daemon

**Superseded by finding 10; both are now closed.** The vertical slice this
finding asked for — netmap-distributed discovery keys, candidate gathering,
relay carriage of advertisements, timer polling, path selection and datapath
endpoint updates — exists and is tested end to end in
`bins/karstd/tests/rendezvous.rs`. The relay data path it was measured against
followed as finding 12.

### 6. Medium: `CallMeMaybe` was accepted from any UDP source

**Fixed 2026-08-16.** `Disco::inbound` accepts a `CallMeMaybe` from the shared
UDP socket only when its source is the already-established direct path;
relay-carried advertisements go through `Disco::inbound_from_relay`, a separate
entry point that additionally requires the relay-stamped source id and the AVEN
tag to resolve to the same peer. A relay cannot carry a `Ping` or `Pong` at all.

### 7. Medium: tag-collision handling overwrote the existing route

**Fixed 2026-08-15.** `TagTable::insert` checks for an existing distinct
mapping before mutating, and `Disco::add_peer_at` refuses to register the new
peer. The test asserts the incumbent still resolves, which the previous version
did not.

### 11. High: a released path never reached the datapath

**Found and fixed 2026-08-18.** `PathSet::select` clears the chosen path as
soon as nothing is usable — deliberately, because continuing to send into a
path that has stopped answering is worse than admitting there is none. But
`apply_disco_paths` read a *snapshot* of the chosen paths, and a snapshot can
only ever say "install this". It had no way to say a path that used to be there
is gone, so a direct path that died left the datapath pointed at a dead address
for the lifetime of the process. AVEN was a net connectivity regression rather
than an improvement.

`Disco::path_changes` now emits transitions instead of a snapshot, and the two
directions are deliberately not symmetric:

- An install is unconditional. A probed and confirmed direct path is better
  evidence than an address learned from a handshake.
- A release is conditional on the installed address still being in force.
  **The endpoint has a second writer** — `Engine::inbound` learns one from a
  handshake that decrypted — and discovery going quiet is weaker evidence than
  a peer that has just completed a handshake from somewhere else.
  `Engine::release_endpoint` is a compare-and-swap for that reason.

A release reverts to the netmap-configured endpoint, which for a peer the
netmap gave no endpoint for is `None`. That follows `select`'s own rule rather
than inventing a second one.

Two further things were closed while fixing this, both of which the first
review had flagged as separate concerns:

- `Engine::set_endpoint`'s documentation claimed the roster index check meant
  "a stale discovery result from a replaced netmap cannot target an arbitrary
  peer". It is a bounds check and says nothing about identity. The comment now
  says what the check does.
- The netmap refresh applied `engine.reconfigure` and `disco.reconcile` as two
  statements, and the timer thread could apply a path between them — installing
  a confirmed endpoint under a roster index that now names a different peer.
  The whole swap is now performed under the discovery lock, with installed
  endpoints withdrawn *first*, while the indices still mean what they meant
  when they were written. `Disco::release_all` exists for that ordering; a
  `reconcile` that simply forgot what it had installed would have reintroduced
  finding 11 through reconfiguration.

## Not defects, but worth recording

- `Disco::on_relay_call_me_maybe` is called only by tests;
  `inbound_from_relay` is the live path. One of the two should go.
- The relay queue drops when full. It is counted and reported as
  `relay_dropped`, which is what this entry previously asked for — recorded here
  because the counter exists and nothing alerts on it, so a node steadily
  shedding relayed traffic is visible only to somebody who looks.
- `Engine::via` is consulted per datagram and takes a read lock on the roster
  each time. That is the same cost the endpoint lookup it replaced had, so
  nothing regressed, but the relay path has not been profiled at all — every
  relayed datagram also crosses a channel to a single-threaded runtime doing one
  TLS write. It is the fallback path and correctness came first; PLAN.md defers
  the measurement.
- Eviction from the probe queue can strand an outstanding probe, so a `Pong`
  can arrive for an address the set no longer holds. `on_pong` re-adds it under
  the same cap, and it ages out as the stalest confirmed path. Bounded, and
  recorded so the next reader does not have to re-derive it.

## Validation performed

`cargo test --workspace --all-features` — 692 passing, 0 failing.
`cargo clippy --workspace --all-targets --all-features -- -D warnings` — clean.
`cargo fmt --all -- --check` — clean.
`cargo deny check` — all four checks clean, after a lockfile bump for
RUSTSEC-2026-0258 (`h2` ≤ 0.4.15, reached through `tonic`). That gate had been
failing before this pass; the advisory was not introduced by any of this work.
`go test ./management/internals/karst/...` — all packages pass, on Go 1.27rc3
after the `crypto/mldsa` migration.

The Rust↔Go interop suites were run explicitly, because they are `#[ignore]`d
by default and are the only place cross-implementation signature compatibility
is checked: `cargo test -p karst-control-client --test interop -- --ignored`
(4 passing) and `cargo test -p karstd --test control -- --ignored` (5 passing).

`crates/karst-tun/tests/addresses.rs` exercises `RTM_GETADDR` against the
running kernel, unprivileged, and was checked by hand against `ip -o addr show`
on a host with loopback, IPv6 link-local and site-local addresses present: all
three are excluded and the two globally scoped addresses are returned.

The NAT matrix **was** run for this pass, privileged, against real kernel
namespaces: 9 passing, including the four rows added on 2026-08-18 (full-cone,
address-restricted, IPv6-only, double-NAT/CGNAT). Each was checked against the
defect, and that check found **two** fixture bugs where a negative assertion
was passing vacuously — one binding a port a reflector already held, one
comparing ports across two different ephemeral source ports. Neither was a
product bug and both would have made the matrix lie.

`bins/karstd/tests/tailnet.rs` was run privileged and passes: the Go
coordination server, `karst-relay` and two daemons in separate namespaces, from
first enrolment to a direct path carrying TCP under a port-scoped ACL — in two
topologies, one flat and one with node A behind a port-restricted cone NAT.

It is checked against the defects it was written for. Reintroducing finding 17
fails it on the TCP conversation; removing finding 20's probe-source rule fails
the flat row. Removing §7.2's reflexive addresses fails **neither** row, so that
mechanism is carried by unit tests alone — recorded because a green NAT row
would otherwise be mistaken for coverage of it.

The other privileged suites (`just test-privileged`: TUN, two-node) were not
run. The `karst-tun` changes are additive — a new netlink dump alongside the
existing device and route paths — so the TUN suite is unaffected, but that is
reasoning rather than a result.

**That result does not cover the open findings above.** Finding 2 is a
lifecycle failure that no unit test models, which is the same caveat the first
pass recorded and the reason it still appears here.

Findings 10 and 12 were both in that category, and both left it the same way —
by someone writing the test that looks at the *join* between layers rather than
at a layer. `tests/rendezvous.rs` and `tests/relay_path.rs` are those tests. The
caveat is a statement about missing tests, not a permanent property of the
findings.
