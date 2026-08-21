<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Karst implementation findings

First reviewed 2026-08-15. Re-verified against the working tree on 2026-08-18,
again after the Phase 4 discovery work later that day, and again on 2026-08-19
after the NAT matrix was extended and measured.

This report records defects found by tracing implementation paths and their
tests. It does not treat the plan or source-code comments as proof that a
feature is correct.

All nine original findings are closed. The re-review and the Phase 4 work that
followed it added thirty-four more, and all but one are closed — most found by
building the thing the finding above them asked for, several found by counting
what the test matrix did *not* cover, three found by writing a release gate for
a feature nobody had ever run, two by building the double-NAT row the exit
criterion names, three by **measuring** a feature that had already been proved
to work, and the last two by asking what a deployment needs that only a test
fixture was providing.

**That last pair is worth naming as a category.** Findings 42 and 43 are one
commit apart, and both are components that exist only in the test harness — a
roster refresher and a relay registry — with production reading the field the
harness filled in. Neither could fail a test, because in a test the missing
piece is present. They surfaced the week the tree acquired its first deployment
artefact, which is the only vantage point from which either is visible.

**One finding remains open** — 38, recorded 2026-08-21, which is a retry
schedule rather than a fault: a node whose gateway can never help asks it again
every five seconds for the life of the process. It is written down rather than
fixed because the fix is a backoff policy with its own test surface, and because
the behaviour predates the row that surfaced it — it is what *every* node
without a port-mapping service has always done.

Finding 28 was resolved by *not adopting* the technique it was about: §7.7's port search is specified, measured and conceded to the relay. Finding 27 was a decision rather than a defect and
was taken on 2026-08-19: the NAT64 row is built from `tayga` plus an ordinary
masquerade. Finding 24 was not a code defect — it recorded that
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
| 23 | Medium | The aquifer fixture's NAT masqueraded but did not filter | Fixed 2026-08-18 |
| 24 | Operational | Phase 4's third exit criterion is not achievable as written | Resolved 2026-08-19 — criterion restated |
| 25 | Medium | The NAT matrix was missing the common symmetric/port-restricted pairing | Fixed 2026-08-19 |
| 26 | Medium | Vendoring pruned test fixtures a retained test still needed | Fixed 2026-08-19 |
| 28 | High | §7.7's port search does not work as specified | Resolved 2026-08-20 — technique not adopted |
| 27 | Operational | NAT64/DNS64 needs a dependency decision the matrix cannot make for itself | Resolved 2026-08-19 — built with `tayga` + masquerade |
| 29 | High | A retransmitted `HandshakeInit` wedged the pair, both ends reporting `established` | Fixed 2026-08-20 |
| 30 | High | The on-demand relay thread died at startup, so §9.1's second rule never ran | Fixed 2026-08-20 |
| 31 | Medium | A relay whose address blackholed packets stalled the relay path silently | Fixed 2026-08-20 |
| 32 | Medium | A node held two Ponor connections to one relay and they displaced each other | Fixed 2026-08-20 |
| 33 | High | A forgeable `HandshakeInit` tore down a working session — §12.6 | Fixed 2026-08-20 |
| 34 | High | A simultaneous open left both ends `established` and unable to decrypt | Fixed 2026-08-20 |
| 35 | Low | Userspace mode reported a host interface it had never created | Fixed 2026-08-20 |
| 36 | Operational | Three privileged suites could report success by not running | Fixed 2026-08-20 |
| 37 | Medium | A mapping on RFC 6598 shared address space was accepted as an external address | Fixed 2026-08-21 |
| 38 | Low | A gateway that cannot ever grant a mapping is asked again every five seconds | **Open** — recorded 2026-08-21 |
| 39 | High | The SOCKS5 relay treated a client half-close as a full teardown | Fixed 2026-08-21 |
| 40 | Medium | Userspace mode's round trip was a poll interval, not a cost | Fixed 2026-08-21 |
| 41 | High | Every userspace TCP socket advertised a one-segment window | Fixed 2026-08-21 |
| 42 | High | Nothing outside the test fixture kept a relay's roster fresh, so a deployed relay stops admitting nodes after 90 s | Fixed 2026-08-21 |
| 43 | High | A production coordination server published no relays at all; only the test server ever set the netmap's relay registry | Fixed 2026-08-21 |

## Open

### 38. Low: a gateway that can never grant a mapping is asked again every five seconds

**Recorded 2026-08-21** by the double-NAT row, which is the first thing in the
tree to run a node whose gateway answers and refuses.

`RETRY_DELAY` is five seconds and flat. A refusal the gateway will keep making —
`NO_RESOURCES` from a router that is itself behind a carrier, and will answer
the same way for as long as the subscriber is behind that carrier — produces
17,280 requests a day that cannot succeed. The measured status is
`portmap_state = "retrying"`, `portmap_reason = "PCP failed transiently (PCP
code 8); retrying"`, restated every five seconds.

**The code is right and the schedule is not.** RFC 6887 §7.4 makes
`NO_RESOURCES` a transient code, and `ResultCode::is_transient` classifies it
that way deliberately — a node that gave up on it would never recover when a
gateway's table drained. What is missing is the other half of the same
argument, which `is_transient`'s own doc comment already makes for permanent
codes: *"a node that retries `UnsupportedVersion` every thirty seconds is
generating traffic that cannot ever work"*. A transient code repeated
indefinitely reaches the same place by a different route.

**It predates the row that found it**, which is why it is Low and why it is
recorded rather than folded into that commit: a node on a NAT with no
port-mapping service at all gets `"the gateway did not answer PCP"` on the same
five-second cadence, and that is most nodes. The row made it visible; it did
not introduce it.

Recommended: back off on consecutive failures — five seconds doubling to a cap
of a few minutes, reset on any success or on an epoch change — and leave the
classification alone. Deferred rather than done because `portmap::run` takes
its time from `Instant::now()` inside its own loop, so a test for the schedule
needs an injectable clock, and that is a refactor with a wider blast radius
than the fix.

## Closed

### 43. High: a production coordination server published no relays at all

**Found 2026-08-21** by reading, one commit after finding 42, while writing the
`docker-compose` artefact both findings block. Fixed the same day.

A node learns which relays exist, and which key authenticates each one, from
exactly one place: the `relays` field of its signed netmap. That is deliberate —
`ponor-v1.md` §4.2 declines to trust TLS for relay identity, so a relay a node
was told about out of band is a relay it cannot authenticate. There is no local
relay list in `karstd`, and there should not be.

`control.NetmapHandler.Relays` is therefore the only supply of relays in the
system. **The only code that ever populated it was `karst/testserver`**, which
exists to serve the Rust test suite. `bootstrap.Install` never set the field, so
every real deployment handed every node an empty registry:

```console
$ grep -rn "KarstRelay{" --include=*.go server/ | grep -v _test | grep -v /proto/
management/internals/karst/testserver/netmap.go:195:	return &proto.KarstRelay{
```

One construction in the whole server, in the test harness.

**Nothing failed.** The relay ran, its config validated, its roster was current
(after 42), and it sat there while nodes that could not reach each other
directly could not reach each other at all. Relaying did not break; it never
happened. This is the same shape as 42 — the test suite holding the production
component — and finding them a commit apart is not a coincidence: both are
things only a deployment needs, and until this week nothing in the tree was a
deployment.

The fix is `server/management/internals/karst/relayreg`, loading an
operator-written registry from `KARST_RELAY_REGISTRY_FILE`. Two decisions in it
are worth stating:

- **`relay_id` is derived, never configured.** §5.2 defines it as
  `SHA-256("karst-relay-id-v1" ‖ identity_pk)`, and `karstd` recomputes it while
  decoding. A hand-written id would make a silent mismatch a typo away, so the
  field is refused if supplied.
- **Validation is fatal at startup**, because it is the only place the error can
  be reported usefully. `karstd` decodes the registry with
  `collect::<Result<_, _>>()?`, so **one malformed entry fails the entire netmap
  for every node** rather than dropping that relay. A typo is a total outage
  whose symptom points nowhere near it; every check in `relayreg` mirrors one in
  `Relay::from_wire` so that a file the server accepts is one every node
  accepts.

**A term hashed by both ends and exercised by neither.** `netmap_version` has
covered a domain-separated `karst-relays` term since 2026-08-18, and no vector
carried a single relay — because no production server ever populated the field.
So the one part of the netmap that had never been checked across
implementations was the part about to be used for the first time. The version is
what a node compares against the netmap it assembled, refusing one that
disagrees, so a drift there is not a degraded relay: **no netmap ever applies.**
`spec/vectors/karst-control-v1.json` now carries three registry cases, and the
Rust side additionally checks the `relay_id` derivation against them.

Verified by injection: dropping the region from the Rust relay hash, and
dropping the `karst-relays` separator, each fail `netmap_version_matches`. Both
passed before this change.

### 42. High: nothing outside the test fixture kept a relay's roster fresh

**Found 2026-08-21** while starting on PLAN.md §5's co-located deployment
artefact — the `docker-compose` that is supposed to have a self-hoster relaying
in five minutes. Fixed the same day.

Ponor's admission is structural and deliberately unforgiving: `ClientAuth`
carries no public key, so a relay verifies a node against an entry in its
roster file or it does not verify at all (§5.3). The relay also refuses to
serve a roster nobody is maintaining — `roster::MAX_AGE` is **90 seconds**, and
past it admission is replaced with an empty roster. Both rules are right. A
membership list nobody refreshes is one nobody is curating.

Together they mean something has to rewrite that file every ninety seconds,
for as long as the relay runs. **Nothing did.** The only writer in the tree was
a thread inside `bins/karstd/tests/aquifer.rs` that touches the file to keep
the fixture's lease alive — and `deploy/kubernetes/README.md` told operators to
"deploy it as ordinary infrastructure with a TLS certificate and an explicit
roster", which followed literally produces a relay that works for a minute and
a half.

**Nobody would have seen this in a test.** Every aquifer row passes, because
the fixture is the missing component. That is the uncomfortable part: the test
suite contained the production gap as a helper, and its presence there is
exactly what stopped anything failing.

The fix is `server/management/internals/karst/roster`: the coordination server
already holds every enrolled node's ML-DSA-65 identity key, so it renders the
roster and rewrites it every 25 seconds. Three things about it are load-bearing
enough to have their own tests:

- **The rewrite is unconditional.** The relay's freshness fingerprint is
  (contents, mtime), so a change-driven writer would leave exactly the stable,
  working deployments failing closed. `TestARewriteMovesTheModificationTimeEvenWhenNothingChanged`
  is the one that pins it.
- **A failed query writes nothing.** Rendering an empty roster from a database
  blip would hand the relay a *valid* file admitting nobody, turning a
  momentary outage into a fleet-wide one; leaving the file alone lets the
  relay's own lease decide.
- **Output is ordered.** The relay reloads on any change, and a file whose rows
  shuffle changes on every write, so unordered output would swap the admission
  table several times a minute for nothing.

**A second implementation of a format nobody was checking.** The Go renderer
and the Rust parser now share `spec/vectors/relay-roster-v1.toml`, generated by
one and parsed by the other in CI, on the same argument as
`spec/vectors/karst-control-v1.json`: a renamed field here does **not** produce
a parse error at the relay. It produces a roster with zero clients, a relay
that starts cleanly, and a fleet that cannot connect. The Rust side asserts the
client count is two rather than merely that the file parses, because "it
parses" is true of the failure.

**Scope, stated so it is not mistaken for more.** This serves the co-located
deployment §5 makes the default: one server, one relay, a shared volume. A
relay on another host needs the roster to travel with provenance, which is
`ponor-v1.md` §13.2 and is still open.

### 41. High: every userspace TCP socket advertised a one-segment window

**Found 2026-08-21** by ADR-0012's gate-1 measurement, after two other fixes
had failed to explain the number. Fixed the same day.

Both `Userspace::connect_tcp` and `listen_tcp` built their socket like this:

```rust
tcp::Socket::new(
    tcp::SocketBuffer::new(vec![0; self.mtu]),   // 1280 bytes
    tcp::SocketBuffer::new(vec![0; self.mtu]),
)
```

One MTU reads like the right unit for a packet-oriented stack, and for a
*device* buffer it would be. For a TCP socket it is not: **the receive buffer is
the window the stack advertises**. At 1280 bytes the far end may hold exactly one
segment in flight and must wait for an acknowledgement before sending the next.
The transmit side mirrors it — one segment of application data at a time, so
every write costs a round trip.

The result is stop-and-wait at whatever the path's latency is, and nothing
underneath can compensate: not batching, not polling, not a faster datapath.
Userspace mode sat at **7.3 Mbps** with the relay loop and the datapath both
idle, which is the signature of a window rather than of a cost. 64 KiB buffers
— an ordinary kernel starting window — took it to **514.8–518.5 Mbps**, a **71×
change**, measured across three runs on the same host and harness. The price is
128 kB per connection, visible as the ~200 kB the memory row moved.

**Two things about how this was found are worth more than the fix.**

It was found *last*. The obvious-looking cause — `recv_segments` returning one
packet per call where the privileged path returns ~52 through segmentation
offload — was found first, fixed first, written up as the explanation, and moved
the number from 7.3 Mbps to 7.3 Mbps. That change is kept (it is strictly
cheaper and will matter when something else is the constraint) and the negative
result is recorded beside it, because attempting batching before finding the
serialisation is **exactly** what PLAN.md §3.4 records doing to the privileged
datapath: there the two lock removals were worth more than every
micro-optimisation combined. The lesson had been written down and did not
transfer.

And nothing that existed could have caught it. The mode worked. ADR-0012's
gate 2 passed, the unit tests passed, the half-close row added the same day
passed — a correctness test cannot see a window, and a feature can be entirely
correct and 70× slower than it should be. The only instrument that finds this
is a number, which is what a measurement gate is for and why "gates, not
estimates" was the right wording in the ADR.

**So something can catch it now.** `a_bulk_transfer_is_not_stop_and_wait` moves
8 MiB through the SOCKS5 attachment and asserts only that it finished inside
five seconds. That is a throughput assertion in a correctness suite, which
usually deserves suspicion, and both ends of its budget are measured rather
than guessed: **1.2 s** healthy in a debug build, **36.7 s** with the defect
put back. A 4× margin below and a 7× margin above, so a slow runner cannot fail
it and stop-and-wait cannot pass it. It reports no rate and has no baseline; it
is not a benchmark and is not trying to become one.

### 40. Medium: userspace mode's round trip was a poll interval, not a cost

**Found 2026-08-21** by ADR-0012's gate-1 measurement. Fixed the same day.

The first run put userspace mode at **1.1 Mbps and a 4.135 ms round trip**
against 1370 Mbps and 0.196 ms on the privileged path. The throughput was
believable; the latency was not, and the distribution said so:

```
rtt_p50 4.139   rtt_p90 4.156   rtt_p99 4.211   rtt_max 4.219
```

A spread of 80 µs across every percentile is not work. It is a timer — and at
2.000 ms per tick, two ticks of one.

`socks5::proxy` slept an unconditional 2 ms at the end of every pass through
its relay loop, so a round trip cost at least two of them: one before the
request went out, one before the reply was noticed. The same sleep capped
throughput at one `READ_CHUNK` per tick.

Fixed by sleeping only when a pass moved no bytes at all, and by two rates
rather than one: 200 µs while a connection has moved something in the last
50 ms, 2 ms once it has gone quiet. The two cases want opposite things — a
connection waiting for a reply is idle in exactly the interval that matters,
and a connection nobody is using is a resource to be cheap about. A flat 200 µs
would have fixed the latency and made every idle connection wake 5,000 times a
second.

Measured, both rates, same host and harness:

| Poll | RTT p50 | Throughput |
|---|---|---|
| flat 2 ms | 4.135 ms | 1.1 Mbps |
| flat 200 µs | 0.545 ms | 9.9 Mbps |
| **adaptive (shipped)** | **0.547 ms** | **5.6–7.3 Mbps** |

**The throughput was not the timer.** At 5.6–7.3 Mbps the mode was still 0.5% of
the privileged path after this fix, and the first guess at why — `recv_segments`
returning one packet per call — was wrong: see finding 41, which is where the
throughput actually was, and the note there about the order these were tried in.

### 39. High: the SOCKS5 relay treated a client half-close as a full teardown

**Found 2026-08-21** by ADR-0012's gate-1 measurement, which could not complete
a single run because of it. Fixed the same day.

`socks5::proxy` relayed until `client.read` returned `Ok(0)`, and then closed
the tunnel and returned. But EOF on that read does not mean the conversation is
over — it means the workload has closed its **write** half, which is an
ordinary thing for a client to do: send the request, half-close, read the
answer to EOF. `curl` does it, `nc -N` does it, and every protocol that
delimits a message by closing does it.

The FIN itself crossed correctly — `Userspace::tcp_close` is smoltcp's `close`,
which is a half-close on the wire — so the service on the far end received the
whole request and answered it. What was lost was the answer: the relay had
already returned, dropping the client socket with it. The observed symptom is a
**truncated reply**, not a missing one, which is worse: a client sees a short
read rather than an error.

The fix tracks the two directions separately, as TCP does. The client's EOF
sets a flag; the FIN goes out only once everything already buffered has been
handed to the stack, so the request cannot be truncated; the relay keeps
copying overlay→client until `tcp_may_recv` says nothing more can arrive, then
closes the workload's side so it sees a clean EOF too.

That last part needed a new distinction. `tcp_can_recv` asks whether bytes are
buffered *now*; a relay that stopped on it would cut the reply short. The
question is whether more can *ever* arrive, which is smoltcp's `may_recv`, now
exposed as `Userspace::tcp_may_recv` with the difference written down at the
call site.

`a_half_closed_request_still_receives_its_reply` covers it, and its shape is
deliberate: both ends read to EOF, so each half of the fix is load-bearing. The
**existing gate test still passes against the defect** — it writes a fixed-size
request, reads a fixed-size reply, and never half-closes — which is exactly why
a feature proved to work still had this in it.

### 37. Medium: a mapping on RFC 6598 shared address space was accepted as an external address

**Found 2026-08-21** while building the double-NAT aquifer row. Fixed the same
day.

`natpmp::is_unusable_external` refuses an external address a gateway should
never name, and its doc comment cites the case it was written for: "RFC 6886
§3.2 anticipates it for a double-NATed gateway". It checked
`Ipv4Addr::is_private`, which is RFC 1918 — 10/8, 172.16/12, 192.168/16 — and
**not** RFC 6598's 100.64.0.0/10, which is the range a carrier actually
addresses subscriber routers out of. So the one deployment the check names by
name was the one it did not cover.

A gateway reporting `100.64.0.2` would have been believed, and the mapped
address is `aven-v1.md` §7.2's **strongest** candidate tier — so every peer
would have put an address it cannot reach at the top of its probe queue, and
the datagrams would have gone into the carrier's shared space toward whatever
equipment holds that address, which is not the peer.

**Measured, not reasoned about.** `miniupnpd` given a 100.64 external address
logs "Reserved / private IP address 100.64.0.2 on ext interface … Port
forwarding is impossible" and answers PCP `MAP` with `NO_RESOURCES` — **and
names `::ffff:100.64.0.2` in the response body anyway**. The bytes that would
have been believed are on the wire in the refusal; a gateway answering
`SUCCESS` with that same body is an ordinary consumer router, not a
hypothetical.

The v6 arm carried the same gap by symmetry — it refused loopback and the
unspecified address while the v4 arm refused private and link-local — so
unique-local (`fc00::/7`) and link-local (`fe80::/10`) are refused now too.
Multicast and broadcast are refused on a different ground, which the comment
keeps separate: they are not unicast endpoints at all, so no probe to one can
establish a path. Documentation prefixes are deliberately still accepted; they
are ordinary global unicast to a router, and both this crate's fixtures and the
aquifer use them to stand in for public addresses.

Three unit tests, each of which fails against the old predicate and passes
against the new one, including both edges of the ten-bit prefix — `100.63.255.255`
and `100.128.0.0` must stay accepted, since an off-by-one there rejects public
space or admits the carrier's.

### 36. Operational: three privileged suites could report success by not running

**Found 2026-08-20** by listing every `#[ignore]`d suite in the tree and
matching each against the CI job that runs it. Fixed the same day.

Three had no job at all — `bins/karstd/tests/aquifer.rs`, which is where
PLAN.md §6's ≥90% direct-connection criterion is measured;
`bins/karstd/tests/userspace.rs`, which is ADR-0012's release gate; and
`crates/karst-portmap/tests/gateway.rs`, which is the only place the NAT-PMP
and PCP codecs meet an implementation we did not write. `just test-privileged`
ran all three, so the coverage existed; what did not exist was anything that
ran it without being asked. The §6 bullet in PLAN.md had said "in CI" for some
time, which is how this survived: the claim was in the title of the thing it
was untrue of.

**The second half is the one worth recording.** All three *skipped* when their
prerequisites were absent, and a skip is reported as a pass. Dropping them into
CI as they stood would have created the failure mode the NAT matrix exists to
prevent one layer down: a runner image that stopped shipping `miniupnpd` would
have turned rows 8b and 9 into a no-op, the gateway suite into nothing at all,
and the job green. A suite that measures an exit criterion must not be able to
report success by not running.

`KARST_REQUIRE_PREREQUISITES=1`, which CI sets and a developer does not, turns
the skip into a failure naming exactly what is missing. Locally the skip
survives, because a developer without `miniupnpd` is the case it was written
for.

The detection probes are deliberately the **unprivileged** ones — `nft
--version`, not `nft list ruleset` — so the message says what is *not
installed* rather than what this process may not do. A check that sends someone
to install a package they already have is a check that trains people to ignore
it. For the same reason the job puts `/usr/sbin` on `PATH` explicitly: `nft`
and `miniupnpd` live there, every run is `sudo env "PATH=$PATH"`, and a runner
PATH without it would produce a red build naming tools that are present.

### 34. High: a simultaneous open left both ends `established` and unable to decrypt

**Found 2026-08-20** by ADR-0012's userspace release gate, which was written to
test something else entirely and passed once, then failed three runs in a row.
Fixed the same day.

Two nodes that both know the other's endpoint both dial at startup —
`connect_all` runs on every node, so a *simultaneous open* is not an unlucky
case but the standing behaviour of any pair with a static endpoint on both
sides, and of any pair that has learned each other's addresses. Each node is
then initiator and responder at once, and the order the four messages land in
is a race on the wire.

`adopt_responder` replaced the whole session state, so a node that answered the
peer's `HandshakeInit` while its **own** handshake was outstanding discarded
that handshake. The peer's `HandshakeResponse` then arrived with nothing left
to complete and was dropped as unsolicited. The two ends settled on key sets
derived from different handshakes: **both reporting `established`, neither able
to decrypt the other**, with every packet counted as a decryption failure at
one end and nothing at all at the other.

This is precisely the stall `State::Established::initiated` documents — *"9
stalls in 7.8 hours, 253–765 seconds each, 13% of samples, with the session
reporting `established` throughout"* — in the one place that rule does not
reach. `initiated` stops two *rekeys* racing by making only the initiator
rekey. It says nothing about the first handshake, and nothing had ever tested
one: every handshake test in the tree is asymmetric, one side dialling and the
other answering.

The fix is small — carry the outstanding handshake across into the slot that
already means "a handshake in flight beside a live session" — and §12.6 is
untouched, because at that point there is no working session to protect.

**The rekey race then returns through the same door.** After a simultaneous
open both ends are initiators, so both rekey; and two sessions created in the
same millisecond reach `REKEY_AFTER_TIME` in the same millisecond, so they
rekey *together*. Completing one's own handshake was discarding the keys owed
to the peer — finding 33's `pending` slot, cleared on every
`handle_response` — which reproduced the same silent stall one rekey later.
Those keys are an independent claim and now survive.

`crates/karst-node/tests/simultaneous.rs` enumerates **all six** valid
interleavings rather than sampling one, because the ordering is exactly what a
real network picks at random and a test that chose one would have passed
against the defect five times in six. Each of the two fixes has a test that
fails without it and passes with it, and a control test pins the asymmetric
case so "carry the handshake across" cannot quietly become "always keep one in
flight" and undo `initiated`.

**What this leaves open** is convergence, not correctness. After a simultaneous
open each end seals with its own initiator keys and reads the peer's through
`previous`, so both sessions coexist and every inbound packet costs a second
AEAD attempt. Traffic flows and keeps flowing; the pair simply never agrees on
one session. `phreatic-v1.md` §14 item 9 — *"rekey state machine: precise
transition table"* — is where a tie-break belongs (the two static keys are
known to both ends and would settle it deterministically), and it is a spec
decision rather than an implementation one.

### 35. Low: userspace mode reported a host interface it had never created

**Found 2026-08-20** by the same gate, on its first run. Fixed the same day.

`karst status` and `karst bugreport` printed `config.interface` — the *name in
the configuration file*. Userspace mode creates no host interface at all, so a
node running it reported `interface = "karst0"` and sent anyone diagnosing it
to an `ip link` entry that does not exist. It also made the two modes
indistinguishable in exactly the output that exists to tell them apart:
`NetworkDevice::name()` already answers this correctly and only `announce()`
was asking it.

Both reports now take the live device's name and MTU together, because both
belong to the device rather than to the configuration.

### 33. High: a forgeable `HandshakeInit` tore down a working session

**Found 2026-08-20** while fixing finding 29, which is the same code path one
step further in. Fixed 2026-08-20.

`phreatic-v1.md` §12.6 is unambiguous, and ProVerif is what put it there — the
agreement query is **false** if a responder claims completion on sending
`HandshakeResponse` and **true** if it waits:

> Therefore a responder MUST NOT, on emitting HandshakeResponse:
> - tear down an existing working session with that peer; […]
> All of these MUST wait for the first authenticated transport message.

`adopt_responder` did exactly that: it installed the keys it had just derived,
discarding whatever session was in use. §12.5 makes a `HandshakeInit` forgeable
by anyone holding the responder's *public* keys, so this was a one-datagram,
off-path, unauthenticated teardown of somebody else's live tunnel — the denial
of service §12.5 warns the unauthenticated handshake invites, reachable by an
attacker who needs no position on the path and no secrets.

**The fix is the session lifetime WireGuard uses**, and the reason it has three
slots rather than two is worth stating, because a two-slot version was tried
first and every rekey test caught it. Keys derived as responder wait in
`pending` and are adopted only when a transport message opens under them, which
a forger cannot produce. But a rekeying **initiator** switches its sending key
the moment its own handshake completes, so the responder goes on sealing under
the old keys until that first message reaches it — and everything already in
flight, in both directions, was sealed under keys one end has just replaced.
So the replaced keys are kept as `previous`, for decryption only, until they
expire. Three slots, each with a different reason to exist.

**Adoption names the keys that opened the message**, not whatever is waiting
when the caller gets round to it. The AEAD runs outside the session's lock, so
a forged `HandshakeInit` — one datagram, timing of the attacker's choosing —
can replace the waiting keys in between. Both careless readings have a victim:
adopting what is there installs keys nothing proved, by a race; refusing
because the slot moved drops a set that *was* proved and leaves the node
sealing for a peer that has gone. Both are tests.

What is *not* closed by this: §12.6's other two clauses — not recording the
session as established in crypto-posture reporting, and not counting it against
admission limits — are about reporting surfaces the node does not have yet.
They belong with whatever builds them.

### 29. High: a retransmitted `HandshakeInit` wedged the pair

**Found 2026-08-20** by `bins/karstd/tests/aquifer.rs`'s two-relay row, which
was written to test relay selection and found this instead. Fixed the same day.

An initiator retransmits the **identical** `HandshakeInit` until it hears back
(§10). The responder answered each copy afresh: `respond()` derives new keys,
`adopt_responder` installed them, and the session the initiator had already
completed under the *first* answer was gone. Both ends then reported
`established` — because both had keys — and neither could decrypt the other.
Nothing re-handshaked, because neither end had any reason to. The pair stayed
wedged until `REJECT_AFTER_TIME`.

The symptom is asymmetric and misleading: one end counts every packet as a
decryption failure, the other counts nothing at all, and `karst status` at both
ends says `established` with a healthy transport. In the aquifer row A sent
eight TCP retransmissions over fifteen seconds and B recorded eight decryption
failures while reporting a live session.

**It takes only a path where a retransmission crosses the response**, which is
the ordinary case on a relayed path with a `PeerGone` detour in it — the first
`HandshakeInit` goes to a relay the peer is not on, the retry goes to the right
one, and the answers arrive out of order. On a single-relay LAN the response
comes back in under a millisecond and the 300 ms retry never fires, which is why
every existing row passed.

The fix is that **the same question gets the same answer**: a session remembers
the `HandshakeInit` it answered and the `HandshakeResponse` it sent, and a
byte-identical repeat re-emits the cached response without deriving anything.
That also makes a repeated `HandshakeInit` cost no ML-KEM decapsulation, which
is the §12.5 posture applied to the cheapest case.

**The rest of the same code path is finding 33**, closed the following day: a
*fresh* `HandshakeInit` still tore down a working session, which §12.6 forbids
outright. The replay cache here stays, because it is the cheaper answer to the
case it covers — a repeated `HandshakeInit` now costs no ML-KEM decapsulation
at all — and because "the same question gets the same answer" is worth being
true on its own.

### 30. High: the on-demand relay thread died at startup

**Found 2026-08-20** by the same two-relay row; fixed the same day.

`tokio::time::timeout` arms a timer as it is *constructed*, so building one
outside a runtime panics with "there is no reactor running". The on-demand
relay hub built its receive timeout as an argument to `block_on` rather than
inside it, so the thread panicked on its first iteration — at daemon startup,
every time.

Nothing noticed. The panic went to the daemon's log among ordinary lines, the
thread was one of several in a scope, and every test of the machinery below it
passed: the pool's lifetimes are sans-io and were unit-tested, the queue split
was unit-tested, and no test ran the hub. §9.1's second rule had never worked
in a running daemon, and the feature had already been committed.

The lesson is the one findings 10, 12 and 19 keep teaching in different clothes:
a component with tests either side of it is not a component that has been run.

### 31. Medium: a relay whose address blackholed packets stalled the path silently

**Found 2026-08-20** while building the two-relay row, which blocks one relay
with a `drop` rule — the closest thing to what a relay that will not admit a
node looks like from outside, since §10.1 makes a roster miss deliberately
indistinguishable from a relay that is down.

`Connection::connect` had no timeout of its own. A `drop` produces no RST, so
the TCP connect retried SYNs for over two minutes; a relay that accepted and
then said nothing would have waited for ever. In that window the node's relay
path was down, **nothing was logged**, and the failure counter that would have
moved it to another relay never incremented, because there was no failure to
count.

Now the whole negotiation — connect, TLS, HTTP upgrade and Ponor handshake — is
bounded at ten seconds, which is generous for a handshake costing one round trip
and an ML-DSA-65 signature.

### 32. Medium: a node held two Ponor connections to one relay

**Found 2026-08-20** by the two-relay row, as a fragmented handshake whose
second fragment never arrived.

A relay keys its clients by node id and a newer connection **replaces** an older
one for the same id (§7.6, deliberately: the old one is often a half-open zombie
after a suspend). So two connections from one node do not coexist — they take
turns, each killing the other, and whatever was in flight on the loser is lost.
A fragmented `HandshakeInit` loses its second fragment and reassembly never
completes.

The way a node ends up with two is ordinary once §9.2 measures alternatives: a
relay is dialled on demand to be measured, and is then adopted as the home
relay. The measurement connection and the home connection are both open, to the
same place.

The rule is now explicit — the relay this node holds is never also in the
on-demand pool — and it is enforced in both directions: a request naming the
home relay goes on the connection that already exists, and the sweep lets go of
a pooled connection to a relay that has since become home.

### 28. High: §7.7's port search did not work as specified

**Resolved 2026-08-20 by not adopting the technique.** The section is kept as
an analysis and the implementation is removed; `aven-v1.md` §7.7 carries the
decision and PLAN.md the cost argument. What follows is how it was reached,
because the route matters more than the destination here.

**And the row it was for now has an answer, added the same day.** §7.7 existed
to reach row 8 — a CGNAT subscriber talking to somebody on a home router. The
aquifer's row 8b runs that pairing with the router serving PCP, and it goes
direct in **37 seconds** using the port-mapping client built for row 9. So the
concession above is narrower than it first reads: what was declined is buying
that pairing with probe traffic, not the pairing itself. Row 8 and row 8b are
kept side by side so the condition is visible rather than inferred.

`aven-v1.md` §7.7 has the hard side "open *N* sockets and send one datagram from
each" toward the easy side's address, and probe on a **thirty-second** cadence
reused from §7.5. Those two numbers do not work together.

Linux's `nf_conntrack_udp_timeout` is **30 seconds**, and most consumer NATs are
at or below it. A scratch socket sends once and never again, so its mapping is
dead or dying by the time the peer's next round probes for it. The technique
cannot land however many rounds run, and it does not: `aquifer.rs`'s row 8 saw
no arrival at all in seven minutes with both sides aiming correctly.

**This is finding 22 one layer down, and the rule it wrote is the fix.** That
finding was about the reflect interval — "a reflexive address is only true for
as long as the binding that produced it is alive, and nothing tells the node how
long that is" — and it set the refresh to well under the shortest timeout it
expected to meet. A scratch mapping is the same object with the same lifetime,
and §7.7 gave it no refresh at all.

That the same mistake recurred in the same specification, written by the same
hand that recorded finding 22, is the part worth keeping. The rule was known and
still not applied, because the scratch datagram reads as *establishing* a
mapping rather than as *holding* one — and nothing in the section's shape
prompts the question.

**A packet capture on the public segment settled it**, after five successive
fixes made on inference had not. 2359 datagrams over eight minutes, both NATs
in view:

| Measured | Value |
|---|---|
| Coincidences — B aimed at a port A's NAT had used | **12** |
| Predicted by the birthday arithmetic (769 × 1082 / 64511) | **12.9** |
| Of those, inside a 30-second mapping lifetime | **2** |
| B's probes leaving the shared socket, as §7.7 requires | 786 of 914 |

**The arithmetic is exactly right and the quantities are wrong**, which is why
no amount of fixing the mechanism helped. Two multipliers were missed.

*Half of the hard side's mappings are dead targets.* A opens 64 scratch sockets
toward `B:51820` **and** sends 64 probes to `B:<random>` each round. Both create
mappings, but a probe mapping accepts a reply only from the random port it was
aimed at — so B's probes, which correctly come from `B:51820`, can only ever be
admitted by the *scratch* half. §7.7's *N* counts external ports; the usable set
is half of them.

*Alignment is partial.* Only 2 of 12 coincidences fell inside a mapping
lifetime. A wall-clock boundary aligns the two nodes' round *starts*, but a
round's 64 sockets and 64 probes are emitted over the seconds that follow, and
the two sides drift within the boundary.

Multiply those together and the expected number of usable, timely coincidences
over eight minutes is **well under one** — against a model that predicted 98%.
The technique is not broken; §7.7's arithmetic counts the wrong population.

The model was corrected — `aven-v1.md` §7.7 carries the derivation — and it did
not explain the failure either.

**A second capture, taken inside the node rather than on the segment, changed
the question.** It shows the exchange *working* at the network layer:

| Measured inside node A | Value |
|---|---|
| Datagrams arriving from the peer's outer address | **22** |
| Local port they arrive on | one scratch socket, `:36692` |
| Datagrams the peer sent to one found port | **184** |

The hole opens. The peer finds a live mapping and uses it repeatedly. A
`Pong` (65 bytes) arrives seventeen seconds after the scratch `Ping` that
earned it. **Everything the technique is supposed to do, happens.**

And `SearchSockets::drain` logs **zero** arrivals across the same run. The
datagrams reach the host and never reach the pool that owns the socket they
landed on. Three further defects were fixed while establishing this — the
reply was discarded rather than sent back out the receiving socket; the
scratch `Ping`s' transaction ids were minted and never recorded, so the
answers matched nothing; and the in-flight table was cleared per round when
the answer arrives a round later — and the row still does not complete.

**The gap is now precisely located and not explained**: between the kernel
delivering a datagram to a socket this process owns, and `drain` reading it.
That is a small enough surface to settle definitively, and it is where the
next session should start rather than anywhere in the protocol.

The branch `aven-77-align` carries all eight fixes. It is unmerged because it
also regresses `a_symmetric_nat_reaches_an_address_restricted_peer_directly`,
which passes without it.

## Closed

### 27. Operational: NAT64/DNS64 needed a dependency decision the matrix could not make for itself

**Resolved 2026-08-19 by building the row from `tayga` plus an ordinary
nftables masquerade**, which needs no kernel module.

**The recommendation below was wrong when first written, and the correction is
the useful part.** It argued for `tayga` on the grounds that "stateless
translation answers the question as well as stateful does". It does not. The two
measure different topologies: stateful NAT64 shares one IPv4 address across many
IPv6 clients and separates them by port, which is what carriers deploy and what
makes the row interesting for traversal; stateless translation gives each client
its own IPv4 address with ports preserved, which is barely distinguishable from
the `Ipv6Direct` row already in the matrix. A `tayga`-only row would have
reported a comfortable result about a topology nobody is on — the same failure
as findings 23 and 25, arrived at a third way.

The resolution keeps `tayga` and adds the missing half from a mechanism this
matrix has already characterised: **`tayga` does the protocol translation,
nftables does the port sharing.** No out-of-tree module, and the NAT semantics
under test are the same masquerade every other row is built on rather than a
second implementation taken on trust. It is also a real deployment shape;
plenty of NAT64 sits in front of carrier NAT.

**What the row establishes**, and it is good news that was not guaranteed: a
NAT64 path built this way has **endpoint-independent mapping**. One socket
addressing two different IPv4 hosts is seen at the same external port, so an
IPv6-only node's reflexive address (`aven-v1.md` §7.6) is the address every peer
sees and discovery works on it unchanged. Had it come out endpoint-dependent,
every IPv6-only node would have been in §7.7's hard class. Making the masquerade
`fully-random` fails the row, so the assertion is real.

One fixture trap worth recording, because it presents as a product failure. RFC
6052 §3.1 forbids pairing the well-known `64:ff9b::/96` prefix with private IPv4
addresses, and `tayga` enforces it — every probe is silently dropped with a note
in a log nobody is reading. The matrix's outer addresses are RFC 1918, so the
row uses a translation prefix from its own ULA space, which is what the RFC says
to do. This is the third time in this project that a fixture defect has
presented as a traversal failure.

A second fixture defect in the same row cost a broken `main`, and the *process*
failure matters more than the technical one. `tayga --mktun` creates a
**persistent** tun device, so a fixed device name is shared with every other
tayga on the machine. The row failed reproducibly while a stray tayga from an
unrelated experiment was alive and passed once it was gone; the exact
interaction was never established, so the device name is now per-process —
removing the class rather than reasoning about the instance.

**The commit was merged to `main` before its test output was read**, because it
was chained behind a full-suite run whose exit status went unchecked. Nine of
thirteen rows were failing at the time. It was reverted within minutes and
re-landed after three clean runs. The lesson is the general one: a suite run
whose result is not read is not a gate, and chaining a merge behind one is
worse than not running it at all.

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
   one §1.1 explicitly allows inside the aquifer — an *N*-fold amplifier aimed
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

The aquifer fixture covered seven topologies and reported five direct. It had a
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

**Found 2026-08-18** by extending `tests/aquifer.rs` to the topology that is not
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

### 23. Medium: the aquifer fixture's NAT masqueraded but did not filter

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
  NAT rather than a router — and the aquifer fixture had been built without the
  equivalent for traffic addressed to the NAT's own address.
- With it, the doubly-NATed row converges in ten seconds instead of never.

### 20. High: only the node that probed first ever got a direct path

**Found and fixed 2026-08-18**, by codifying the live run as
`bins/karstd/tests/aquifer.rs` — the third defect that test has produced, and
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
an advertisement that was sent and lost. The aquifer test catches this one and
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
  dropped it. **This is what a node joining an existing aquifer does**, and it
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

`bins/karstd/tests/aquifer.rs` was run privileged and passes: the Go
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

### Validation, 2026-08-20 — the userspace release gate

`cargo fmt --all --check`, `cargo clippy --workspace --all-targets
--all-features -- -D warnings`, **874 Rust tests in 55 suites**, `cargo deny
check licenses advisories`, `go build ./...` and the Go `karst` packages: all
clean.

The privileged suites were **all** run for this pass, which the previous entry
could not say: `karst-tun` device (9), `karstd` two-node (9, 219 s), the
**eleven aquifer topologies (474 s)**, and the new
`bins/karstd/tests/userspace.rs` (2). The aquifer matters here because the fix
for finding 34 is in the session state machine, on every datapath in the tree.

Nine defect injections, each restored afterwards:

| Defect | Caught by |
|---|---|
| `Userspace::send` drops the packet | the gate — ADR-0012 requires this one |
| `recv_segments` returns nothing | the gate — ADR-0012 requires this one |
| the `setpriv` wrapper is removed | the gate *and* the instrument check |
| `--bounding-set=-all` is removed | the gate's `CapBnd` assertion alone |
| status reports `config.interface` | the gate's device-name assertion |
| `tx_packets` is not counted | the gate's packet-count assertion |
| the far end reflects instead of answering | the gate's payload comparison |
| the outstanding handshake is discarded | three of the four simultaneous-open tests; the asymmetric control still passes |
| `pending` is cleared on `handle_response` | `a_simultaneous_rekey_carries_traffic` alone |

The last two rows are the point of the exercise: each fix has a test that fails
without it, and the control test passes in both cases, so "keep the handshake"
cannot silently become "always keep one in flight".

The gate was also run **three times consecutively** after the fix. That is not
ceremony: finding 34 presented as a first run that passed and three that
failed, so a single green run would have proved nothing.

### Validation, 2026-08-20 — row 8b

`cargo fmt --all --check`, workspace clippy, 874 Rust tests in 55 suites, and
the **twelve aquifer topologies in 507 s** — which includes row 8 still
relaying, so adding 8b did not quietly change the row it exists to be contrasted
with.

Row 8b measured **direct in 37 s**. Two defect injections, both restored:

| Defect | Result |
|---|---|
| `KARST_AQUIFER_DISABLE_PORT_MAPPING=1` | times out after 210 s of trying — the mapping is what carries the row |
| A's carrier NAT also serves `miniupnpd` | fails the one-sided assertion in 4 s |

The first is the load-bearing one and it is stronger than it looks: the
candidate sets are **identical** across those two runs, because the fixture pins
B's outbound source port either way, so B's reflexive address already equals its
mapped address. The only thing that differs between direct-in-37-s and
never-converging is whether B's NAT admits the probe. That is the evidence for
the claim that the mapping's *inbound* half is what closes this pairing — not
the fourth candidate tier, which is what closes row 9.

The second guards the row's premise rather than its result. Row 8b is worth
having only if the mapping is on the **home router** and not on the carrier
equipment the CGNAT subscriber cannot ask for anything; an assertion that A got
no mapping is what keeps it that row.

### Validation, 2026-08-20 — the privileged suites in CI

`cargo fmt --all --check`, workspace clippy, and **874 Rust tests in 55
suites**: clean. The change is to CI and to three test files, so the evidence
that matters is that each suite passes under **the exact command line CI
uses** — `sudo env "PATH=$PATH" "KARST_REQUIRE_PREREQUISITES=1" <bin>
--ignored --test-threads=1` — rather than under `just`:

| Suite | Result |
|---|---|
| `karstd` userspace (ADR-0012's gate) | 2 passing, 2.5 s |
| `karst-portmap` gateway | 4 passing, 3.4 s |
| `karstd` aquifer | **12 passing, 507 s** |

The aquifer figure is the same 507 s as the row-8b pass, which is the point of
quoting it: running it the CI way changed nothing about what it measures.

The refusal to skip is checked in both directions, on all three suites, because
a gate that cannot be observed failing is a gate nobody has tested:

| Condition | Required behaviour | Observed |
|---|---|---|
| `KARST_REQUIRE_PREREQUISITES=1`, non-root | fail | `missing: ["root"]` |
| `KARST_REQUIRE_PREREQUISITES=1`, root, `PATH` without `/usr/sbin` | fail | `missing: ["nft", "miniupnpd"]` |
| unset, non-root | skip, pass | skipped |
| set, everything present | run | passed |

The second row is the load-bearing one: it is the runner-image regression the
whole change exists to catch, and it names the two tools rather than reporting
success. It also demonstrates why the job adds `/usr/sbin` to `PATH` itself —
that row is what a GitHub runner would produce if it did not.

The workflow file was parsed rather than eyeballed, and the `aquifer` job's
steps enumerated from the parse, since a YAML error here fails only on push.

### Validation, 2026-08-21 — the double-NAT row

`cargo fmt --all --check`, workspace clippy, and the full Rust suite: clean, now
**877 tests in 55 suites** — the three new `karst-portmap` units for finding 37.
Each of the three fails against the old predicate and passes against the new
one, which was checked by reverting the predicate rather than asserted.

**Thirteen aquifer topologies in 542 s**, up from twelve in 507 s: the new row
costs 35 seconds and changed nothing about the twelve it joined. Row 11 —
`a_subscriber_behind_carrier_grade_nat_reaches_a_public_peer` — reaches a direct
path in **35 s**, with node A behind its own router behind a carrier's symmetric
NAT on RFC 6598 space.

A's port-mapping status at the end of the row, which is the half worth quoting:

```
portmap_state    = "retrying"
portmap_gateway  = "10.98.1.1:5351"
portmap_protocol = "pcp"
portmap_external = "-"
portmap_reason   = "PCP failed transiently (PCP code 8); retrying"
```

PCP code 8 is `NO_RESOURCES`, and it is the same code a raw probe gets out of
`miniupnpd` when its external address is 100.64.0.2 — so the daemon's path and
a hand-built datagram agree about what the gateway said.

Three mutations, each restored:

| Mutation | Result |
|---|---|
| the carrier forwards without translating | fails in 31 s — node A cannot reach the coordination server at all, so the second stage is load-bearing before discovery is even reached |
| the router serves no PCP | fails on the new assertion — `"the gateway did not answer PCP"`, after reaching a direct path in 31 s, so the failure is isolated to the port-mapping half |
| the carrier made a cone rather than symmetric | **passes**, direct in 35 s |

The third is reported because it is a negative result and belongs in the record:
the row does not depend on the carrier's flavour for its outcome. The symmetric
carrier is there because that is what carriers are — the instrument row
`a_subscriber_behind_a_carrier_nat_is_translated_twice` pins it — and not
because the row would pass without it.

**Two assertions in the row are guards that no mutation here makes fire**: that
B holds neither the router's 100.64 address nor A's private one. No cheap
mutation of the fixture produces either, because nothing advertises them —
which is the point of writing them down. They constrain a future change to
candidate selection, not this fixture.

### Validation, 2026-08-21 — ADR-0012's gate 1

`cargo fmt --all --check`, workspace clippy, **877 Rust tests in 55 suites**:
clean. Every privileged suite was run, because this pass changed `karst-tun`
and `karstd`'s datapath attachment rather than a test:

| Suite | Result |
|---|---|
| `karst-tun` device | 9 passing, 1.7 s |
| `karstd` two-node | 9 passing, 217 s |
| `karstd` userspace (the gate) | **3** passing, 1.2 s — the half-close row is new |
| `karstd` aquifer | 13 passing, 544 s |

The measurement itself is in
`docs/measurements/userspace-cost-2026-08-21.md` with its host details and
commands; the numbers are not repeated here.

**Finding 39 is checked against its own defect, and the control is the point.**
Restoring the old `Ok(0) => { tcp_close; return }` makes
`a_half_closed_request_still_receives_its_reply` fail with *"the reply was
truncated after the half-close"* — and leaves
`a_tcp_conversation_crosses_userspace_mode_without_cap_net_admin` **passing**.
That is precisely how a feature with a release gate shipped with this in it:
the gate writes a fixed-size request, reads a fixed-size reply, and never
half-closes.

**Finding 40 is checked by measurement rather than by assertion**, which is the
honest form for a latency figure, and the three poll settings were each run on
the same host in the same session:

| Poll | RTT p50 | Throughput |
|---|---|---|
| flat 2 ms (as found) | 4.135 ms | 1.1 Mbps |
| flat 200 µs | 0.545 ms | 9.9 Mbps |
| adaptive (shipped) | 0.547 ms | 5.6–7.3 Mbps |

The middle row is not the shipped one on purpose: it buys the same latency by
waking every idle connection 5,000 times a second. The third row's throughput
spread across three runs is wider than the second row's single sample, and no
claim is made that the two differ — at 200× below the privileged path, the
remaining variance is not where the interesting number is.

**What the harness does not establish.** One flow, one peer, one connection, on
a veth underlay carrying 130+ Gbps. It compares two modes on one host; it is
not a link measurement and PLAN.md §3.4's figures are not comparable to it.

### Validation, 2026-08-21 — the 71× window (finding 41)

`cargo fmt --all --check`, workspace clippy, the full Rust suite and every
privileged suite, re-run after the change to `karst-tun`'s socket construction:

| Suite | Result |
|---|---|
| workspace | 877 passing in 55 suites |
| `karst-tun` lib | 64 passing |
| `karst-tun` device | 9 passing |
| `karstd` two-node | 9 passing |
| `karstd` userspace (the gate) | 3 passing, and **4** once the bulk row below was added |
| `karstd` aquifer | 13 passing |

The measurement, three runs of each scenario on the same host and harness:

| Step | Throughput | RTT p50 |
|---|---|---|
| as found | 1.1 Mbps | 4.135 ms |
| poll fix (40) | 5.6–7.3 Mbps | 0.547 ms |
| batched `recv_segments` | 7.3 Mbps — **no change** | — |
| 64 KiB socket buffers (41) | **514.8, 515.9, 516.8, 518.5 Mbps** | 0.544–0.549 ms |

**The final figures are quoted individually rather than as a range** because
their spread — under 1% across four runs — is itself the evidence that the
window was the constraint. The 5.6–7.3 Mbps before it varied by 30% run to run,
which is what a number decided by timing races looks like; a number decided by
a window does not move.

Memory moved with it and by the right amount: the subject's peak resident set
went from 6,656 kB to 6,700–6,784 kB against a peer holding steady at ~6,560 kB.
Two 64 KiB buffers is 128 kB, and the row shows 140–220 kB with run-to-run
noise. A memory column that had *not* moved would have meant the buffers were
not being allocated and the throughput change came from somewhere unexplained.

**And the defect was put back**, which is how the 36.7 s figure above exists.
`SOCKET_BUFFER` returned to one MTU fails the new bulk row at 8 MiB in 36.7 s
and leaves the other three userspace rows passing — the same shape as finding
39's check, and the same conclusion: the rows that existed before could not see
this, one at a time or together.
