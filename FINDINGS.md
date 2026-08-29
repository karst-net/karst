<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Karst implementation findings

First reviewed 2026-08-15. Re-verified against the working tree on 2026-08-18,
again after the Phase 4 discovery work later that day, and again on 2026-08-19
after the NAT matrix was extended and measured.

This report records defects found by tracing implementation paths and their
tests. It does not treat the plan or source-code comments as proof that a
feature is correct.

All nine original findings are closed. The re-review and the Phase 4 work that
followed it added forty-three more, and all of them are now closed — most found by
building the thing the finding above them asked for, several found by counting
what the test matrix did *not* cover, three found by writing a release gate for
a feature nobody had ever run, two by building the double-NAT row the exit
criterion names, three by **measuring** a feature that had already been proved
to work, two by asking what a deployment needs that only a test fixture was
providing, one by building the second half of a feature and looking at what the
first half did with what it allocated, one by asking what a topology Karst has
never been run on would need before it could be run on at all, one by then
running that topology, one by injecting a defect into a passing test and
watching it stay green, one by asking which CI job already installed a tool a
new row needed, two by reading a CI log that a previous fix had made legible,
one by building an end-to-end test for a mechanism whose unit tests all
passed, and the last three by installing a package that CI had been building
and uploading, green, for weeks.

**Findings 59 to 62 are the packaging set, and they share one cause.** They
came out of the first run of `scripts/package-verify.sh`, which does nothing
cleverer than install the `.deb` and `.rpm` on Debian 12, Ubuntu 24.04, Fedora
41 and RHEL 9 and look at what happened. Three of the four are release-blocking
and none of them is subtle; the reason they survived is that nothing had ever
performed the install. `plans/phase-5/09-exit-criteria.md` §2 names exactly this
gap — "do not describe package definitions alone as a published installer
experience" — and it was right.

**Findings 42 and 43 are worth naming as a category.** They are one
commit apart, and both are components that exist only in the test harness — a
roster refresher and a relay registry — with production reading the field the
harness filled in. Neither could fail a test, because in a test the missing
piece is present. They surfaced the week the tree acquired its first deployment
artefact, which is the only vantage point from which either is visible.

58 is the most recent closed one: a two-kilobyte signature increase aborting
the relay's tests with a stack overflow, which was a margin problem rather than
a size problem. 57 is beside it and the one worth reading: a lockout guard
that always demanded the whole network be acknowledged, because it read a table
no code ever wrote. 55 is beside it: a head exchange
that had ten passing unit tests and sent in only one direction, because the
event it hooked fires for one of the two roles.

**Six findings are open.** Two of them — 67 and 68 — are a live gap rather than scope or design: deprovisioning does not meet the timing PLAN.md §4.4 requires, and the work planned to fix it was costed against a stream the node does not hold. The other four are as they were. 53 is scope, and it is
now load-bearing: **CNSA 2.0 is a mandate as of 2026-08-25 (ADR-0015)**, so
AES-256-GCM — named in the suite registry and, for a long time, implemented
nowhere — is the first item of a Category 5 transition rather than a
hypothetical. **The data plane is now finished, and ChaCha20-Poly1305 is gone
from it entirely** (ADR-0015 item 7): both remaining suites run AES-256-GCM, so
no PHREATIC registry row describes something the binary does not do and nothing
in the data plane sits outside a FIPS boundary. The control channel and the
netmap cache still hardcode ChaCha20-Poly1305 and ML-KEM-768, which is what
keeps 53 open — and what remains there is dispatch, not cryptography. 54 is a constraint: PHREATIC's transport type byte sits outside
the AEAD, which is harmless while only one encrypted type exists and becomes a
redirection bug the moment a second one is added. 56 is a design gap: audit
anchoring cannot run on a timer without a capability-scoped authority, because
anything holding an authority key can also countersign nodes. 62 is the newest,
and it is a question rather than a bug: the DNS revert record is written under
`/run/karst`, which the unit's own `RuntimeDirectory=` deletes on stop, so the
recovery the docs offer by hand has nothing left to read on the one path the
record exists for. Among the closed ones, 52 is the most recent and the one worth reading:
RFC 3542's `ICMP6_FILTER` uses a set bit to *block*, this code assumed it meant
*pass*, and so PREF64 discovery admitted every `ICMPv6` type except the one it
existed to receive. Every unit test passed — the parser was right, the
solicitation was right, and the answer was thrown away by the socket before any
Rust in the tree saw it. 51, beside it, closes a sub-issue deferred from 45: a
node that cannot use IPv6 now says so. Before them, 49 and 50, and both came out of
a CI failure that an earlier fix had made readable — 49 is a real defect in the
inbound path (a socket mid-handshake is indistinguishable from one that will
never send again, so a published port half-closed its backend before the request
arrived), and 50 retires a wall-clock budget that could not be set correctly for
the range of machines it runs on. Before them, 46, 47 and 48, all from
2026-08-21 and all from actually building the NAT64 row rather than reasoning
about it. 48 is the one worth reading first: the *instrument* row for the same
topology had skipped on every CI run since it was written, because the job that
runs it never installed `tayga` and the suite skipped quietly — the exact
failure mode a paragraph in PLAN.md claims was closed the day before, in work
that reached three suites and not the fourth.
46 is what the first run found: a node on a NAT64-only network could reach
nothing at all, because every address it is handed is an IPv4 literal and it has
no IPv4 route to any of them. 47 is smaller and stranger — a test written to
catch half of 46's fix could not fail, because the prefix chosen to make the
test possible was the one prefix that made it vacuous.

Before them, 45, found on the way to the same row while checking that IPv6 worked
at all: a dual-stack node learned every IPv4 peer at a v4-mapped address and
handed it back as that peer's reflexive address, which no IPv4-only node can
send to. The node itself worked throughout, which is why nothing caught it.

Before it, 44 — found the same day by building userspace mode's inbound
attachment: the *outbound* path had been leaking a TCP socket and its 128 KiB of
buffers per connection since the day it shipped, and no test of bytes could see
it because every conversation it leaked was correct.

Before it, 38 was the last open one, closed the same day: a node whose
gateway can never help used to ask it again every five seconds for the life of
the process, which is what *every* node without a port-mapping service had
always done. The classification was right and the schedule was not, so the fix
is RFC 6887 §8.1.1's own backoff — doubling to a 1024-second cap, resetting on
any answer, never giving up — and its deferral reason did not survive contact:
a schedule that is a pure function of its own history needs no injectable
clock.

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
| 38 | Low | A gateway that cannot ever grant a mapping is asked again every five seconds | Fixed 2026-08-21 |
| 39 | High | The SOCKS5 relay treated a client half-close as a full teardown | Fixed 2026-08-21 |
| 40 | Medium | Userspace mode's round trip was a poll interval, not a cost | Fixed 2026-08-21 |
| 41 | High | Every userspace TCP socket advertised a one-segment window | Fixed 2026-08-21 |
| 42 | High | Nothing outside the test fixture kept a relay's roster fresh, so a deployed relay stops admitting nodes after 90 s | Fixed 2026-08-21 |
| 43 | High | A production coordination server published no relays at all; only the test server ever set the netmap's relay registry | Fixed 2026-08-21 |
| 44 | High | Userspace mode never reclaimed a TCP socket, so a sidecar grew by 128 KiB per connection for the life of the process | Fixed 2026-08-21 |
| 45 | High | A dual-stack node learned every IPv4 peer at a v4-mapped address and advertised it back as that peer's reflexive address, which no IPv4-only node can send to | Fixed 2026-08-21 |
| 46 | High | A node on a NAT64-only network could reach nothing at all: every address it was handed was an IPv4 literal and it had no IPv4 route | Fixed 2026-08-21 |
| 47 | Low | The first NAT64 socket test could not fail, because the prefix it chose let an earlier rewrite do the work | Fixed 2026-08-21 |
| 48 | Medium | The NAT64 instrument row skipped on every CI run since it was written, and reported success each time | Fixed 2026-08-21 |
| 49 | High | A published port half-closed its backend before the request arrived, because a socket mid-handshake looks exactly like one that will never send again | Fixed 2026-08-21 |
| 50 | Medium | The bulk row's wall-clock budget could not separate healthy from defective across the range of machines it runs on | Fixed 2026-08-21 |
| 51 | Medium | An `AF_INET` node dropped every send to an IPv6 candidate in silence, with no log line, counter or symptom but never connecting | Fixed 2026-08-21 |
| 52 | High | `ICMP6_FILTER` was written inverted, so PREF64 discovery admitted every ICMPv6 type except the one it wanted | Fixed 2026-08-21 |
| 59 | High | Every Linux package shipped a binary that cannot start on Debian 12 or RHEL 9, and installs cleanly on both | Fixed 2026-08-28 |
| 60 | Medium | Removing the node package left the daemon running and a dangling enablement symlink behind it | Fixed 2026-08-28 |
| 61 | Medium | No package created `/var/lib/karst`, so the documented netmap cache path did not exist and had no mode | Fixed 2026-08-28 |
| 62 | Low | `RuntimeDirectory=karst` deletes the DNS revert record on stop, so the documented manual recovery has nothing to read | Open |
| 63 | Medium | The portal's session history was audit rows: every entry reported a null end time and a null address | Fixed 2026-08-28 |
| 64 | Medium | The portal's Playwright suite has never run in CI — only the console's | Fixed 2026-08-28 |
| 65 | Medium | The download manifest generator named a Windows MSI and a `.deb` the pipeline does not build, so it could not succeed, and the fixture served the same invented names | Fixed 2026-08-28 |
| 66 | Medium | Exporting an audit anchor before the Bedrock genesis answered 500, where every sibling precondition on the same surface answers 412 | Fixed 2026-08-28 |
| 67 | High | Deprovisioning takes as long as the netmap poll — measured at 48.9 s on a settled node, over the 30 s CI gate | Open |
| 68 | High | The push that would fix 67 was costed against a persistent control stream the node does not hold: it opens one per sync and closes it | Open |

## Closed

### 69. High: userspace mode's SOCKS5 attachment never worked on macOS

**Found 2026-08-29** by the first CI run of `bins/karstd/tests/macos_pair.rs`.
Fixed the same day.

`socks5::serve` polls a non-blocking listener, and **whether an accepted socket
inherits `O_NONBLOCK` is a platform decision POSIX declines to make.** Linux's
`accept(2)` explicitly does not inherit it; BSD's and macOS's explicitly do. So
the negotiation that follows ran blocking on Linux and non-blocking on macOS,
and `negotiate` uses `read_exact`, which reports `WouldBlock` as a failure
rather than waiting for the bytes.

SOCKS5 is a round trip, and that is what made this total rather than
intermittent. The client sends its `CONNECT` only after reading the method
selection, so the daemon's `read_exact` for the request is always issued before
those bytes can have arrived. Every connection failed at the same place, every
time. The client saw its greeting answered and then an EOF — no SOCKS error
code, because the failure is upstream of the code path that sends one.

ADR-0012's whole outbound attachment was therefore dead on macOS while every
Linux test passed, and nothing said so. `tests/userspace.rs` is the suite that
covers this surface and it is Linux-only by construction — it drives `setpriv`
and reads `/proc` — so no amount of running it could have found this.

**The knowledge was already in the tree.** `run.rs`'s control-socket accept
clears the flag and carries a comment saying why, which is why `karst status`
kept working on macOS and made the daemon look healthy. Two other accept sites
behind a non-blocking listener never got the same treatment.

The second is `karst_dns::listener::serve_tcp_once`, fixed here as well. Its
exposure is smaller and its failure worse to diagnose: a DNS client sends its
query without waiting for anything, so the bytes are usually already there and
the request usually succeeds — it would have dropped TCP DNS requests
intermittently on macOS, under load, and only there.

Both now ask for blocking explicitly rather than inheriting whatever the
platform decided. What found it was running the product on the platform: the
pair test reproduces the failure on macOS and passes after the fix, and
`KARST_PAIR_ON_HOST=1` runs the same rows against a Linux TUN, which is how the
fault was localised to the platform rather than the arrangement.

Noted and not fixed, because it is neither new nor platform-specific:
`serve_tcp_once`'s `read_exact` on an accepted socket has no timeout, so a
client that connects to the tunnel's TCP DNS port and sends nothing holds that
worker thread indefinitely. That is today's behaviour on Linux too, and this
change makes macOS match it rather than introducing it.

### 68. High: the netmap push was costed against a stream that does not exist

**Found 2026-08-28** while scoping the push that finding 67 needs. Open.

`plans/phase-5/08-scim-and-groups.md` §2 chooses server-initiated push over a
shorter poll, and justifies the cost this way:

> The stream is already bidirectional and already exists for exactly this
> reason. The server loop becomes a select over "a request arrived" and "this
> node's map changed"; the node's reader must accept an unsolicited envelope.

**The node holds no such stream.** `Connection::open` appears exactly once in
production code — inside `Client::sync` in `bins/karstd/src/control.rs` — and
the connection it returns is a local that is dropped when `sync` returns. A
node opens a control connection every 60 seconds, logs in or fetches, and
closes it. Between syncs the server has nothing to push *to*.

The server half of the description is accurate: `Session` is a bidirectional
RPC and its loop is strictly receive-then-send. The node half is not, and it is
the half the estimate rested on.

So the work is not "a select and a reader". It is:

1. karstd holding a control connection open across syncs, with the reconnect,
   backoff and keepalive that a long-lived connection needs and a
   once-per-minute one does not;
2. a way to tell a push from a response on the wire, since
   `Connection::request` currently treats the next server message as its own
   answer and would consume a push as one;
3. the server tracking which nodes are attached and to which account, so a
   change can be aimed;
4. and only then the select.

Recorded rather than fixed because the estimate is what changes: "one week of
Go and half a week of Rust in W6" was costed against item 4. Items 1–3 are the
work, item 1 is a change to how the daemon talks to the control plane at all,
and none of it should be started against a plan that says the stream is already
there.

### 67. High: deprovisioning takes as long as the poll, and the poll is the budget

**Found 2026-08-28** by building the measurement
`plans/phase-5/08-scim-and-groups.md` §3 asks for. Open.

PLAN.md §4.4 requires that removing a user "must expire their node keys and
drop their sessions **within 60 seconds**", and
`plans/phase-5/09-exit-criteria.md` §6 wants it "measured under 30 s in CI".
Neither had ever been measured.

`a_revoked_peer_loses_its_session_inside_the_deprovisioning_budget` measures
it: two nodes converge on a direct path and carry TCP, the fixture removes one
from the account, and the survivor probes the overlay once a second until it
stops answering.

**48.9 seconds.** Comfortably past the 30-second CI gate, and inside the
60-second requirement only because that is where this sample happened to land —
a settled node notices a revocation on its next netmap refresh, and the refresh
interval *is* 60 seconds, so the observed delay is spread across it. SCIM's own
latency then lands on top of whatever it was.

**§3's other question is answered, and answered well.** The plan asked whether
removal from the netmap even tears an established session down, warning that if
it did not, "the deprovisioning requirement is unmeetable regardless of how
fast the netmap arrives". It does: the survivor's roster loses the peer, its
flow cache is cleared, and traffic stops. The problem is entirely latency,
which is the better of the two answers — the datapath is right and only the
notification is slow.

**The first version of this measurement said 4.1 seconds and was wrong.** The
control loop syncs early whenever the node's home relay changes, and a node
that has just started changes it several times while AVEN and the reflector
settle, so the revocation was picked up by a sync that a node connected for an
hour would never have made. The row now settles the node first, which is the
node the requirement is about. A measurement of a freshly-started daemon would
have reported this problem as already solved.


### 66. Medium: the audit-anchor export answered a missing precondition with a 500

**Found 2026-08-28** by driving every mutating console route against the real
account manager for the first time. Fixed the same day.

`POST /bedrock/audit-anchor/export` handles two preconditions by name —
`audit.ErrEmpty` and `bedrock.ErrNothingToAnchor` — and both become a 412 with
a sentence explaining what is missing. `PrepareAnchor` has a third,
`bedrock.ErrNoLog`, returned when the account has no Bedrock log at all. The
handler had no branch for it, so it fell through to the generic error path:

```
POST /karst/v1/bedrock/audit-anchor/export -> 500 {"message":"internal server error"}
```

**That is the state every account is in before the genesis ceremony**, which
makes it the first thing an administrator who finds this button hits. They are
told the server broke.

The comparison is what makes it clearly a defect rather than a rough edge:
`POST /bedrock/requests/export`, three handlers away, answers the *same*
missing genesis with `412` and "Bedrock genesis must be imported before node
signing requests can be created". One export explains the missing ceremony; its
sibling reported a fault.

Found because the new real-server table asserts an administrator is never
refused and lands on an expected status, and 500 is not a status any route on
this surface should reach from an empty account. None of the handler-level
tests could have found it: they drive the same route against a `bedrockLog`
double whose `PrepareAnchor` never returns `ErrNoLog`.


### 65. Medium: the download manifest described artefacts nothing builds

**Found 2026-08-28** by tracing the portal's download page back to what
produces its data. Fixed the same day.

`scripts/release-manifest.sh` named three exact files, one of them
`karst-windows-amd64.msi`. There is no Windows client — it is Phase 8 — so the
script's `test -f` could never pass against a real release directory, and it
was wired into nothing. Its `karst-linux-amd64.deb` was equally invented: the
pipeline builds `karst-client_<version>_<arch>.deb`.

**The fixture agreed with the script rather than with the pipeline.**
`web/tools/karst-api-mock.mjs` served those same three names, so the portal's
download test passed against a manifest describing files that have never
existed, for a page that would have been empty in production. That is findings
42 and 43's category again — a component that exists only in the test harness —
and it is the third time this shape has appeared.

The generator now discovers artefacts and fails if it finds none, which also
fixed something the fixed list could not express: since finding 59 the client
ships as `.deb` and `.rpm` for amd64 and arm64, so "the Linux download" names
four files. The page offered exactly one, chosen by first match, and was
therefore wrong for three users in four. It now lists every build for the
detected platform with its architecture, format and checksum, because a browser
cannot be asked what architecture it is running on and guessing hands somebody
a package that will not install.

### 64. Medium: the portal's browser suite has never run

**Found 2026-08-28** while adding a download test to it. Fixed the same day.

`web/portal` has a Playwright config, seven tests, and an axe sweep over all
four routes. CI's `web` job runs `--filter console test:e2e` and nothing else,
so none of them has ever executed on a push.

The suite passes, which is the least reassuring possible outcome: it means the
portal's accessibility and self-service flows have been correct *and unverified*
for as long as they have existed, and nothing would have said otherwise the
first time they were not. Finding 48 was this exact shape — a suite reporting
success by not running — and the lesson recorded there was to check that a
check runs, which is a habit and not a fix.

### 63. Medium: the portal's session history was audit rows with the interesting fields removed

**Found 2026-08-28** from the use-case review's own list
(plans/phase-5/05-user-portal.md §1). Fixed the same day.

`GET /me/sessions` mapped audit-log entries to session rows:

```go
items = append(items, map[string]any{
    "started_at": entry.CreatedAt, "ended_at": nil, "device": entry.Target, "ip": nil})
```

Every field but the first was wrong. `started_at` was when an administrative
action was logged, not when a device connected; `device` was an audit target;
and `ended_at` and `ip` were hardcoded null because the audit log does not know
either. The contract declares both nullable, so this was contract-legal and
useless — a page titled "My session history" that could not say when a session
ended or where it came from.

Nothing in the tree could have answered it. `SessionObservation` looks like the
right table and is not: it is a node's report about its *peers*, replaced
wholesale on each report, so it holds no history at all.

The answer was in the control channel, which already knows exactly when a
device attached and from where — it is serving the stream. `DeviceSession` now
records open, progress and close around the authenticated portion of
`Service.Session`, and the portal reads real rows filtered to the caller's own
devices.

Three things that were not obvious until the data existed:

- **A killed server records no ends.** Its streams' deferred closes never run,
  so those rows stay open, and closing them at the next startup would report a
  session that ended on Friday as having ended on Monday. Each row carries a
  last-seen time that advances with the node's requests, and recovery closes it
  there — accurate to the refresh interval and honest about being an estimate.
- **Revocation has to close the row itself.** The stream teardown normally
  records the end, but a user who has just revoked a stolen laptop must not be
  shown it as still connected because the two raced.
- **The address is the proxy's, behind a proxy.** The control channel
  authenticates itself (ADR-0011) and does not read a forwarded-for header,
  because a header the client sets is not evidence of where the client is. The
  schema says so rather than implying a device location the server cannot know.


### 62. Low: the DNS revert record is deleted by the unit that exists to use it

**Found 2026-08-28** while building the packaged-unit systemd check
(`scripts/package-systemd-verify.sh`), by noticing an assertion that passed
against a package with a deliberately broken hook path. Open.

`karstd.service` sets `RuntimeDirectory=karst`, and systemd's default
`RuntimeDirectoryPreserve=no` means it **deletes `/run/karst` when the unit
stops** — including `/run/karst/dns-revert`, the record
`plans/phase-5/01-karstdns.md` §7.1 introduces precisely so that a host whose
resolver was replaced can be recovered after the daemon is gone.

On the ordinary path this costs nothing: `ExecStopPost=` runs `karst dns
revert` before the directory is cleaned up, the host is restored, and the
record is consumed. It costs something on the path the record exists for. If
the hook does not run or does not succeed — a wrong path, a transient failure,
an operator who ran `systemctl stop` on a daemon that had already been
`SIGKILL`ed — systemd then removes the only description of what the original
resolver configuration was. `sudo karst dns revert`, which
docs/GETTING-STARTED.md §6.3 offers as the manual recovery, finds nothing to
revert and exits successfully, on a machine where every lookup is failing.

Not fixed here because the fix is a KarstDNS design decision rather than a
packaging one, and there are at least two:
`RuntimeDirectoryPreserve=restart`, which keeps the record across a restart but
still not across a stop; or moving the record to `/var/lib/karst`, which
survives both and raises its own question, since a record that outlives a
reboot describes a resolver configuration that `/run` being a tmpfs has already
reset. §7.1's own test plan says to assert recovery "across a reboot by leaving
the revert file and starting cold", which cannot happen with the file under
`/run` at all — so the workstream should settle which of those it meant.

**What it cost as a test.** The check "the revert record was consumed" passed
whether the hook worked or not, because systemd deleted the directory either
way. It is removed rather than repaired, with the reason written where it was.

### 61. Medium: no package created the state directory the docs tell operators to use

**Found 2026-08-28** by the first run of `scripts/package-verify.sh`, on all
four supported distributions. Fixed the same day.

docs/GETTING-STARTED.md §6.3 configures `cache_file =
"/var/lib/karst/netmap.cache"` and tells the operator to `sudo mkdir -p
/var/lib/karst` by hand. No package created it, so the directory existed only
if someone read that line, and its mode was whatever their umask was.

That mode is not cosmetic. The netmap cache holds one pre-shared key per peer —
THREAT-MODEL R5 — so a default-umask `0755` publishes every PSK on the node to
every local user. The directory is now package content at `0700`, declared once
in the nfpm description so `rpm --verify` can check it, rather than created by
a postinstall where nothing would.

### 60. Medium: removing the package left the daemon running behind it

**Found 2026-08-28** by `scripts/package-verify.sh`'s removal section. Fixed
the same day.

The packages shipped no maintainer scripts at all. `dpkg --remove karst-client`
therefore deleted `/usr/bin/karstd` and the unit file out from under a running
service, which kept running — with its executable unlinked — until the next
reboot, and left
`/etc/systemd/system/multi-user.target.wants/karstd.service` pointing at a unit
file that no longer existed.

The dangling link is the part that bites twice. systemd complains about it on
every subsequent `daemon-reload`, and a later reinstall silently resurrects a
service the administrator never re-enabled.

Fixed with `preremove` scripts that stop and disable the unit — and only on a
real removal. The two packaging systems disagree about how they say so
(`dpkg` passes `remove`; `rpm` passes `0`), and a hook that acts on every
invocation turns an upgrade into an outage, so both dialects are matched
together. `packaging/scripts/preremove-karstd.sh` carries the reasoning, and
the upgrade case has its own assertion: a service the admin enabled must still
be enabled afterwards.

### 59. High: every Linux package shipped a binary that could not start on half the supported distributions

**Found 2026-08-28** on the first run of `scripts/package-verify.sh`, before
any of it had been wired into CI. Fixed the same day.

`deliverables.yml` built the release binaries on `ubuntu-latest`. A dynamically
linked binary records the highest glibc symbol version it uses, and that build
records `GLIBC_2.39`. Debian 12 has 2.36 and RHEL 9 has 2.34 — two of the four
distributions plans/phase-5/09-exit-criteria.md §2 says the docs will claim.

```
/usr/bin/karstd: /lib/aarch64-linux-gnu/libc.so.6: version `GLIBC_2.39' not found
```

**The package installs perfectly first.** `dpkg -i` succeeds, every file lands
in the right place with the right mode, and the failure arrives when the
operator starts the service. Nothing upstream of an install on a real
distribution could see it: the build was green, the packaging was correct, and
the artefact was broken.

Fixed by building in a `rockylinux:9` container — RHEL 9's glibc, public
repositories, no subscription — which puts the floor at the oldest distribution
in the supported set. `scripts/glibc-floor.sh` then asserts it next to the
compiler, so a change of build image fails in the job that made the change
rather than eight container jobs later. The guard was checked in both
directions: it passes the Rocky-built binaries and fails the
`ubuntu-latest`-built ones.

**Why this one was invisible for so long.** Finding 43 and finding 42 were the
same shape — components that existed only in the test harness — and this is the
next layer down. The tree has had package *definitions* since Phase 5 opened,
and a CI job that built them and uploaded them, and every one of those runs was
green. What none of them did was install the result on a distribution, which is
the only vantage point from which this is visible. §2 of the exit criteria
already said so in as many words: package definitions are not a published
installer experience.


### 58. Medium: the relay's connection future was 2 KB from overflowing a stack

**Found 2026-08-25** by moving identities to ML-DSA-87 (ADR-0015 item 5) and
watching the relay's test suite abort. Fixed the same day.

`serve` runs the TLS handshake, the Ponor handshake and the connection loop, and
an async fn's future holds every local that lives across an `.await`. That
future carried two 8 KB read buffers as **stack arrays**, plus the handshake
frames — and the frames grew from a 3 309-byte ML-DSA-65 signature to a 4 627-byte
ML-DSA-87 one.

That increase was enough to overflow the stack outright. Not to slow anything
down or to fail a bounds check: `fatal runtime error: stack overflow, aborting`.

**The margin was the finding, not the overflow.** A protocol change of two
kilobytes should not be able to do that, and the fact that it could means the
relay had been running close to a cliff nobody could see — there is no counter
for "how much stack is left", and the first symptom is a killed process.

Three fixes, in decreasing order of how much they matter:

- The connection loop's 8 KB buffer moved to the heap, and `read_more` now
  reads straight into its caller's spare capacity — which removes 8 KB from
  that future *and* removes a copy from the read path.
- The per-connection and mesh-dial spawns are `Box::pin`ned, so the state
  machine lives on the heap where growing it is a bounded cost rather than a
  cliff.
- Test threads get a larger stack through `.cargo/config.toml`, with the reason
  written there. The *test* futures are large by construction — helpers nest
  several deep and debug builds do not collapse the nesting — and boxing every
  test body would be noise rather than a fix. Release builds are unaffected.

Recorded because the trigger was incidental. Nothing about CNSA 2.0 caused
this; it revealed it. The next protocol field to grow would have found it just
as well, and later.


### 57. High: the lockout guard consulted a table nothing ever wrote

**Found 2026-08-25** by tracing plan item 10.13's console endpoints into the
tree, having just built the verified log they were supposed to read. Fixed the
same day.

`bedrock.Store` carried a `karst_bedrock_coverage` table, described as "the
derived state needed to make the enforcement decision deterministic".
**Nothing ever inserted a row.** The table was created by the migration, read
by `Store.Uncovered`, and written by no code anywhere.

So `Uncovered` returned *every* enrolled handle, always. The consequences ran
in the wrong direction from what a hollow safety check usually costs:

- `GET /karst/v1/bedrock` reported every node as uncovered, including nodes a
  quorum had properly countersigned.
- `PUT /karst/v1/bedrock/mode` to `enforcing` demanded that the operator
  acknowledge cutting off **the entire network**, by name, every time.

The guard exists because plan §7 says "turning on network lock is the single
most effective way to lock yourself out of your own network". A guard that
always presents the whole roster is one an operator learns to confirm without
reading — so the check most likely to be rubber-stamped was the one protecting
against the most expensive mistake in the feature.

**Deleted rather than filled in.** Coverage is a property of the verified chain
and `State.IsCovered` computes it. A table beside the log would be a second
answer to a question that has one, free to drift from the chain the nodes
themselves enforce against — and the console would have been showing the answer
that was *not* being enforced. `UncoveredAt` now derives from the chain, and
`SetMode` computes the required set itself rather than taking it from a caller
who might compute it wrongly.

Two things the fix pins that the old shape could not express. A node whose
handle is covered under *different keys* is uncovered — the substitution spec
§6.1 exists to catch, invisible to a table keyed on handle alone. And a nil
state, meaning no log, covers nobody, so enabling enforcement without a chain
still requires acknowledging every node by name.

**The stub endpoints around it were honest and that is why this was findable.**
`bedrockLog` returned an empty list and `bedrockLogVerify` returned 501, both
with a comment saying they would rather expose nothing than fabricate
cryptographic state. Had they invented plausible data, the coverage table would
have looked like it worked.


### 56. Open: audit anchoring cannot be automated without a capability-scoped authority

**Found 2026-08-25** while building plan item 10.14, "audit anchor entries on a
schedule". **Open — a design gap, not a defect.**

An `anchor` entry commits an audit-log head into the Bedrock chain, which is
what makes `audit.Log.VerifyFrom` able to detect truncation the audit chain
cannot detect itself. It needs one authority signature (spec §4 rule 8).

**The coordination server holds no authority key, and must not.** An authority
key is an authority key: whatever is given one can also countersign nodes, which
is precisely the capability Bedrock exists to deny a server that may be
compromised. So there is no arrangement in which a server both anchors on a
timer and cannot admit rogue nodes, and "on a schedule" cannot mean what it
sounds like.

What is built is the honest half: the server computes what should be anchored
and *prepares* the entry, and an authority signs it offline with the same
`karst-bedrock sign` ceremony a node-sign uses. The cadence is therefore how
often an admin runs it. `AnchorDue` exists so the decision is at least
consistent — entries advanced **or** time elapsed, because a pure interval
re-anchors a quiet log at the same point and a pure count never anchors a slow
one, which is the log whose truncation would be least noticed.

**The fix, if automation is wanted: capability-scoped authorities.** An
authority permitted to sign `anchor` and nothing else could live on the server
or on a monitoring host without being able to admit a node. That is a change to
the `authority-list` body in §3.4 — today the list is bare public keys and every
authority may sign every authority op — and it is a genuine addition to the
trust model rather than a refactor, so it is recorded rather than taken.

Worth noting the cost of *not* doing it: anchoring that depends on a human
ceremony is anchoring that stops happening, and an anchor that stops advancing
degrades silently — the old anchor keeps verifying, so nothing fails, and the
window of undetectable truncation just grows.


### 55. High: half of every Bedrock head exchange was never sent

**Found 2026-08-25** by writing plan §11's two-node equivocation test, the row
that had been deferred twice. Fixed the same day.

The peer head exchange (`bedrock-v1.md` §5 layer 3) sent its claim from
`Action::Established`, which reads like the obvious hook and is the wrong one.
**That action is produced for the handshake *initiator* only.** A responder
adopts its keys on the transport fast path — `engine.rs`'s §12.6 branch, which
calls `promote` directly and emits no action at all — so it never sent a claim.

Every exchange was therefore one-directional. The initiator learned whether its
peer agreed; the responder learned nothing and could not have raised an alarm
about anything. Equivocation between a pair where the lying server had put the
*responder* on the divergent chain would have gone unreported by both: the
responder never spoke, and the initiator was comparing against its own correct
copy.

**Nothing in the unit tests could see it.** `compare_head` had ten tests and all
of them passed — the comparison was right, the frame codec was right, the
multiplexing was right. What was wrong was which of two code paths reached the
sender, and there is exactly one vantage point from which that is visible: two
engines completing a real handshake and both being asked what they concluded.

The fix stops hooking an event. The claim is now driven from `poll`, gated on
comparing the current head against the last one claimed to that peer, which
both roles reach and which no future path to "established" can bypass. It is
also better behaviour than the original intent: once per *head* rather than
once per session, so a node whose log advances tells its peers instead of
waiting for the next handshake.

**Recorded as the third bug in this workstream that only an integration test
could find**, after `GenerateRoot`'s type assertion (which had never worked
because every fixture used `RootFromBytes`) and the identity-key binding. All
three were in code that unit tests covered thoroughly and from the wrong side.


### 54. Open: PHREATIC's transport type byte is outside the AEAD, so it cannot discriminate a second message type

**Found 2026-08-25** while designing Bedrock's peer head exchange (plan item
10.12), which needed a way to carry a control frame inside an established
session. **Open — a constraint to respect, not a live defect.**

`Transport::seal` writes the type byte `0x04` into the header and then encrypts
the body with an **empty AAD** (`karst-noise/src/transport.rs`). The header —
type, reserved bytes, peer index and counter — is authenticated only insofar as
the counter feeds the nonce. The type byte itself is not covered by anything.

**This is currently harmless and only currently.** `MessageType` has exactly
one encrypted type, and `open` rejects anything whose first byte is not `0x04`,
so flipping it turns a valid message into a dropped one and achieves nothing.

It becomes a defect the moment a second encrypted type exists. Adding, say,
`0x05` for a control frame would let anyone who can flip one bit in flight
redirect a tunnelled packet into the control handler, or a control frame into
the host stack — with the AEAD still verifying, because the AEAD never saw the
byte that decided where the plaintext went.

**Bedrock's head exchange therefore multiplexes inside the plaintext instead**,
on a `0x00` marker: zero is not a legal IP version, so it cannot collide with a
tunnelled packet, and it is covered by the AEAD like everything else in the
body. That is the right answer for this feature and it leaves the underlying
constraint in place for the next one.

**The fix, if a second outer type is ever wanted:** put the header in the AAD.
`encrypt_in_place_detached` already takes one and is passed `&[]`; passing the
four header bytes instead costs nothing per packet and is a wire-format change,
so it belongs with the next one rather than on its own.

Recorded because the obvious way to add a message type — a new `MessageType`
variant, which the enum invites — is the wrong one, and nothing in the code
currently says so.


### 53. Open: AES-256-GCM is specified and named but not implemented, and ChaCha20-Poly1305 cannot be FIPS-validated

**Found 2026-08-25** by asking whether ChaCha20-Poly1305 needs replacing for
post-quantum security and NIST compliance. **Open — this is scope, not a bug.**

> **Item 1 of the scope below is done, on the data plane only (2026-08-25).**
> `karst-crypto::aead` now holds both algorithms behind one `Cipher`, chosen by
> `Algorithm::for_suite`, and `karst-noise` dispatches on it through the
> `SymmetricState` and the transport instead of hardcoding ChaCha. `KARST_2` is
> in `Engine::new`'s `supported` list, so the one-line change warned about
> below has been made — safely, because the AEAD it names now exists. A test
> asserts every registry row selects the algorithm it advertises, and another
> that the two do not interoperate, so a future row cannot claim an AEAD it is
> not running.
>
> **The data plane is now finished, not just the AEAD (2026-08-25).**
> ADR-0015 item 1 landed: the CNSA suite runs end to end — ML-KEM-1024
> dispatched at run time, SHA-384, the no-X25519 variant, three fragments — so
> every row of the data-plane registry is a suite the binary can speak. That
> closes the shape of this finding for PHREATIC: the registry no longer
> describes anything it does not do.
>
> **And the second half of this finding is now answered too.** Item 7 removed
> ChaCha20-Poly1305 from the data plane outright and renumbered the registry to
> two rows, both AES-256-GCM: `KARST_1` (Category 3, ML-KEM-768 + X25519,
> SHA-512) and `KARST_2` (Category 5, the CNSA 2.0 profile). The paragraph below
> arguing that ChaCha "cannot run in the approved boundary — not because it is
> weak, but because it is not on the list" is the reasoning that was acted on;
> `karst-crypto` no longer depends on `chacha20poly1305` at all.
>
> **Note the renumbering when reading anything below this line.** `KARST_2` and
> `KARST_3` in the original text mean the rows now called `KARST_1` and
> `KARST_2`; `spec/phreatic-v1.md` §3.1 has the mapping.
>
> **The finding stays open for the other two layers.** The control channel and
> the netmap cache still hardcode ChaCha20-Poly1305 *and* ML-KEM-768. The
> channel at least has a suite mechanism (ADR-0015 item 4) — version 2 is
> reserved, named and refused honestly — and both primitives it needs now exist,
> so what remains there is dispatch in `channel.go`/`channel.rs` rather than
> cryptography. The cache has no suite mechanism at all, which is the weaker
> position of the two.
>
> Item 7 sharpened this: with the data plane clean, **the control channel is the
> only place in the tree a CNSA 2.0 or FIPS 140-3 deployment is
> non-conformant.** It has nothing else to be counted alongside any more.

> **Escalated the same day.** The answer to "is compliance a goal?" came back
> **CNSA 2.0 is a mandate** — see [ADR-0015]. Everything below stands; what
> changes is that the closing paragraph's "if NIST compliance is now a goal"
> is no longer conditional, and the gap is wider than the AEAD: CNSA 2.0 is a
> **Category 5** suite, so ML-KEM-768 → 1024 and ML-DSA-65 → 87 as well, and
> **SLH-DSA is not in the suite at all**, which puts Bedrock's offline root in
> question. ADR-0015 carries the full scope.
>
> [ADR-0015]: docs/adr/0015-cnsa-2-0-as-a-mandate.md

The two halves of that question have opposite answers, and conflating them is
how a deployment ends up doing unnecessary work or missing necessary work.

**Post-quantum: no swap is needed.** ChaCha20-Poly1305 is symmetric. Grover
gives a quadratic speedup on key search, so a 256-bit key retains ~128 bits
against a quantum adversary — the *same* margin AES-256 retains, for the same
reason. ADR-0001 already records this. The post-quantum problem is asymmetric,
and it is already answered by ML-KEM-768, ML-DSA-65 and SLH-DSA-SHA2-192s.
Replacing ChaCha with AES buys **zero** post-quantum security.

**NIST compliance: it matters, and it is not about strength.**
ChaCha20-Poly1305 is RFC 8439, an IETF specification. It is not a NIST
algorithm and is not FIPS 140-3 approved; AES-GCM is (SP 800-38D), and CNSA 2.0
requires AES-256. So a deployment needing FIPS 140-3 validation or CNSA 2.0
alignment cannot run ChaCha in the approved boundary — not because it is weak,
but because it is not on the list.

**ADR-0001 anticipated exactly this and the implementation never followed.**
The ADR specifies "ChaCha20-Poly1305 default, AES-256-GCM option", and
`karst-crypto`'s registry names two AES suites: `KARST_2` (AES-256-GCM) and
`KARST_3` (the CNSA 2.0 profile). Neither exists:

| Layer | What runs | Negotiable? |
|---|---|---|
| PHREATIC data plane | ~~`ChaCha20Poly1305`, hardcoded in `karst-noise/src/{symmetric,transport}.rs`~~ **fixed:** AES-256-GCM only — item 7 removed ChaCha from `karst-crypto` outright | Suite is negotiated and bound into the transcript, ~~but every suite runs ChaCha~~ and now selects the AEAD, hash and KEM |
| Control channel | `ChaCha20Poly1305`, hardcoded in `karst-control-client/src/channel.rs` | No negotiation; a version-implied suite with a floor since ADR-0015 item 4, and version 2 is reserved, not implemented |
| Netmap cache at rest | `ChaCha20Poly1305`, hardcoded in `karst-control-client/src/cache.rs` | **No suite mechanism at all** |

The registry is therefore a description of an intent, not of the binary. There
is no `aes-gcm` dependency anywhere in the tree.

**It is not currently a misreport**, which is the one piece of good news:
`Engine::new` sets `supported: vec![SuiteId::KARST_1]`, so `KARST_2` can never
be selected and no session can claim an AEAD it is not using. The bug that would
exist if `KARST_2` were offered today — a crypto posture view reporting AES over
a ChaCha session — is prevented by the feature being absent rather than by
anything checking. **Adding `KARST_2` to `supported` without implementing the
AEAD would create that defect**, which is worth knowing before someone does it
as a one-line change.

**Scope, if compliance becomes a goal:**

1. ~~An `aes-gcm` backend in `karst-noise`, selected by the already-negotiated
   `SuiteId`.~~ **Done.** The negotiation, the downgrade protection and the
   transcript binding were all already there; only the cipher was missing, and
   it took one new module and a field on `SymmetricState`.
2. The control channel and the cache have **no** suite mechanism, so each needs
   one — or a build-time choice. These are the harder half, and they are the
   half nobody has looked at, because ADR-0006's agility layer was designed for
   the data plane. *(The channel's half of this landed as ADR-0015 item 4; the
   cache's has not.)*
3. `KARST_3` additionally needs ML-KEM-1024, ML-DSA-87 and SHA-384, ~~none of
   which are implemented either~~ — the first two now are (ADR-0015 items 3
   and 5). SHA-384 is not, and neither is the dispatch that would let a session
   pick a KEM: `karst-noise` reaches ML-KEM-768 through a type alias, so its
   long-term keys are Category 3 by construction. `KARST_3` also drops X25519,
   which the handshake cannot express. **A primitive existing is not the same
   as a suite being reachable**, and the registry tests for both the AEAD and
   the KEM are written to claim only the former.
4. SHA-512 is FIPS 180-4 approved, so the hash is not a blocker.

**The premise this rests on has changed, and has now been re-recorded.**
ADR-0001's Context said the audience has "no identified CNSA 2.0 mandate and no
compliance deadline (PLAN.md §13 Q6)", and several decisions — the ChaCha
default, the Category 3 target, deferring `KARST_3` to Phase 7 — follow from
it. PLAN.md §13 Q6 is reopened and answered, ADR-0001 and ADR-0006 carry
amendment notices, and ADR-0015 records the scope. **This finding stays open
until AES-256-GCM exists**, which is the first item of that scope and the one
everything else waits behind.


### 52. High: a filter that admitted everything except what it was for

**Found 2026-08-21** by building an end-to-end test for RFC 8781 discovery
against a router written in another language. Fixed the same day.

RFC 3542 §3.2's `ICMP6_FILTER` is a 256-bit map, and **a set bit blocks**:
`ICMP6_FILTER_SETBLOCKALL` is all ones and `SETPASS` *clears* a bit. That reads
backwards to anyone who assumes a filter lists what it admits, and it was
written backwards here — block-all as zeros, then setting the bit for Router
Advertisements. The result passed every `ICMPv6` type except type 134.

**Nothing in the unit tests could see it.** The option parser was correct and
thoroughly tested against RFC 8781's field layout; the solicitation was correct
and went out correctly. The answer was discarded by the socket before any code
in this crate looked at it, so the only symptom was that discovery never found
a prefix — indistinguishable from a network with no NAT64 router on it.

The same misreading appeared independently in the Python router the test uses,
which filtered *out* the solicitations it was waiting for. Two ends written from
the same wrong assumption, which is exactly the failure mode an independent
implementation is supposed to prevent — and it still worked, because each end
failed at a different point and the test could not pass until both were right.

Injection-verified: restoring the inverted filter fails the row.

**The row exists because of this defect and would not have existed without it.**
The mechanism was three-quarters unit-tested and looked finished. What was left
was the quarter only a socket can exercise: that the filter admits what it
should, that a solicitation reaches the right multicast group out of the right
interface, and that what comes back starts at the byte the parser expects.

### 51. Medium: a node that could not use IPv6 and never said so

**Found 2026-08-21** — recorded as a named sub-issue of FINDINGS.md 45 on
2026-08-21 and deferred, then fixed.

`node.listen` decides the datapath's address family, because §4 gives it one
shared socket. A node listening on an IPv4 address has an `AF_INET` socket,
which cannot send to an IPv6 address at all — the kernel refuses with
`EAFNOSUPPORT`. That is correct behaviour for a node with no IPv6 connectivity.

**The problem was that every send path drops errors on purpose.** A full buffer
or an unreachable host must not take the daemon down, and the protocol
retransmits, so `dispatch` discards the result. A peer reachable only over IPv6
therefore produced no log line, no counter, and no symptom other than never
connecting — and "this node cannot use IPv6" was a fact no operator could read
anywhere.

The transport is what knows its own family, so that is where it is answered
now: a send to an unreachable family is refused before the syscall with
`ErrorKind::Unsupported` and a message naming `node.listen`, counted, and
reported once per process in the log. `karst status` prints
`ipv6 = "unreachable (node.listen is IPv4)"` on every such node — before the
first IPv6 candidate arrives as well as after, because the configuration is the
fact and a count of zero does not make it untrue.

### 50. Medium: a budget that could not be set

**Found 2026-08-21** by reading the CI figure the previous fix had put in the
log: 8.19 s, against a budget of 10 s that had just been widened from 5 s.
Fixed the same day.

`a_bulk_transfer_is_not_stop_and_wait` moves 8 MiB and asserts it finishes
inside a fixed time, which is the only way an end-to-end row can see finding
41's one-segment window. The trouble is the spread. Healthy is **1.34 s** on two
pinned cores here, **8.19 s** on a hosted runner, and **over 10 s** on a loaded
single core — six-fold — while the defect is only about 41x healthy on whatever
machine is doing the measuring. So the budget has to fall between "slowest
healthy" and "fastest defect", and across the machines this actually runs on
those two overlap. Any fixed number is too tight for a busy runner or too loose
for a fast workstation. Widening it once had simply moved the failure.

**The mistake was the instrument, not the number.** The property being asserted
— the advertised receive window — is a property of the socket and does not vary
with the machine at all. It is now asserted in `karst-tun` directly:
`a_tcp_socket_advertises_a_window_worth_having` reads the buffer capacity, costs
microseconds, cannot flake, and fails for exactly one reason. Injection-verified
by putting `SOCKET_BUFFER` back to one MTU.

The end-to-end row keeps a deliberately loose bound (120 s) as a smoke test —
8 MiB really does cross two daemons and a userspace TCP stack — and its failure
message now points at the window test rather than pretending to diagnose.

### 49. High: a published port answered before it had been asked

**Found 2026-08-21** from a CI log, after failing to reproduce it locally and
after a first hypothesis that turned out to be wrong. Fixed the same day.

The inbound row failed intermittently — about one run in ten, and only when run
after the rest of the suite, never alone. The daemon's log said everything:

```
karstd: publishing overlay port 19004 to 127.0.0.1:19005
karstd: overlay port 19004 from 10.88.3.2:49612: Broken pipe (os error 32)
```

**`is_active()` is true from `SYN-RECEIVED` onward.** `publish::serve` waited on
it to decide a listening socket had become a connection, so on a machine slow
enough to run that loop inside the handshake it handed `pump` a socket whose
handshake had not finished. In that state `may_recv()` is false — and `pump`
reads `!may_recv && !can_recv` as "the peer will send no more", which is exactly
right once a connection is established and exactly wrong before it is. So the
copy loop half-closed the backend immediately. The backend's `read_exact` got
`EOF`, returned an error, dropped its socket; the request then arrived, the
daemon wrote it, and got `EPIPE`. No reply was ever generated, and the test read
`EOF` where 64 KiB should have been.

**A wrong hypothesis, recorded because it cost two experiments.** The first
theory was that the fixture's single-accept backend had been consumed by an
abandoned connection from the test's connect-retry loop. It was disproved by
instrumenting the backend to log every accept and running the suite twelve
times: exactly one accept on the published port in every run, failures included.

Fixed at the accept point, where the mistake is — `publish::serve` now waits for
`may_recv`, the precise question of whether the connection can deliver bytes,
and reclaims a socket whose handshake started and then died rather than waiting
on it forever. `pump` carries a second guard: it will not believe a socket is
finished until it has been ready at least once.

The semantics that caused it are now pinned deterministically in `karst-tun`, by
driving a handshake one packet at a time and asserting the two answers that
together made the bug: `is_active()` true and `may_recv()` false after the `SYN`
and before the `ACK`. Twenty runs of the full suite on a single core, the
configuration that reproduced it, now pass.

### 48. Medium: the instrument row that has never run

**Found 2026-08-21** while adding `tayga` to the CI job for the *whole-aquifer*
NAT64 row, by asking which other job already needed it. Fixed the same day.

`crates/karst-disco/tests/nat_matrix.rs`'s
`a_nat64_path_carries_ipv6_to_ipv4_and_shares_one_port_space` begins by checking
for `tayga` and returning quietly if it is absent. The `tun` job that runs the
suite installs nothing. So the row has skipped on every CI run since it was
written on 2026-08-19 — printing one line into a log nobody reads and reporting
success.

**The measurement it produced is still real**, taken locally on a machine that
has `tayga`, and PLAN.md cites it correctly: an IPv6-only node's NAT64 path maps
endpoint-independently, which keeps every such node out of §7.7's hard class.
What was lost is the guarantee that it stays true. A regression in the fixture,
the kernel, or `tayga` itself would have been reported as a pass.

**This is the exact failure mode PLAN.md claims was closed on 2026-08-20**, in
the paragraph beginning "The suites now refuse to be quietly green". That work
added `KARST_REQUIRE_PREREQUISITES` to `aquifer`, `userspace` and `gateway` and
did not reach `nat_matrix` — which is the suite the §6 exit criterion is
*measured through*. The sentence was true of the suites it was written about and
read as true of all of them.

Fixed on both sides, because either alone leaves a hole: the `tun` job now
installs `tayga` and sets `KARST_REQUIRE_PREREQUISITES=1`, and every skip in
`nat_matrix.rs` — the root check included — now goes through a helper that
refuses to skip when that variable is set. Verified by running the suite as an
ordinary user with the variable set (fails, naming what is missing) and as root
with it set (thirteen rows, all executed, 21.58 s).

### 47. Low: a test that could not fail

**Found 2026-08-21** by injecting the defect it was written to catch, and
finding that it still passed. Fixed the same day.

`karst-transport`'s NAT64 test needed synthesised addresses that a machine with
no translator could still route, and `::ffff:0:0/96` looked ideal: it embeds
`127.0.0.1` as the v4-mapped loopback address, which a dual-stack socket
delivers to itself. The send worked, the datagram arrived, the source came back
as `127.0.0.1`, and the test was green.

**It was green because [`canonical`] had already rewritten the source, one line
before the NAT64 extraction ran.** The prefix chosen to make the test possible
was exactly the prefix that made it vacuous. Deleting the extraction entirely
left the test passing.

Rewritten around `::/96`, which embeds `0.0.0.1` as `::1` — a real IPv6 address
on loopback that only NAT64 extraction turns back into an IPv4 one. Removing
either half now fails it.

**The general shape is worth keeping.** A test written against a boundary that
already normalises will silently measure the normalisation instead of the thing
under test, and it looks identical from the outside: same assertion, same green.
The only way to tell the two apart is to break the code on purpose. Every fix in
this report is checked that way; this is the first time the check caught the
*test*.

### 46. High: a node on a NAT64-only network could reach nothing at all

**Found 2026-08-21** by building the whole-aquifer NAT64 row and running it
before writing any code — the first run failed in 30 seconds with
`karstd: server: transport: transport error`, before the node had finished
starting. Fixed the same day.

**Every address Karst hands a node is an IPv4 literal.** The control server
comes from its own configuration file, the relay from the netmap, the peer from
a call-me-maybe. On an ordinary network that is fine. On a NAT64-only network
the node has no IPv4 address and no IPv4 route, so all three are unreachable and
the node never gets past enrolment.

Nothing in Karst knew what a NAT64 prefix was. FINDINGS.md 45 had already
recorded that — "not RFC 7050's `ipv4only.arpa` heuristic, not RFC 8781's
PREF64" — as something the row would have to establish. It established it in the
strongest available way, by failing.

**What the fixture proved first.** Before concluding this was Karst's problem,
the NAT64 leg was probed on its own: `ping6` and a TCP connection from the
IPv6-only namespace to `64:ff9b::334b:a0a` both reached `51.75.10.10`. The path
worked; only the daemon could not name it.

**The fix is one rule applied at one boundary, plus two string rewrites.**
`prefix::v4` is the IPv6 address a translator turns back into `v4`, so:

- the datapath socket synthesises on send and extracts on receive, which means
  the engine above it goes on holding, comparing and advertising plain IPv4
  addresses on a host that cannot send an IPv4 packet;
- the relay's address and the control server's URL are rewritten once, at the
  point the configuration becomes real.

A **name** is left alone in both, and that is not a shortcut — DNS64 synthesises
for names already. Only a literal arrives unsynthesised, because nothing looked
it up.

**The extraction half is the one that matters and the row cannot see it.** With
the receive-side extraction deleted the aquifer row still passes, because a
synthesised address is one the NAT64 node really can reach — its own paths keep
working. What breaks is `Pong.observed` (`aven-v1.md` §7.2): the node hands its
IPv4 peer an address inside its own translator's prefix, the peer publishes that
as its reflexive candidate, and every IPv4-only node in the mesh is handed an
endpoint it cannot send to. That needs a third node to observe, so
`bins/karstd/tests/nat64.rs` observes it instead — a real socket, a real
`Disco`, and the `Pong` that comes out. Finding 45 is the same failure in its
other spelling, and this one is worse: a v4-mapped address at least names
somewhere real.

**RFC 6052's embedding is not concatenation** below /96. Bits 64–71 are reserved
and must be zero, so an address straddling them is split around the gap, and
five of the six legal prefix lengths do straddle. The implementation is checked
against §2.4's worked example copied verbatim from the standard rather than
against its own arithmetic. Lengths the standard does not define are refused:
assuming /96 for a /64 prefix does not fail, it synthesises a well-formed
address for the wrong host, and the only symptom is that nothing answers.

**Discovery is RFC 7050 and it is a heuristic, which the RFC says itself** (§3,
§6). It needs a DNS64 resolver on the path, and it trusts an unauthenticated
answer — a resolver that lies can choose where this node sends. That is bounded
by what Karst already assumes, since traffic is authenticated and encrypted end
to end, so a hostile prefix costs reachability rather than confidentiality. It
is nonetheless why discovery is gated rather than eager: `auto` will not even
ask unless the datapath is IPv6 *and* the host has no IPv4 address of its own.
The second gate matters — a host with both would otherwise route every IPv4 flow
through a translator it does not need, and learn a reflexive address belonging
to the translator rather than to itself.

**RFC 8781's PREF64 router-advertisement option is the better mechanism and is
not implemented.** It needs no DNS and no DNS64, and it needs a raw ICMPv6
socket to read router advertisements — so `CAP_NET_RAW` in a daemon that
otherwise wants only `CAP_NET_ADMIN`. That trade is declined rather than
overlooked.

### 45. High: a dual-stack node hands its IPv4 peers an address they cannot be reached at

**Found 2026-08-21** while establishing what a whole-aquifer NAT64 row would
have to assert — a row about an IPv6-only node needs IPv6 to work first, and
this is what was found on the way to checking that. Fixed the same day.

**`node.listen` decides the datapath's address family, and that is the whole of
Karst's IPv6 story.** §4 gives the datapath one shared socket and the operator
picks its family by writing an address. An `AF_INET` socket — `0.0.0.0`, which
is what every example in the tree writes — cannot send to an IPv6 address at
all; the kernel refuses with `EAFNOSUPPORT`, and `dispatch` drops the error
deliberately, because a send failure must not take the daemon down. So `[::]` is
the only configuration that can use an IPv6 path, and `aven-v1.md`'s candidate
encoding carries IPv6 addresses precisely so that one can exist.

On that socket, an IPv4 peer's datagrams arrive from `[::ffff:a.b.c.d]`, and
`SocketAddr::V4(x) == SocketAddr::V6(mapped)` is false in Rust, always.

**The obvious consequence is not the one that happens, and that is worth
recording.** The engine attributes a transport datagram to a peer by comparing
its source against the endpoint it holds, so this looked like a node that
establishes — handshakes are attributed by *key* — and then silently drops every
packet. It does not. Accepting a handshake *records the source address as the
peer's endpoint*, so the comparison is mapped-against-mapped and matches. The
node works.

What breaks is everything that lets that address out of the node:

- `karst status` prints an address that is not the peer's address.
- `set_endpoint` and `release_endpoint` compare against the netmap's IPv4
  endpoint and never match it.
- **`Pong.observed`.** This is the damage. AVEN answers a `Ping` with the source
  address it arrived from, which is how a node is told its own reflexive address
  (`aven-v1.md` §7.2). A dual-stack node tells its IPv4 peer that it is at
  `[::ffff:a.b.c.d]`; the peer believes it, advertises it in `CallMeMaybe`, and
  every IPv4-only node in the aquifer receives a candidate it cannot send to.
  One dual-stack node can make an IPv4 node unreachable to everyone else, and
  every symptom of it is silence: the sender's error is dropped, and the
  advertiser sees a peer that never answers.

The fix is one normalisation at the socket boundary — `karst_transport::canonical`,
applied in both receive paths, so no v4-mapped address ever enters the daemon
and there is exactly one representation of an address above the socket.
`source_key` maps the *other* way and stays as it is: a reassembly key wants
both families in one width and is not an address anything sends to.

The wire decoder gets the matching rule. `aven-v1.md` §6.2's endpoint encoding
already refuses a non-zero IPv4 pad, with the comment that an ignored tail is
"a covert channel and a second spelling of one address" — and `::ffff:a.b.c.d`
under family `0x06` is exactly a second spelling. It is now refused the same
way, so a peer running unfixed code, or a hostile one, cannot advertise a
candidate that only dual-stack nodes can probe.

**Two test layers, because neither sees the other's half.**
`karst-transport`'s `a_dual_stack_socket_reports_an_ipv4_peer_at_its_ipv4_address`
binds real sockets and pins what the *kernel* does — the first assertion is the
mapped-source claim itself, so a platform where it were false would say so
rather than leave the normalisation looking like superstition.
`bins/karstd/tests/dual_stack.rs` drives two engines with no socket at all and
pins what the daemon *does with* the result, modelling the receive path through
the same `canonical` the daemon calls. Removing that call fails both.

**Still open, and named rather than fixed**: an `AF_INET` node silently drops
every send to an IPv6 candidate. That is correct behaviour for a node with no
IPv6 connectivity, and the silence is `dispatch`'s deliberate policy, but it
means "this node cannot use IPv6" is a fact no operator can read anywhere. It
belongs with the NAT64 row, which is the remaining Phase 4 shape.

### 44. High: userspace mode never reclaimed a TCP socket

**Found 2026-08-21** while building the inbound attachment, by asking what an
accept loop should do with a connection once it is finished. Fixed the same day.
It is not a bug in the new code: it is a bug in the *outbound* path, which had
been shipping since 2026-08-20.

`Userspace::connect_tcp` added a socket to smoltcp's `SocketSet` and **nothing
ever removed one.** `SocketSet::remove` appeared in exactly one place in the
tree — the error path of `listen_tcp` — so every SOCKS5 connection the sidecar
handled left a socket behind permanently. A daemon that had served a thousand
connections held a thousand sockets and had reclaimed none of the memory.

Two costs, and the second is the one that would have been diagnosed as something
else:

- **Memory.** Each socket carries a receive and a transmit buffer, so a finished
  connection retains 128 KiB. Finding 41 made this a hundred times worse
  three days ago and neither of us noticed: raising the buffers from one MTU to
  64 KiB was right for throughput, and it multiplied the size of every leaked
  socket by 51.
- **Time.** `interface.poll` walks every socket in the set on every packet the
  daemon carries. So the datapath gets slower in proportion to the number of
  connections the process has *ever* handled — a sidecar that is fast on Monday
  and slow on Friday, with no leak visible in any per-packet code path.

**Nothing could have caught it.** Every conversation was correct: the bytes
arrived, the half-closes worked, the bulk row hit its budget. Correctness tests
observe what crosses a connection, and this is a property of what is left behind
after one. The measurement in `docs/measurements/userspace-cost-2026-08-21.md`
could not see it either — it reports peak RSS for a run that opens three
connections.

The fix has three parts, and the second is the one that makes the first safe.

*Release, not close.* `tcp_release` hands a socket back; the stack keeps polling
it until it has finished closing and only then frees it, so a `FIN` already in
flight is not cut off. A connection that never finishes is aborted after five
seconds — `RETIRE_GRACE` — because at that point the far end is not answering
and holding 128 KiB for it is the wrong trade. `tcp_abort` is the same mechanism
with the deadline already past, for a connection the daemon has decided to
refuse.

*A generation on every handle.* smoltcp identifies a socket by its index and
hands a freed index straight back out to the next socket, so making removal
possible also makes **use-after-release** possible — and a stale handle would
not fail, it would read and write a different connection's bytes. Every handle
now carries the generation it was issued in and every accessor checks it, so a
stale one resolves to nothing. `a_released_handle_cannot_reach_the_socket_that_
replaces_it` asks a released handle every question the API has, against a live
connection sitting in its old slot, and requires all of them to come back empty.
It also removes the last way a caller could panic this crate: smoltcp's own
`get_mut` panics on a handle it does not recognise.

*Somewhere to see it.* `karst status` reports `userspace_sockets` in userspace
mode, and the end-to-end row waits for the count to come back down after its
conversation ends. Without that line the property would be back to being
invisible — which is how it survived in the first place.

Verified by injection: with the reaper's removal taken out, three unit tests and
the end-to-end row fail, and each names the socket it expected back.

### 38. Low: a gateway that can never grant a mapping is asked again every five seconds

**Recorded 2026-08-21** by the double-NAT row, which is the first thing in the
tree to run a node whose gateway answers and refuses. **Fixed the same day.**

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

The classification is left alone, as recommended. What changed is the schedule:
`Backoff` doubles from the same five seconds to a cap of **1024 seconds**, and
resets on progress of any kind.

Both numbers are RFC 6887 §8.1.1's rather than chosen. That section is PCP's own
retransmission schedule, answering the same question — how often to keep asking
a gateway that is not helping — and it pairs `MRT = 1024` with `MRC = 0` and
`MRD = 0`: **retry forever, never give up.** That second half was already right
here and is what made the first half's absence a defect on its own. A day of
refusals falls from 17,280 requests to about 90, and a gateway that recovers
waits at most seventeen minutes.

Reset covers more than success. A PCP gateway answering "use NAT-PMP", a
gateway that restarted and lost its mapping, and a mid-protocol continuation are
all gateways that *answered*; backing off through them would make a working
fallback look slow to establish when nothing had failed.

The jitter is ±10%, which is the same section's `RAND`. Every node behind one
carrier-grade NAT starts its daemon when the link comes up, so an undithered
schedule has them all asking at the same instants — and the doubling would make
those collisions rarer but larger.

**The deferral reason turned out to be avoidable.** The note above said a test
needed an injectable clock in `portmap::run`. It does not: the schedule is a
pure function of its own history, so `Backoff` is tested directly — six tests,
including the arithmetic in this entry — and the *wiring* is checked end to end
instead, by the row that found the finding. `portmap_retry_in_seconds` is now
published, and `assert_double_nat` requires it to be non-zero; removing the one
line that sets it fails that row. Publishing it also fixes the quieter half of
this finding, which is that the status line read identically every five seconds
for as long as the condition lasted, and so read as normal operation.

Verified by injection against the six unit tests: removing the cap, removing the
doubling (which is the original defect), disabling the reset, and zeroing the
jitter each fail exactly the tests that name them.

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
