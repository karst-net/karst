<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Relay migration and verification (#446)

Parallel to [gateway-migration-verification.md](gateway-migration-verification.md),
for the two items #446 split out of #404's closed "Unified Relay component"
scope: a documented, executed mixed-version/upgrade verification, and a
consolidated direct+Ponor transport verification record. Both were missing
even though the underlying behavior was already covered by pre-existing
suites — this records what those suites actually prove, and what they do not.

## Schema compatibility

Relay service associations (#419, #440, #444) gate activation on
`RelayLifecycleSchema`: an account using `services` publication at schema
version ≥ 2 refuses an older agent's schema-1 report
(`server/management/internals/karst/control/netmap.go`); a disabled mode
persists as `services-v2` so older service-aware readers reject the unknown
schema instead of silently reinterpreting it
(`server/management/internals/karst/relayservice/modes.go`). This is the same
category of claim Gateway's `#422` field-7 compatibility makes, at the
Relay/Ponor service-association layer instead of the Gateway-offer layer.

## Direct + Ponor transport exercise

The shared path-selection model (`crates/karst-disco/src/path.rs`) is one
`PathKind{Relay, DirectV4, DirectV6}` state machine, not duplicated per
transport — confirmed in an earlier audit for #446's own close-out. Failover
and reconnect between a direct path and Ponor are therefore one mechanism to
verify, exercised at three layers: pure state-machine unit tests, an
engine-level test with two in-process nodes and no real sockets, and
real-socket/real-process tests against an actual `karst-relay` binary.

## Verification record — 2026-10-27

| Check | Evidence / boundary |
|---|---|
| Relay service schema gating (new control, old agent report) | `TestUpgradeDefaultsPreserveExistingBackendAssociations`, `TestModesPersistWithdrawAndRestoreWithoutReinterpretingLegacyState` — `relayservice` package, 16/16 passed. |
| Wire identity preserved across publication rollback | `TestRelayServicePublicationPreservesWireIdentityAndExplicitRollback` — `control` package, passed. |
| Relay usage/telemetry signing vectors agree with the Rust side | `relaytelemetry` (12/12) and `relayusage` (27/27) passed, including cross-language signing-vector tests shared with `bins/karst-relay`. |
| Direct path displaces Ponor; a dying direct path falls back to it without hysteresis flapping | `crates/karst-disco/src/path.rs` unit tests — 36/36 passed, including `a_direct_path_displaces_a_relay_immediately`, `a_dying_direct_path_falls_back_to_the_relay_without_hysteresis`, `a_faster_relay_never_displaces_a_working_direct_path`. |
| Same failover/reconnect behavior at the engine layer, including a peer that published a different relay | `bins/karstd/tests/relay_path.rs` — 14/14 passed, including `a_direct_path_displaces_the_relay_without_disturbing_the_session`, `a_published_endpoint_that_has_gone_stale_falls_back_to_the_relay`, `a_peer_this_relay_cannot_reach_moves_to_the_relay_it_published`. |
| Admission denial, credential/TLS rejection, draining/reconnect signaling against a real Ponor relay and a real node | `bins/karstd/tests/relay_live.rs` — 10/10 passed, including `an_unlisted_node_is_refused`, `a_substituted_relay_registry_entry_is_refused`, `without_the_configured_ca_the_tls_hop_is_refused`, `a_draining_relay_sends_restarting_before_it_closes`. |
| Roster-based admission, replay resistance, mesh peering, QUIC/TCP interop, real-socket forwarding | `bins/karst-relay` test suites — lib 9, `end_to_end.rs` 9, `listener.rs` 16, `quic.rs` 7, `roster_vector.rs` 3, `shutdown_signal.rs` 1, `telemetry_vector.rs` 1, `usage_write.rs` 3 — 49/49 passed. |
| End-to-end encrypted transit | Covered implicitly by the above: every forwarded packet in `end_to_end.rs`/`listener.rs`/`quic.rs` crosses a real Noise handshake between node and relay: the relay forwards opaque frames and never decrypts overlay payload. No test asserts on plaintext at the relay. |
| Roster lease expiry and refresh (the 90s freshness lease `deploy/compose/README.md` documents) | **Covered in #450.** The real-TLS-socket regression checks expiry, revocation, silent refusal, invalid replacements, and recovery; see the 2026-10-28 record below. |
| Real mixed old/new **Relay-binary** namespace execution, parallel to Gateway's seven real mixed-binary aquifer runs | **Executed in #450.** Old relay/current nodes+control and current relay/old nodes+control both pass the real Ponor-to-direct namespace scenario; exact revisions and commands appear below. |
| Production control deployment, database upgrade, native-platform (macOS/Windows) integration | Not covered, same boundary `gateway-migration-verification.md` records for Gateway. |

### Local check results

- `crates/karst-disco` path unit tests: 36 passed.
- `bins/karstd` `relay_path` and `relay_live` integration tests: 14 + 10 = 24 passed.
- `bins/karst-relay` full test suite (lib + 7 integration binaries): 49 passed.
- Go `relayservice`, `relaytelemetry`, `relayusage` packages and the targeted
  `control` publication-rollback test: 16 + 12 + 27 + 1 = 56 passed.
- Incidental finding, outside this verification's scope: `relayreg`'s own
  package suite has one pre-existing, reproducible failure —
  `TestStartDemandHistoryWorkerSamplesImmediatelyOnStartup`
  (`demand_history_test.go:127`, "no sample recorded within 2s of starting
  the worker"). It concerns the scaler-adjacent demand-history sampling
  worker, not Relay schema compatibility or transport behavior, and predates
  this work — this doc does not fix it, only notes it was observed while
  running the adjacent package suite.
- This is current-worktree Rust and Go test execution on macOS/arm64. It is
  not a claim that CI's full matrix, `just check`, or any Linux-namespace
  suite ran as part of this pass.

## Follow-up verification — 2026-10-28 (#450)

Both remaining gaps are now covered on Linux/amd64. The current source is
`970abb2f559702a1dc9ae6372c162050d9ead4f1` (based on main `72c3a93`).
The older source is `e519de57c76ca819e1abc75f5c2d310879be39ec`.
The old relay and node were extracted from the existing Debian packages
`/tmp/karst-pr431-relay.deb` and `/tmp/karst-pr431-client.deb`; both package
versions are `0.0.0+git.e519de57c76ca819e1abc75f5c2d310879be39ec-1`.
The old control fixture was built from the clean checkout of that same revision
at `/tmp/karst-421-verification`:

```sh
(cd /tmp/karst-421-verification/server && \
  CGO_ENABLED=1 go build -o /tmp/karst450-old-testserver \
    ./management/internals/karst/testserver/)

KARST_AQUIFER_RELAY_BIN=/tmp/karst-pr431-relay/usr/bin/karst-relay \
  ./scripts/test-aquifer-container.sh \
    two_nodes_meet_on_the_relay_and_end_up_direct --exact

KARST_AQUIFER_NODE_A_BIN=/tmp/karst-pr431-client/usr/bin/karstd \
KARST_AQUIFER_NODE_B_BIN=/tmp/karst-pr431-client/usr/bin/karstd \
KARST_AQUIFER_TESTSERVER_BIN=/tmp/karst450-old-testserver \
  ./scripts/test-aquifer-container.sh \
    two_nodes_meet_on_the_relay_and_end_up_direct --exact
```

| Actual binary combination | Executed result |
|---|---|
| Old relay; current node A, node B, and control fixture | 1 passed, 0 failed. |
| Current relay; old node A, node B, and control fixture | 1 passed, 0 failed. |

The relay override applies to every relay started by the harness, including
multi-relay scenarios. The container runner validates and copies the selected
executable into its read-only products mount. These two executed runs use the
single-relay scenario: enrollment, authenticated Ponor transit, PHREATIC
handshake, AVEN rendezvous, direct-path upgrade, and an ACL-scoped TCP exchange.
They do not establish mixed-version mesh peering, a full rolling production
upgrade, production database migration, or native-platform behavior.

### Automated freshness-lease regression

```sh
cargo test -p karst-relay --lib \
  roster_lease_expiry_refuses_admission_and_refresh_restores_it
```

`server::roster_tests::roster_lease_expiry_refuses_admission_and_refresh_restores_it`
passed. It runs the production roster reload loop and a real TLS/Ponor listener
with a private three-second lease and 20ms poll interval. Production still uses
90 seconds and a five-second poll; no configuration or environment override
can shorten them.

The test authenticates a rostered client, stops refreshing the roster, and
observes admission become empty. The existing socket receives `NotAdmitted`
and closes; a new handshake is silently refused. An invalid roster write does
not reopen admission. Atomically publishing the original membership with a new
mtime restores admission and a new client handshake succeeds. It exercises
actual elapsed monotonic time and real file/socket I/O, without a 90-second wait.

Validation at the same implementation: the complete `karst-relay` suite passed
(195 library tests and 49 integration tests), strict relay Clippy across all
targets passed, Rust formatting passed, and the container runner passed shell
syntax validation. The two namespace runs above passed. The full Aquifer suite,
`just check` (`just` is unavailable), and the full CI matrix were not run locally.
