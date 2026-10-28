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
| Roster lease expiry and refresh (the 90s freshness lease `deploy/compose/README.md` documents) | **Not covered by an automated test.** Verified only by the manual `watch`/stop/start demonstration in that README. This is a real gap, not a documented limitation elsewhere. |
| Real mixed old/new **Relay-binary** namespace execution, parallel to Gateway's seven real mixed-binary aquifer runs | **Not done.** `scripts/test-aquifer-container.sh` accepts `KARST_AQUIFER_NODE_A_BIN`/`KARST_AQUIFER_NODE_B_BIN`/`KARST_AQUIFER_TESTSERVER_BIN` overrides but has no equivalent for `karst-relay` — `bins/karstd/tests/aquifer.rs`'s `spawn_relay`/`start_relay` always build and run the current worktree's relay. Existing aquifer scenarios already exercise real Ponor transport (`two_nodes_meet_on_the_relay_and_end_up_direct`, `two_nodes_on_two_relays_reach_each_other`, symmetric-NAT-stays-on-relay cases), but none of them can select an old relay binary today. Adding a `KARST_AQUIFER_RELAY_BIN` override (mirroring the existing node/testserver ones) is the concrete next step, not done here — it also needs a Linux/Docker host to execute, which this verification pass did not have. |
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
