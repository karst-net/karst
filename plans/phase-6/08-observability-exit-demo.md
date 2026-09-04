# Observability exit demonstration (workstream 8, §7)

Every IP address below is a placeholder (`203.0.113.7` — RFC 5737 — for the
deployment's real external address, `192.168.1.x` for the real LAN address),
not the deployment's actual addressing — this is a public repository.

Run against `deploy/compose/pentest/`, the same topology
[04-pentest.md](04-pentest.md) used, reused per §7's own instruction rather
than standing up a fresh one. Built from tag `v0.0.0-observability.1`
(52a06de), following `v0.0.0-pentest.1`'s and `v0.0.0-signing-test.1`'s
precedent: a throwaway release tag that runs `deliverables.yml`'s tag-gated
jobs, so the target is built by the actual packaging pipeline instead of
`:dev` images or `cargo run`. Every image (`karst-control`, `karst-relay`,
`karstd`) was pulled from `ghcr.io/karst-net/*:v0.0.0-observability.1` and
verified with `cosign verify` against the workflow's own OIDC identity
before use — not merely "CI signed it," independently re-checked.

`deploy/compose/pentest/docker-compose.override.yml` (untracked, local-only)
pins `control`/`relay` to the new tag without editing the tracked compose
file, which still documents `v0.0.0-pentest.1` as what
[04-pentest.md](04-pentest.md) validated.

## 1. Bedrock chain depth / anchor age — not run live

Requires an anchor key enrolled through Bedrock's root ceremony
(ADR-0016), which this deployment's account has never run. Standing one up
was out of proportion to the rest of this demonstration. Verified instead
by:

- `TestKarstMetrics_BedrockChainDepth`/`TestKarstMetrics_BedrockAnchorAge`
  (`management/server/telemetry/karst_metrics_test.go`) — table-driven,
  asserting the gauges change on the right event and stay absent
  (not zero) until one occurs.
- Code review of the two write sites: `bedrock.Log.Import` calls
  `SetBedrockChainDepth` on every commit; `bedrock.Scheduler.Tick` calls
  `SetBedrockLastAnchoredAt` when `LastAnchoredAt` finds one.

## 2. PSK epoch age — not run live

`management.karst.psk.epoch.age.seconds` only updates on a real epoch
rotation (`control.EpochScheduler.Tick`, gated on `CurrentEpoch(now)`
actually changing), which happens once per 86400s wall-clock day boundary.
No boundary fell inside this session. Confirmed instead:

- Immediately after a `karst-control` restart the gauge is correctly
  **absent**, not a stale or reset-to-zero value — restart alone does not
  count as a rotation (`Tick`'s `prev == next` early return), matching the
  metric's own "absent until observed" contract.
- `TestEpochScheduler*` (`control/epoch_test.go`) drives `Tick` against a
  synthetic clock and asserts the rotation and the metric write
  deterministically, which is the same code path a real day boundary
  exercises.

## 3. Relay registry size — `0 → 1 → 0`

Registered and deregistered a relay through the real admin API
(`POST`/`DELETE /api/karst/v1/relays`, OIDC password-grant login as the
deployment's own portal user via `pentest_lib.py`), using the existing
relay's real ML-DSA-87 identity key (`karst-relay pubkey`) at a distinct
address so it could not collide with the statically-configured registry
entry, which is a separate mechanism entirely.

```
metric before create: management_karst_relay_registry_size{...} 0
POST /relays: 201
metric after create:  management_karst_relay_registry_size{...} 1
DELETE /relays/<id>:  204
metric after delete:  management_karst_relay_registry_size{...} 0
```

## 4. Netmap-push duration + trace span

Enrolled a real `karstd` node (userspace mode, joined the deployment's own
compose network, no `CAP_NET_ADMIN` needed for this) and left its control
session connected. `karst.control.session_handshake` and `karst.netmap.push`
both export as real OTLP spans to a throwaway `jaegertracing/all-in-one`
container pointed to by `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` — confirming
the exporter is a real one, not a no-op, when an operator configures it.

Triggering an actual push needed a real peer-set change: Karst's own
`/karst/v1/policy` write does **not** route through the inherited
`SendNotification` mechanism (a real, pre-existing architectural gap —
GitHub issue #75's own scope note), only the account/peer pipeline
GitHub issues #72/#73 wired up does. Removing a stale device already in
this account's roster (left over from [04-pentest.md](04-pentest.md) and
from this session's own node-enrollment testing) was the trigger used.

```
push histogram before: (absent)
DELETE /nodes/<handle>: 204
push histogram after:  management_karst_netmap_push_duration_ms_milliseconds_count{trigger="unknown"} 1
```

Jaeger, same event:

```json
{"operationName": "karst.control.session_handshake", "duration": 9113}
{"operationName": "karst.netmap.push", "duration": 28}
```

(durations in the exporter's native microseconds; consistent with the
histogram's `sum=0` — a sub-millisecond, same-network push.)

## 5. `karst metrics` / opt-in HTTP listener

On the enrolled node, `karst metrics` (IPC) and `curl
http://127.0.0.1:9091/metrics` (the `[metrics] listen` HTTP listener,
enabled for this demonstration only) returned **byte-identical** output —
`diff` empty — confirming the listener is a transport wrapper around the
same IPC verb, not a second computation.

A second node configured with `[metrics] listen = "0.0.0.0:9092"` refused
to start:

```
karstd: configuration: metrics.listen = 0.0.0.0:9092 is not a loopback
address; the Prometheus listener may only bind 127.0.0.0/8 or ::1, never a
network-facing interface
```

## 6. `karst bugreport`

Ran on the enrolled node. `[control]` (`transport = "plaintext (h2c)"`,
`since_last_push_seconds`) is present and populated. `[bedrock]` is
correctly absent — this node's account has no Bedrock data (§1). No
`[[relay]]`/`[[turn]]` entries — this node never attempted to dial either
(no other live peers to reach). Confirmed by inspection: no key material
anywhere in the output, consistent with
`no_bugreport_field_name_suggests_key_material` and
`no_psk_bytes_reach_any_diagnostic` (`tests/leakscan.rs`), both passing.

## Cleanup

The throwaway relay registration, the throwaway `karst metrics` HTTP
listener, the demonstration `karstd` node, and the Jaeger container were
all removed after the demonstration. The one non-reverted admin action —
deleting the stale `lovelace.compute`/`turing.compute`/duplicate-enrollment
device records used to trigger §4 — was deliberate cleanup of dead
[04-pentest.md](04-pentest.md)-era state, not incidental to the
demonstration. The account's `/karst/v1/policy` document, briefly written
to trigger a netmap recompute before the peer-delete approach above was
used instead, was reverted to empty (`{"acls": []}`) — version-controlled by
the policy store itself, so both states remain in its history.

The deployment now runs `v0.0.0-observability.1` going forward — a real,
signed, upgrade from `v0.0.0-pentest.1`, not reverted.
