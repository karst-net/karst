# Observability exit demonstration (workstream 8, §7)

> **Archived planning record — 2026-09-06.** Remaining work is tracked in
> [GitHub issues via the migration index](../README.md). This notice supersedes
> all backlog/status instructions below; retain the text as historical context.
> Tracking: [#130](https://github.com/karst-net/karst/issues/130) — **closed
> 2026-10-03**. Sections 1 and 2 below record why those two items were not run
> live at the time; each now carries a 2026-10-03 update with the live
> evidence that closes them.

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

### Update, 2026-10-03 — run live

Disposable deployment on lab host `turing`, built from a new throwaway tag
`v0.0.0-observability.2` (`78a60f68180061d3f90cf7c4eb704aa7f5f70448`),
following this document's own precedent: `deliverables.yml`'s tag-gated jobs
built and cosign-signed real images, independently re-verified (not just
"CI signed it") against the workflow's own OIDC identity:

```
ghcr.io/karst-net/karst-control:v0.0.0-observability.2
  sha256:32b06f02198483be78df166ca20d23bc28362a7b96ed787a65e2193cf65cea9d
ghcr.io/karst-net/karst-relay:v0.0.0-observability.2
  sha256:8dd62de07341a83f982d6c23cd5d5faf61f6535b4601cf7d4c314f91e7d3854b
```

A real root ceremony was run offline with `karst-bedrock` against a fresh,
disposable account (zone `karst-demo-130`) — 3 root keys (k=2), 1 authority
key, and ADR-0016's anchor key enrolled **from genesis** rather than added
later:

```
karst-bedrock init root root1.key / root2.key / root3.key
karst-bedrock init authority authority1.key
karst-bedrock init anchor anchor1.key
karst-bedrock genesis-request genesis.req karst-demo-130 2 \
    root1.key.pub root2.key.pub root3.key.pub -- 1 authority1.key.pub \
    -- anchor1.key.pub
karst-bedrock sign genesis.req root1.key resp1.sig
karst-bedrock sign genesis.req root2.key resp2.sig
karst-bedrock combine genesis.req genesis.log resp1.sig resp2.sig
```

The resulting log was imported via `POST /api/karst/v1/bedrock/bootstrap/import`
as the account's real (OIDC-authenticated) owner, and the account's Bedrock
mode was set to `advisory`. With `KARST_BEDROCK_ANCHOR_MIN_ENTRIES=1`, the
anchor scheduler fleet picked up the account on its next reconcile pass and
anchored on its own, with no further operator action:

```
control-1 ... bedrock anchor scheduler fleet: starting for account db01fdmbcinc73bm0no0
control-1 ... bedrock anchor scheduler: anchored db01fdmbcinc73bm0no0's audit log at seq 2
```

```
management_karst_bedrock_chain_depth{account_id="db01fdmbcinc73bm0no0"} 2
management_karst_bedrock_anchor_age_seconds{account_id="db01fdmbcinc73bm0no0"} 323
```

`chain_depth` moved 1 → 2 (genesis, then the scheduler's own `anchor` entry)
and `anchor_age_seconds` appeared and climbed — both live, on the real signed
artifact, exactly as `TestKarstMetrics_BedrockChainDepth`/
`TestKarstMetrics_BedrockAnchorAge` predicted.

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

### Update, 2026-10-03 — run live

#99 (the fix this item was blocked on) is closed, so `EpochScheduler` now
rotates a running `karst-control` without a restart. A real UTC day boundary
was reached by advancing `turing`'s wall clock forward (NTP disabled first,
re-enabled and resynced after) rather than by waiting out the full 86400s —
`EpochSeconds` is a hard-coded Go constant with no test hook, and `time.Now()`
in Go reads the clock via vDSO directly, so per-process clock faking
(`libfaketime`/`LD_PRELOAD`) was tried and confirmed to have no effect before
falling back to the host clock. `turing` is disposable lab hardware with one
other, unrelated project on it; nothing on it depended on wall-clock
continuity across the jump. This is the real `EpochScheduler.Tick` code path
a genuine day boundary exercises — nothing about the server or the clock
input mechanism was faked, only when the real boundary was reached.

A `karstd` node (userspace mode) was enrolled against the deployment at
`psk_epoch 20728` and left running. Server and node logged the rotation at
the same instant, the node's netmap push arriving without waiting out any
poll floor:

```
control (2026-10-03T00:00:38.410Z): karst: psk epoch rotated 20728 -> 20729
node1   (2026-10-03T00:00:38.426868Z): netmap updated outcome=Replaced { peers: 0 }
    epoch_rotated=true push_triggered=true
```

```
management_karst_psk_epoch_age_seconds 1870
```

Peer continuity: `karst-control-1`'s container creation timestamp and
node1's daemon uptime were both unchanged across the boundary — neither side
restarted or reconnected.

One incidental finding from this run: `karst status`'s displayed `psk_epoch`
field did not reflect the rotation even after the node logged
`epoch_rotated=true`, while `engine.stats()`/`engine.status()` (used for the
rest of that output) are fetched live — `run.rs`'s `Status` IPC handler
appears to print a `config` snapshot that was not refreshed by the engine's
own post-rotation config swap (`engine.rs`'s `previous.config.psk_epoch !=
config.psk_epoch` check). Filed separately; not a discrepancy in the
control-plane behavior this item exists to verify.

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

### Update, 2026-10-03 — items 1 and 2's deployment

Items 1 and 2's live run above used a separate, genuinely disposable
deployment on lab host `turing` (built from `v0.0.0-observability.2`), not
this section's long-lived one — a fresh account was required for the root
ceremony. That deployment (`karst-control`, `karst-relay`, Keycloak, Caddy,
and the one enrolled `karstd` node) was torn down after the evidence above
was collected.
