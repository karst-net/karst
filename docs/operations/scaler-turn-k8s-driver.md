<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# The Kubernetes TURN scaler driver

Operations reference for `karst-scaler-turn-k8s` (ADR-0045 §7b, issue
#311) — the TURN counterpart of `docs/operations/scaler-k8s-driver.md`.
Read that document first: the naming conventions, `StatefulSet`/headless-
`Service` prerequisites, and scale-down-removes-the-highest-ordinal
semantics are identical here, and are not repeated below. This document
covers only what differs.

## What differs from the relay driver

- **Enrollment/removal endpoints.** `create` mints a token from
  `POST /karst/v1/turn/enroll-tokens` (#310) instead of
  `/karst/v1/relays/enroll-tokens`; `drain` calls
  `POST /karst/v1/turn/deenroll` (#320) to remove the registry row.
- **Bundle shape.** One `Secret` key per ordinal, same as the relay
  driver, but a sourceable `KEY='value'` file (`<pool_id>-<i>.env`) in a
  `<pool_id>-turn-enroll` `Secret`, not a TOML file — see
  `deploy/images/karst-turn-bootstrap-entrypoint.sh`'s own doc comment for
  why (no Karst code runs inside coturn to parse TOML with) and
  `docs/operations/scaler-turn-bootstrap.md`'s "Per-pod delivery" section
  for the full contract. The bundle carries `control_api_base`, `token`,
  and `uri` — never `KARST_TURN_STATIC_AUTH_SECRET`, the operator's own
  shared secret, which belongs on the pod template directly (see that
  document).
- **The URI, not a separate address field.** Each pod registers as
  `turn:<pod>.<pool_id>.<namespace>.svc.cluster.local:3478` — fixed
  scheme (`turn:`, no TLS) and port (`3478`, TURN's IANA default). An
  operator needing `turns:` or a different port configures it through
  the bootstrap image's own `KARST_TURN_BASE_CONF` (see that document);
  this driver has no config knob for either, by design — a reference
  driver's one fixed shape, not a general one.
- **`drain`/`destroy` split.** This is the real difference, and the
  reason to read this section carefully before running it.

## `drain`/`destroy`: why `destroy` does nothing

The relay driver's `drain` blocks for a real but short wait (its own
`DRAIN_TIMEOUT`, 30s) for a pod to actually terminate, then `destroy`
removes it immediately after. A TURN instance has no equivalent short
wait: once `drain` removes the `turncred.Store` row, the instance is
*safe to stop advertising* but not yet *safe to kill* — a client with an
already-minted credential keeps a live allocation against it until that
credential's own expiry passes (removing the registry row does not
revoke anything coturn-side; see issue #311's own recorded reasoning).
That window is the operator's own configured credential TTL — plausibly
hours.

`bins/karst-scaler/src/drive_loop.rs::reconcile` calls `drain` and
`destroy` back-to-back, synchronously, on the one thread that reconciles
every pool each tick. Blocking that thread for hours inside `drain` would
stall every other pool and every future tick. So this driver's `drain`:

1. Calls `/karst/v1/turn/deenroll` synchronously (fast — one HTTP
   request).
2. Spawns a **detached background task** on its own multi-threaded
   `tokio::runtime::Runtime` that sleeps out `credential_ttl` and then
   performs the actual `StatefulSet` scale-down itself, re-checking at
   that later time (not from a stale snapshot) that the instance being
   removed is still the current highest ordinal.
3. Returns immediately.

`destroy` is then a deliberate no-op: the real work already happened, or
was scheduled, inside `drain`.

**This is best-effort, not durable.** The scheduled task lives only in
this process's memory. A `karst-scaler drive` restart during the wait
window loses the scheduled teardown silently — the instance keeps
running, and its `StatefulSet` replica count stays un-decremented, until
an operator notices. This is a known, deliberate limitation of this first
implementation, not an assumed-away gap: a durable, restart-surviving
version (persisted per-instance drain timestamps, mirroring `breaker.rs`'s
own state-file pattern) is real follow-up work, not built here.

Operationally, this means: expect `karst-scaler drive`'s own process to
stay running continuously relative to your configured `credential_ttl`.
A deployment that restarts the scaler frequently (an aggressive
rolling-update policy, a crash loop) will accumulate undestroyed TURN
instances faster than this driver's current design can clean them up —
watch pod count/cost, not just the control server's own registry, until
a durable version of this exists.

## Configuring `karst-scaler drive` to use this driver

```toml
# advise-config.toml, alongside the existing [breaker] section (required
# regardless of which driver is selected — ADR-0045 §6 allows no
# "unlimited" default).
[driver]
kind = "turn-k8s"
namespace = "karst-turn"
enroll_pat_file = "/etc/karst-scaler/turn-enroll.pat"   # a UserRoleScaler-scoped PAT
credential_ttl_secs = 86400   # must equal the control server's own turncred.Minter TTL
```

Requires a `karst-scaler` binary built with `cargo build --features
turn-k8s` and a `kubeconfig`/in-cluster service account reachable the
ordinary way every `kubectl`-adjacent tool discovers one — this driver
adds no connection configuration of its own on top of that.
`deploy/kubernetes/scaler-turn/rbac.yaml` is the namespace-scoped
`ServiceAccount`/`Role`/`RoleBinding` this driver's own client needs;
its own header comment explains why it is narrower than the relay
driver's RBAC in one real way (no `pods: delete`). `pools.*.kind
= "turn"` must be set on every pool this driver is meant to size (see
`bins/karst-scaler/src/cost_model.rs::PoolKind`) — a pool left at the
default `"relay"` kind is sized from relay demand telemetry this driver's
own instances never produce, which is almost certainly not what an
operator configuring this driver wants.

## Verified

Build, `clippy --all-targets` (including every feature combination:
none, `k8s`, `turn-k8s`, `aws`, and all four together), and
`cargo test` are all clean. `bundle.rs`'s own tests cover every pure
naming/rendering decision, including that `create` and `drain` derive a
pod's `turn:` URI from the same function rather than two independent
string-building call sites that could drift apart. A dedicated test
confirms the one genuinely new mechanism here — a task spawned on a
multi-threaded runtime keeps running to completion independent of the
spawning thread's own later work — behaves the way `drain`'s whole
design depends on.

**Not verified**: a real cluster (kind/k3d), a real control server, and a
real coturn instance actually enrolling and later being torn down end to
end. Out of reach in the environment that built this, the same posture
`scaler-k8s-driver.md`'s and `scaler-aws-driver.md`'s own docs already
flag for their own real-infrastructure gaps.
