# Title: Home-relay re-homing: busy connections never move, roams don't trigger re-measurement, and `Restarting` is unused

Found while verifying an assumption for ADR-0045 (cost-aware geographic
scaling). These affect any client that roams or any relay that is taken out of
service, independent of that ADR.

## What works today
- A relay withdrawn from the netmap is released by `Selector::retain` even if it
  was the choice; `home_target` moves the home connection and `handover` keeps
  the old relay on demand so peers aren't black-holed (`bins/karstd/src/home.rs`,
  `run.rs`).
- A dead relay is abandoned after `HOME_RELAY_ATTEMPTS` (3) failed connects.
- `ponor-v1.md` §9.2 hysteresis: 20 ms / 20% margin, 3 consecutive wins.

## Problems
1. **A busy home connection never moves.** `moved_home` is checked only on the
   idle branch of `relay_send_loop` (`run.rs`). A client with continuous traffic
   never takes that branch, so a chosen move, or a move away from a withdrawn
   relay, can be deferred indefinitely.
2. **Reaction is tens of minutes.** `PROBE_INTERVAL` is 60 s; each alternative
   is measured for `PROBE_ROUNDS` (4) rounds, then `REST_ROUNDS` (6) pass before
   the next candidate. With N alternatives a given one is measured roughly every
   10·N minutes, then needs 3 further wins.
3. **No network-change trigger.** `run.rs` re-enumerates interfaces and calls
   AVEN `rediscover`, but nothing resets or accelerates the home-relay
   `Rotation`/`Selector`. A roam is invisible to relay selection until the slow
   cycle comes round.
4. **`Restarting` is specified but unused.** `ponor-v1.md` §7.6 says a relay
   SHOULD send `Restarting(reconnect_in_ms, try_for_ms)` before a planned close
   and clients SHOULD jitter. The frame exists in `karst-relay-proto`;
   `karst-relay` never sends it and `karstd` has no handler. A relay taken out
   of service drops its clients onto the dead-relay path instead of a
   coordinated, jittered move.

## Proposed (to be confirmed in the design, not prescribed)
- Check for a pending move on a bounded interval even when traffic is flowing,
  and hand over without dropping in-flight traffic (the existing `handover`
  already keeps the old relay on demand).
- On a detected interface/network change, start a fresh measurement round
  across the registry rather than waiting for the rotation.
- Send `Restarting` from `karst-relay` on graceful shutdown/drain; handle it in
  `karstd` with jitter per §7.6.
- **Keep §9.2's margin and sample count unchanged.** Speed-ups should come from
  measuring sooner, not from lowering the hysteresis; the cost of flapping is
  paid by the whole aquifer's netmap churn.

## Acceptance
- Test: a node with sustained traffic moves home relay within a bounded time
  after a better relay appears / the held relay is withdrawn.
- Test: a simulated interface change triggers re-measurement.
- Test: relay sends `Restarting`; client waits `reconnect_in_ms` plus jitter and
  does not trip the 3-attempt abandon path.
- No change to wire format; `ponor-v1.md` updated if §9 behaviour is clarified.

Related: ADR-0045 (prerequisite for relay scale-down), ADR-0008, `ponor-v1.md`
§7.6 and §9.
