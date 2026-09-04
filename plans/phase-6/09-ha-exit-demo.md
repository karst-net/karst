# HA exit demonstration (workstream 9, §7)

Every IP address below is a placeholder (`203.0.113.0/24` — RFC 5737 — for
real LAN addresses), not the deployment's actual addressing — this is a
public repository. Hostnames (`shannon`, `turing`, `lovelace`) are real, per
[09-ha.md](09-ha.md)'s own §0 note and [04-pentest.md](04-pentest.md)'s
precedent.

Run 2026-09-04, against real hardware: `turing` and `lovelace` were powered
on from off via iDRAC/Redfish for the drill and powered back off afterward.
Two deviations from §7's preamble, both deliberate and both worth recording
rather than glossing over:

- **Images were built from this tree's `HEAD`, not pulled from a published
  tag.** The HA code (`server/management/internals/karst/ha`) needed to be
  exercised as it exists in-tree, and no `v0.0.0-ha.*` release tag existed
  yet. `local/karst-control:ha-drill` was built via
  `deploy/images/karst-control.Dockerfile`; the relay image was reused
  unchanged from `v0.0.0-observability.1` (relay behavior is explicitly out
  of this workstream's scope, §1).
- **The shared entry point §7's preamble assumes was not already running.**
  This overlay does not ship one (now noted in
  [deploy/compose/ha/README.md](../../deploy/compose/ha/README.md)); an
  ad-hoc HAProxy TCP round-robin was stood up for the drill. It is called
  out explicitly in step 6 below, where it matters.

## 1. Enrollment via either replica — done

Bootstrapped a fresh two-host deployment: `shannon` running the Postgres
primary and one `karst-control` replica (co-located with the single relay
instance, owning `roster.toml`-write duty per §1's compose note), `turing`
running a streaming replica of Postgres and a second `karst-control`
replica. `lovelace` enrolled as a node against `shannon`'s replica, then was
reconfigured (`[control] server` in `karstd.toml`) to dial `turing`'s
replica directly and reconnected successfully against the same
Postgres-backed account — confirming a node can land on either replica
without re-enrolling.

## 2. Cross-replica eviction on identity clone — done

Cloned `lovelace`'s ML-DSA control identity (`identity.key`) onto a second
`karstd` process on the same host, given its own tunnel key and interface —
the same clone-the-identity-key-material technique
[04-pentest.md](04-pentest.md) §9.7 used to find #87 — and connected it to
`shannon` while the legitimate session was live on `turing`.

The legitimate session's stream closed (`the stream closed unexpectedly` in
`karstd`'s own log) within the same second the clone's `Claim` landed in
`control_sessions` and `replica_id` flipped from `turing` to `shannon`.
Restarting the legitimate client re-won ownership (Claim is a plain
last-writer-wins upsert, by design — §3.2), and re-evicted the clone in
turn. This is the regression test for #87 that matters most under HA, run
against two live `karst-control` processes on two real hosts sharing one
Postgres primary, and it passed: a cloned identity cannot hold a session on
two replicas at once, and eviction fires within the same `NOTIFY` round
trip regardless of which replica the clone reaches.

## 3. Postgres primary loss, promotion, RTO — done

Confirmed which containers belonged to the drill before touching anything
(`karst-ha-*`, distinct from the unrelated `karst-*` production-ish stack
already running on `shannon` from the observability exit demo) and killed
only `karst-ha-postgres-1` on `shannon` (`docker kill`), starting the clock
at `15:12:50.964Z`.

**Found and fixed a real bug**: `scripts/pg-promote.sh` ran `docker compose
exec` without `-u postgres`. The `postgres:17` image's default exec user is
root, and `pg_ctl` refuses to run as root — the script failed at the first
real drill, not in review. Fixed (now `-u postgres` on all three `exec`
calls) and re-run successfully.

- **Measured RTO: ~45s** wall-clock from the kill to both `karst-control`
  replicas serving reads/writes against `turing`'s promoted primary again.
  This run's number includes real discovery time for the bug above and a
  second real gap — `pg_hba.conf` needed each host's own docker-compose
  bridge subnet added, not just the shared LAN CIDR (documented in
  [deploy/compose/ha/README.md](../../deploy/compose/ha/README.md)). A
  clean run of the fixed script against an already-correct `pg_hba.conf`
  should be well under a minute, dominated by `pg_ctl promote`'s own wait
  plus two `docker compose up -d --force-recreate control` cycles.
- **Node survival**: `lovelace`'s tunnel interface never dropped —
  `karstd`'s "session held open, retrying" design kept the data plane up
  through the whole primary-loss window. The control channel (netmap
  refresh, PSK-epoch delivery) recovered once both replicas were repointed
  at the new primary's DSN.

## 4. Topology left recoverable — done

`shannon` was rebuilt as a fresh streaming replica of `turing` via
`pg_basebackup -R` against the new primary, using a fresh replication slot.
`turing`'s `pg_stat_replication` showed `shannon` back as `state=streaming`,
`sync_state=async` — the drill did not leave the deployment in a degraded,
single-instance state.

## 5. Backup, corruption, restore, RPO — done

Took a real `pg-backup.sh` base backup from `turing` (the primary at that
point in the drill) to a genuinely off-host destination — a third host
(`lovelace`), over the network, not the primary's own disk. Deliberately
corrupted data (`DROP TABLE control_sessions` against the live primary) and
restored with `pg-restore.sh --yes` to a point-in-time target before the
corruption.

- **Measured RPO: ~38.5s** — corruption at `15:18:38.749Z`; the restore
  reached `15:18:00.211Z`, the last committed transaction actually
  recoverable from archived WAL. A target closer to the corruption
  (`15:18:35Z`) was tried first and failed outright — "recovery ended before
  configured recovery target was reached" — because the archived WAL simply
  didn't extend that far.
- **Real finding, not an assumed number**: the checked-in `postgresql.conf`
  sets `archive_mode = on` with no `archive_timeout`, so a WAL segment
  archives only on completion (16 MB) or an explicit switch. Under low write
  volume the actual RPO is bounded by *time since the last full segment*,
  not by replication lag — invisible from the design alone, only found by
  timing a real restore against a real archive gap. Documented as a
  commented-out `archive_timeout` option in
  [deploy/compose/ha/postgres/postgresql.conf](../../deploy/compose/ha/postgres/postgresql.conf),
  the same kind of operator trade-off §3.4 already documents for
  synchronous replication, one layer down.
- Restore verified correct, not just "the script exited zero": the
  restored `control_sessions` table held its pre-corruption row; a marker
  table inserted after the chosen restore point was correctly absent.
- Topology recovery: `turing` promoted onto a new WAL timeline after the
  restore; `shannon` was rebuilt as its replica the same way as step 4,
  confirmed streaming.

## 6. Replica-process kill and client failover — attempted, not conclusively closed

Killing a single `karst-control` process and confirming the client
reconnects through the *other* replica requires the shared entry point §7's
preamble assumes exists — a single `karstd.toml` `server` line cannot fail
over on its own, by design (§3.1). This overlay does not ship one, so an
ad-hoc HAProxy TCP round-robin was stood up for the drill (not part of this
workstream's deliverables).

After extended chaos testing beforehand (repeated primary kills, a PITR
restore that moved Postgres across two WAL timelines, many client
restarts), the node's netmap sync became unreliable going through the
proxy — a connect-then-disconnect loop that did not look like a session-
eviction or `ha.Hub` failure (no session ever failed to *evict* correctly;
every `Claim`/`NOTIFY` round trip in steps 2–5 above worked). The same
instability reproduced briefly against a direct, un-proxied connection to a
single replica later in the same run, which points at accumulated
drill-environment state — the ad-hoc proxy, or the node's netmap
cache/PSK-epoch state after two live timeline jumps — rather than a defect
in the shipped cross-replica design.

**This step needs a clean re-run to close out**: a real load-balanced entry
point (not an ad-hoc proxy improvised mid-drill), a fresh node with no prior
cache, and no other chaos in flight, to get an unambiguous pass/fail. Until
then this is an open item, not a passed check — recorded honestly in
[docs/operations/ha.md](../../docs/operations/ha.md) rather than assumed
from the design.

## Cleanup

All `karst-ha-*` containers, the ad-hoc HAProxy, the cloned identity's
`karstd` process, and the sshfs mounts used for off-host WAL
archiving/backups were torn down on all three hosts after the drill.
`lovelace`'s own pre-existing enrolled `karstd` (a separate deployment, a
separate identity, untouched throughout) was never stopped or
reconfigured. `turing` and `lovelace` were powered back off via iDRAC.

Two real, unrelated nomad-scheduled jobs (a `postgres`/`stac-api` pair on
`turing`, a `gitlab-ce` instance on `lovelace`) started running on their own
schedule once the hosts were powered on for the drill; they were left
running rather than interrupted, and the hosts were powered off only after
confirming that was acceptable.

## Findings shipped from this drill

- `scripts/pg-promote.sh`: fixed, `-u postgres` on every `docker compose
  exec`.
- `deploy/compose/ha/postgres/postgresql.conf`: `archive_timeout` documented
  as a commented-out RPO/archive-volume trade-off.
- `deploy/compose/ha/README.md`: documents the per-host `pg_hba.conf`
  bridge-subnet requirement and the shared-entry-point gap this overlay
  does not close.
- `docs/operations/ha.md`: the real RTO/RPO numbers and the open item from
  step 6, replacing the "not yet run" placeholders — §8's definition of
  done requires a real drill's numbers here, not a writeup of one.
