# HA operations record

This record is completed only by a real `shannon`/`turing` drill; a compose
run is not evidence of HA. Schema upgrades require all control replicas stopped
or explicit acceptance of the existing migration race.

## Failover drill — run 2026-09-04

- Date/operator: 2026-09-04, Adrian Anderson (assisted). Two real hosts:
  `shannon` (primary, this dev box) and `turing` (streaming replica,
  promoted). `lovelace` ran the enrolled node.
- Control read/write RTO: **~45s** wall-clock from killing `shannon`'s
  Postgres primary (`docker kill`) to both `karst-control` replicas serving
  reads/writes against `turing`'s promoted primary again. This run includes
  discovery time for a real `pg-promote.sh` bug (below); a clean run of the
  fixed script is expected to be well under a minute, dominated by
  `pg_ctl promote`'s own wait plus two `docker compose up -d --force-recreate
  control` cycles.
- Node survival: `lovelace`'s tunnel interface stayed up throughout —
  `karstd`'s "session held open, retrying" design meant the data plane never
  dropped. The control channel (netmap refresh, PSK epoch delivery) recovered
  once both `karst-control` replicas were repointed at the new primary.
- **Bug found and fixed**: `scripts/pg-promote.sh` ran `docker compose exec`
  without `-u postgres`. The `postgres:17` image's default exec user is
  root, and `pg_ctl` refuses to run as root — the script failed at the first
  real drill. Fixed by adding `-u postgres` to all three `exec` calls.
- **Deployment-specific gotcha, not a script bug**: `pg_hba.conf` must list
  every docker-compose bridge subnet in play (each host's compose project
  gets its own `/16`), not just the LAN subnet nodes and replicas dial over.
  `deploy/compose/ha/postgres/pg_hba.conf`'s checked-in placeholder
  (`203.0.113.0/24`) needs both the real LAN CIDR and each host's own bridge
  subnet added per deployment; this is inherent to running Postgres in
  compose on two independent hosts, not something the checked-in file can
  fix once for everyone.
- Topology recovery: `shannon` was rebuilt as a fresh streaming replica of
  `turing` (`pg_basebackup -R` against the new primary) and confirmed
  streaming (`pg_stat_replication` on `turing` showed `shannon`,
  `state=streaming`, `sync_state=async`) — the drill did not leave the
  deployment in a degraded state.

## Backup/restore drill — run 2026-09-04

- Date/operator: 2026-09-04, Adrian Anderson (assisted), against `turing`
  (the promoted primary at that point in the drill).
- Took a real `pg-backup.sh` base backup to an off-host destination (a
  third host, over the network — not the primary's own disk), then
  deliberately corrupted data (`DROP TABLE control_sessions` against the
  live primary), then restored with `pg-restore.sh --yes` to a
  point-in-time target before the corruption.
- **Measured RPO: ~38.5 seconds** — corruption at `15:18:38.749Z`, restore
  reached `15:18:00.211Z` (the last committed transaction actually
  recoverable from archived WAL) before running out of archive. A target
  time closer to the corruption (`15:18:35Z`) was tried first and failed
  with "recovery ended before configured recovery target was reached": the
  archived WAL simply didn't extend that far.
- **Real finding, not an assumed number**: this deployment's
  `postgresql.conf` sets `archive_mode = on` with no `archive_timeout`, so
  WAL segments archive only on completion (16 MB) or an explicit switch.
  Under low write volume — the common case between drills, and plausibly in
  early production too — the actual RPO is bounded by *time since the last
  full segment*, not by replication lag. An operator who wants a tighter,
  bounded RPO should set `archive_timeout` (e.g. `60s`) in
  `deploy/compose/ha/postgres/postgresql.conf`, trading a small steady
  stream of mostly-empty archived segments for a predictable worst-case
  data-loss window. This workstream ships the async-replication trade-off
  documented in §3.4 of the plan; this is the same kind of trade-off one
  layer down, at the archiving layer, and it was not visible from the design
  alone — only from timing a real restore against real WAL archive gaps.
- Restore verified correct: `control_sessions` was back with its
  pre-corruption row; a marker table inserted after the restore point was
  correctly absent.
- Topology recovery: after restore, `turing` promoted onto a new timeline;
  `shannon` was rebuilt as its replica the same way as the failover drill,
  confirmed streaming.

## Duplicate-identity eviction and enrollment — run 2026-09-04

- `lovelace` enrolled against `shannon`'s `karst-control` replica, then was
  reconfigured to dial `turing`'s replica directly and reconnected
  successfully against the same Postgres-backed account — confirming a node
  can land on either replica (§7 step 1).
- Cloned `lovelace`'s ML-DSA control identity (same technique
  [04-pentest.md](../../plans/phase-6/04-pentest.md) §9.7 used to find #87)
  and connected the clone to the replica the legitimate session was *not*
  on. The legitimate session's stream closed (`the stream closed
  unexpectedly`) within the same second the clone's `Claim` landed in
  `control_sessions`, and `replica_id` flipped to the clone's replica —
  cross-replica eviction fired for real, against two live `karst-control`
  processes on two real hosts sharing one Postgres primary. This is the
  regression test for #87 that matters most under HA, and it passed.
- `TestClaimNotifiesOtherReplica`, `TestSecondSessionOnOtherReplicaEvictsFirst`,
  and `TestNotificationReachesPeerOnOtherReplica` were also run against a
  real local Postgres container (not just trusted from CI config) and pass.

## Client failover through a shared entry point — closed, re-run 2026-09-04

§7 step 6 (kill one `karst-control` process while a node is connected,
confirm it reconnects through the *other* replica without operator
intervention) was attempted but not conclusively demonstrated in the first
run on 2026-09-04 (full account in the exit-demo doc's history). That
attempt used an ad-hoc HAProxy improvised mid-drill, on top of extended
prior chaos (repeated primary kills, a PITR restore across timelines, many
client restarts), and produced a connect-then-disconnect loop that was
never run to ground.

The re-run used the real, checked-in load balancer this workstream now
ships — [`deploy/compose/ha/loadbalancer/`](../../deploy/compose/ha/loadbalancer/),
an HAProxy TCP-mode proxy health-checking both replicas — a fresh node with
no prior cache, and no other chaos in flight. `shannon` ran the primary
Postgres and one replica, `turing` the streaming replica and the second,
and the load balancer ran on a third host (`lovelace`), fronting both.

The fresh node's session landed on `turing`. Killing `turing`'s
`karst-control` container (not the database, via `docker kill`) at
`2026-09-04T20:07:36.696Z`: the data plane never dropped (the node kept
advertising to its peer throughout), and the control channel noticed the
dead stream and retried at `20:07:49.347645Z` — the roughly 13-second gap is
the periodic netmap-refresh-poll interval finding the dead connection, not a
slow TCP-level failure detection. `control_sessions` showed the session
re-claimed by `shannon` at `20:07:50.435034Z`. **Measured client failover:
~13.7 seconds**, zero operator intervention, `policy.enforcing` never
dropped to `false`. Full record: [the HA exit-demo doc](../../plans/phase-6/09-ha-exit-demo.md#6-replica-process-kill-and-client-failover--closed-re-run-2026-09-04).

Two real bugs in the checked-in overlay were found and fixed getting this
far: `docker-compose.yml` set `KARST_RELAY_ROSTER_FILE` without
`KARST_AQUIFER`, which fatals `karst-control` at startup unconditionally
(fixed by adding `KARST_AQUIFER`); and the `postgres` service published no
host port, so the other host's replica had no way to reach the primary
across two real hosts (fixed by adding one). Neither had been exercised for
real before this run.

## #75 re-estimate

Each affected update now produces a compact Postgres `NOTIFY` and one local
lookup per replica; no `SyncResponse` payload is broadcast. Re-estimate with
production update rate × replica count before raising replica count.
