# HA operations record

This record is completed only by a real `shannon`/`turing` drill; a compose
run is not evidence of HA. Schema upgrades require all control replicas stopped
or explicit acceptance of the existing migration race.

## Failover drill — pending

- Date/operator/log bundle: **not yet run**
- Control read/write RTO: **not yet measured**
- Node survival or reconnect time: **not yet measured**

Fence `shannon`, change every control DSN to `turing`, run `pg-promote.sh` on
`turing`, measure service and node recovery, then rebuild `shannon` as standby.

## Backup/restore drill — pending

- Date/transcripts: **not yet run**
- Measured RPO (last archived WAL to corruption): **not yet measured**

Take an off-host `pg_basebackup`, corrupt a known record, restore to before it
with `pg-restore.sh --yes`, and preserve the original data directory until
verification succeeds.

## #75 re-estimate

Each affected update now produces a compact Postgres `NOTIFY` and one local
lookup per replica; no `SyncResponse` payload is broadcast. Re-estimate with
production update rate × replica count before raising replica count.
