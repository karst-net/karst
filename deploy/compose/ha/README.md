# Two-host HA overlay

Run this overlay once each on `shannon` and `turing`; they are separate failure
domains. Start `shannon` as primary and clone `turing` using `pg_basebackup -R`
and a physical replication slot. Both control replicas point to the current
primary via `NB_STORE_ENGINE_POSTGRES_DSN` and use distinct `KARST_REPLICA_ID`s.

The checked-in setting is asynchronous streaming replication. Its RPO is the
measured WAL/archive lag, not a promise. Operators who require RPO=0 can enable
synchronous commit and a named standby, accepting blocked writes when it fails.

Run `../bootstrap.sh` only once; distribute its bootstrap input read-only.
Account state lives in Postgres. `roster.toml` remains a relay input and has one
intentional writer; move that duty explicitly during a host failure.

Fence the old primary, update both replicas' DSNs, then promote on the standby:

```sh
scripts/pg-promote.sh --compose-dir deploy/compose/ha
```

Recreate the old primary with `pg_basebackup`; never restart its old data
directory. Backups and WAL archive must be off-host; see the scripts and
[`docs/operations/ha.md`](../../../docs/operations/ha.md) for the real-drill
record.
