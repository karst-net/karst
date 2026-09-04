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

`postgres/pg_hba.conf`'s checked-in rule uses this file's own placeholder
subnet — replace it with the real LAN CIDR the two hosts share, **and** add
each host's own docker-compose bridge subnet (`docker network inspect
karst-ha_default`), since `control` on the same host reaches `postgres`
through that bridge, not the LAN. Two independent hosts get two independent
bridge subnets; a real drill needed both added, not just the LAN one — see
`docs/operations/ha.md`'s 2026-09-04 run.

Clients need a shared, load-balanced (or round-robin DNS) entry point in
front of both replicas' `KARST_CONTROL_PORT`s to actually fail over
automatically when one replica's `karst-control` process dies — a
`karstd.toml` with a single fixed `server` address cannot do this on its
own, by design (§3.1). This overlay does not ship that front end; provide
one before relying on automatic per-process failover, and validate it
directly rather than assuming a TCP proxy is transparent to a long-lived
gRPC/HTTP2 stream.
