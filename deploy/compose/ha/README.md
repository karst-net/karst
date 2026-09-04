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

Without an identity provider, set `KARST_BOOTSTRAP_SETUP_KEY_FILE` in the
`.env` of whichever host starts first (only) — see the checked-in comment in
`docker-compose.yml`. `/var/lib/karst` is read-only in this overlay, so the
path must be under `/var/lib/netbird` (e.g.
`/var/lib/netbird/bootstrap.key`); read it back the same way as
[Getting started §5](../../../docs/GETTING-STARTED.md#5-path-b-a-coordination-server-and-a-relay-with-containers)'s
single-host `cat state/bootstrap.key`, from that host's own `./state/netbird/`.

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
own, by design (§3.1). [`loadbalancer/`](loadbalancer/) ships that front
end: a `haproxy` TCP-mode proxy, health-checking both replicas and
round-robining new connections between them. Edit
`loadbalancer/haproxy.cfg`'s two placeholder `server` lines to the real
`host:port` of each replica, then run
`docker compose -f loadbalancer/docker-compose.yml up -d` on the host that
will be the shared entry point — a third host, not either replica host,
unless that host's own loss taking down the front end too is acceptable.
Point every `karstd.toml`'s `[control] server` at the load balancer's
address, not at either replica directly.

This closes automatic per-process failover for real: a fresh node pointed
at the load balancer, with one `karst-control` process killed while
connected, reconnects through the surviving replica without operator
intervention — measured in [`docs/operations/ha.md`](../../../docs/operations/ha.md),
which also has the caveat this does **not** cover (a whole host, not just its
`karst-control` process, going down — the load balancer itself still needs
its own redundancy plan, same as any other single-instance front end).
