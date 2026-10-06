# Two-host HA overlay

Run this overlay once each on `shannon` and `turing`; they are separate failure
domains. Start `shannon` as primary and clone `turing` using `pg_basebackup -R`
and a physical replication slot. Both control replicas point to the current
primary via `NB_STORE_ENGINE_POSTGRES_DSN` and use distinct `KARST_REPLICA_ID`s.

The checked-in setting is asynchronous streaming replication. Its RPO is the
measured WAL/archive lag, not a promise. Operators who require RPO=0 can enable
synchronous commit and a named standby, accepting blocked writes when it fails.

Run `../bootstrap.sh` only once; distribute its bootstrap input read-only.

**Seed `./state/management.json` on each host before first start — it is not
optional here.** `docker-compose.yml` mounts it as a single file
(`./state/management.json:/etc/netbird/management.json`); if the path does
not exist yet, Docker creates a *directory* there instead of failing, and
`karst-control` then loops on `failed reading provided config file: ...: is a
directory` with no hint why. Copy `../state/management.json` (the one
`../bootstrap.sh` wrote) to `state/management.json` on every replica host
before `docker compose up`, and use the identical file on every host — do not
let each host generate its own. It carries `DataStoreEncryptionKey`, which
`boot.go` also uses as an HMAC key "to ensure all management instances are
using the same key"; replicas that generated their own would silently diverge
on it. Editing the copy is also required, not just copying it:
`../bootstrap.sh` writes `"StoreConfig": {"Engine": "sqlite"}` for the
co-located single-host deployment, and that value wins over this overlay's
`NETBIRD_STORE_ENGINE: postgres` — `store.go`'s own comment says the env var
is "supposed to be used in tests. Otherwise, rely on the config file." Change
`Engine` to `"postgres"` in every replica's copy before starting it, or every
replica silently runs its own disconnected local SQLite database instead of
the shared one, with no error either.

Also add `NB_DISABLE_GEOLOCATION: "true"` to the `control` service's
`environment` — the base `deploy/compose/docker-compose.yml` sets it "for a
reason" (its README: first start otherwise fetches GeoLite2 databases from a
third party before serving anything, and a bad download is fatal), and this
overlay does not carry it over.

`KARST_WAL_ARCHIVE_DIR` must be pre-created and owned by the `postgres` image's
runtime user (uid/gid `999`) before first start —
`chown 999:999 that-directory` — or `archive_command` fails with `Permission
denied` on every WAL segment and no base backup ever becomes recoverable past
the last completed checkpoint.

Account state is meant to live in Postgres (once `Engine` above is actually
`"postgres"`). `roster.toml` remains a relay input and is meant to have one
intentional writer, moved explicitly during a host failure. It needs its own
writable mount, separate from the read-only bootstrap input
(`relays.json`/`policy.json`) both replicas share via `KARST_SHARED_STATE_DIR`
— a directory `karst-control` can write and the relay can read cannot also be
the directory that must stay fixed bootstrap input (confirmed live: pointing
`KARST_RELAY_ROSTER_FILE` inside `KARST_SHARED_STATE_DIR`, mounted `:ro`,
fails every 25s with `roster: create temp: ...: read-only file system` on
every replica, and the relay's roster lease expires at 90s and falls back to
admitting nobody — #219). Set `KARST_ROSTER_DIR` on both hosts to the same
physical location (a path the relay's own host also has, e.g. shared over
NFS, or the relay's local disk if it runs on one of the two replica hosts) —
whichever replica holds the one-writer duty writes `roster.toml` there and
the relay reads it from the same path.

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

**Before cloning a replica from any primary that was itself restored with
`pg-restore.sh`**, run `scripts/pg-preflight-clone-source.sh` against that
primary's own `PGDATA` first. `pg_basebackup` copies `postgresql.auto.conf`
verbatim, and a primary that still carries the `recovery_target_time`/
`recovery_target_action` `pg-restore.sh` wrote (`docs/OPERATIONS.md` §4 step
4 exists to clear these, and is easy to skip) hands that stale,
already-elapsed target straight to the clone — which then replays past it
on its first start and silently promotes itself onto a new timeline instead
of staying a standby. Confirmed live (#244): `pg_basebackup -R` itself
reports success either way; the self-promotion gives no error at the
moment it happens, only a confusing failure on a *later*, unrelated clone
attempt. This cannot be checked over the primary's live connection —
`recovery_target_time` has postmaster context, so `SHOW` on it keeps
reporting history rather than the current file — the preflight script
reads `postgresql.auto.conf` directly instead.

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
