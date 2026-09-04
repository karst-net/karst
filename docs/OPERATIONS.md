<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Karst operations manual

This manual begins after a first node connects. For installation and initial
enrollment, use [Getting started](GETTING-STARTED.md). For the security model
behind an operational choice, use the [security whitepaper](SECURITY-WHITEPAPER.md).

## 1. Deployment topologies

### Container deployment

Use [`deploy/compose/README.md`](../deploy/compose/README.md) as the canonical
procedure for the co-located control, relay, and optional TURN services. Keep
`state/` private and backed up off-host; it contains the server keys pinned by
every node. Verify release images with `cosign`, record their immutable
digests, and deploy those digests rather than mutable tags. Re-running
`bootstrap.sh` completes missing state without rotating existing identities.

For two failure domains and PostgreSQL replication, apply
[`deploy/compose/ha/`](../deploy/compose/ha/README.md) on both hosts. Give each
control process a distinct `KARST_REPLICA_ID`, point both DSNs at the current
primary, and provide a shared load-balanced entry point. Karst does not ship
that front end and a node configured with one replica address cannot
automatically choose the other.

### Bare metal and systemd

Follow [Getting started §6](GETTING-STARTED.md#6-path-c-bare-metal-and-systemd).
The installed `ExecStopPost=karst dns revert` is part of safe operation: keep
it when customizing the unit. Back up `/etc/karst`, `/etc/netbird`, and server
state with permissions and ownership intact.

## 2. Day-to-day operations

### Enroll and revoke nodes and users

Issue a one-off, short-lived setup key in Console → Auth keys, place it in the
new node's `[control] setup_key`, start `karstd`, and confirm addresses plus
`policy.enforcing = true` with `sudo karst status`. Remove the setup key from
the node configuration after registration. Revoke a device from Machines and
deprovision a user through the configured IdP/SCIM path; both invalidate the
affected live sessions. The CI gate measures deprovisioning at 2.0 seconds
against a 30-second bound (`plans/phase-6/00-overview.md` §0.1).

Keep the bootstrap setup key only until OIDC administration works, then revoke
it. It is reusable and non-expiring by design.

### Rotate the relay roster

The coordination server is the single writer for a co-located relay roster.
Edit the relay registry through the admin API/console, wait for
`KARST_RELAY_ROSTER_FILE` to refresh, then run `karst-relay check` against the
result before retiring an old relay. Admission leases expire after 90 seconds;
the default writer refreshes every 25 seconds. During HA failover, explicitly
move the one-writer duty—never run competing roster writers.

### Read node status

Run `sudo karst status`. Empty `addresses` means no netmap arrived;
`policy.enforcing = false` means traffic is not filtered; `connecting` with
`transport = relay` is normal during path discovery, while persistent relay
use deserves NAT/TURN inspection. Check netmap age and control-session health
before changing firewall rules.

## 3. Observability and diagnostics

Scrape `karst-control` at `:9090/metrics` and each opted-in node at its
loopback-only metrics listener. The canonical metric names, labels, queries,
OTel spans, and alert meanings are in [Observability](observability.md). Set
`OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` on control replicas to export traces.

Print a sanitized support bundle with:

```sh
sudo karst bugreport
```

Review the output before sharing it. It intentionally omits netmap PSKs,
TURN credentials, and keys, while reporting control-session health, Bedrock
chain state, relay/TURN reachability, configuration with secrets redacted, and
recent logs. Correlate a stale netmap with
`management_karst_netmap_push_duration_ms_milliseconds`; check
`management_karst_bedrock_anchor_age_seconds` and
`management_karst_psk_epoch_age_seconds` before blaming the datapath.

## 4. Backup and restore

This procedure is the operator form of the exercised
[HA record](operations/ha.md), not an independently invented runbook.

1. Keep base backups and the continuous WAL archive on a different failure
   domain from the primary. Set `PGHOST` and the replication-role `PGUSER`,
   then run:

   ```sh
   PGHOST=primary.example PGUSER=replicator \
     scripts/pg-backup.sh --destination /mnt/off-host/karst
   ```

2. Choose a recovery time before the unwanted change. Fence and stop the
   database at the restore target. Set `PGDATA` and
   `KARST_WAL_ARCHIVE_DIR`, then prepare point-in-time recovery:

   ```sh
   PGDATA=/var/lib/postgresql/data \
   KARST_WAL_ARCHIVE_DIR=/mnt/off-host/karst-wal \
     scripts/pg-restore.sh --backup /mnt/off-host/karst/20260904T150000Z \
       --target-time 2026-09-04T15:18:00.211Z --yes
   ```

3. Start PostgreSQL, wait for recovery to promote, and verify known
   pre-target rows exist and post-target marker rows do not. Repoint both
   control replicas, recreate them, enroll or reconnect a node, and verify
   reads and writes. Preserve the script-created `.pre-restore.*` directory
   until verification is complete.

The drill on 2026-09-04 used these commands after deliberately dropping
`control_sessions` and measured **RPO ≈38.5 seconds**: corruption at
`15:18:38.749Z`, recoverable state at `15:18:00.211Z`. This is a measurement,
not a guarantee. Without `archive_timeout`, low write volume can leave an
older incomplete 16 MiB WAL segment unarchived. Set an appropriate
`archive_timeout` (for example `60s`) and test it if a bounded RPO is required.

## 5. Failover

The tested manual failover sequence is:

1. Fence the old primary so it cannot return and create split brain.
2. Update both control replicas' `NB_STORE_ENGINE_POSTGRES_DSN` to the
   standby that will become primary.
3. On the standby host run
   `scripts/pg-promote.sh --compose-dir deploy/compose/ha`.
4. Recreate the control services on both hosts and confirm reads and writes.
5. Move the relay-roster writer explicitly. Rebuild the old primary with a
   fresh `pg_basebackup -R`; never restart its old data directory. Verify
   `pg_stat_replication` reports `state=streaming`.

On 2026-09-04 this command sequence measured **control read/write RTO ≈45
seconds**, from `docker kill` of the old primary until both control replicas
served against the promoted primary. The node dataplane stayed up. Automatic
control-process failover through a shared entry point was not conclusively
demonstrated; validate your production load balancer with a fresh node before
depending on it. Full evidence and limitations are in
[the HA operations record](operations/ha.md).

## 6. Operator `justfile` index

These source-checkout targets operate or validate deployable artifacts. All
other public targets (`check`, formatting, lint, unit/integration tests,
generators, mocks, web development, fuzzing, and walkthroughs) are developer
or CI tasks, not deployment operations.

| Target | Operator use |
|---|---|
| `just packages VERSION` | Build `.deb`/`.rpm` artifacts and their upgrade fixture after release binaries exist. |
| `just packages-verify` | Install, upgrade, and uninstall those packages on every documented Linux distribution. |
| `just packages-verify-systemd` | Verify packaged systemd startup and DNS recovery after `SIGKILL`. |
| `just macos-package` | Build the universal `.pkg`; signs/notarizes only when credentials are supplied. |
| `just licenses` | Refresh third-party license material for a release. |
| `just licenses-check` | Verify SPDX coverage before publishing. |
| `just secrets-scan` | Scan the release checkout for leaked credentials. |
| `just deny` | Check dependency advisories and the license allowlist. |
| `just verify` | Run the bounded formal-verification release gate. |
| `just verify-slow` | Run expensive broken-primitive models before a consequential release. |

`just` is not installed on production hosts merely to run Karst. Commands in
the backup/failover sections invoke shipped scripts directly.

## 7. Upgrading a deployment

1. Read the release notes and verify every downloaded package or image.
   For containers, follow the `cosign verify` procedure in
   `deploy/compose/README.md` and record image digests. For client artifacts,
   compare SHA-256 with the generated release manifest.
2. Take and verify an off-host database backup. Back up `state/`,
   `/etc/karst`, and `/etc/netbird`; do not regenerate pinned identities.
3. In HA, stop all control replicas for schema migrations unless the release
   explicitly documents compatibility. Upgrade one failure domain at a time,
   then restore replication before continuing. Do not mix incompatible wire
   or database versions: pre-alpha wire formats have no compatibility promise.
4. Upgrade nodes with the native package manager. The packages preserve
   configuration and restart `karstd`; confirm `karst status`, policy
   enforcement, DNS, and peer traffic after each cohort.
5. Upgrade relays and control images by verified digest, run component
   `check` commands, then verify metrics, enrollment, netmap push, direct and
   relayed traffic. Keep the prior verified artifacts and backup until the
   observation window passes.

Release automation discovers real artifacts with
`scripts/release-manifest.sh RELEASE_DIR OUTPUT_JSON`; it does not invent
platforms that were not built. Validate Linux packaging with
`just packages-verify` and the service/DNS lifecycle with
`just packages-verify-systemd` before publishing.
