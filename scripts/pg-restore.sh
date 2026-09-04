#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
set -euo pipefail
backup= time= yes=0
while [ $# -gt 0 ]; do case "$1" in --backup) backup=$2; shift 2;; --target-time) time=$2; shift 2;; --yes) yes=1; shift;; *) exit 2;; esac; done
[ "$yes" = 1 ] && [ -d "$backup" ] && [ -n "$time" ] || { echo "usage: $0 --backup DIR --target-time TIME --yes" >&2; exit 2; }
: "${PGDATA:?set stopped restore target}"; : "${KARST_WAL_ARCHIVE_DIR:?set off-host archive}"
[ ! -e "$PGDATA/postmaster.pid" ] || { echo "pg-restore: postgres is running" >&2; exit 1; }
mv "$PGDATA" "$PGDATA.pre-restore.$(date -u +%Y%m%dT%H%M%SZ)"; cp -a "$backup" "$PGDATA"
rm -f "$PGDATA/standby.signal"
echo "restore_command = 'cp $KARST_WAL_ARCHIVE_DIR/%f %p'" >> "$PGDATA/postgresql.auto.conf"
echo "recovery_target_time = '$time'" >> "$PGDATA/postgresql.auto.conf"
echo "recovery_target_action = 'promote'" >> "$PGDATA/postgresql.auto.conf"; touch "$PGDATA/recovery.signal"
echo "pg-restore: prepared; start Postgres and verify before deleting preserved data"
