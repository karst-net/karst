#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
set -euo pipefail
[ "${1:-}" = --destination ] && [ -n "${2:-}" ] || { echo "usage: $0 --destination OFF_HOST_DIR" >&2; exit 2; }
: "${PGHOST:?set PGHOST}"; : "${PGUSER:?set PGUSER (replication role)}"
target="$2/$(date -u +%Y%m%dT%H%M%SZ)"; mkdir -p "$target"
# PostgreSQL refuses to start a data directory that is accessible to group or
# other users. Preserve a private mode on the physical backup root so restores
# inherit a valid PGDATA permission set.
chmod 0700 "$target"
# This is a restore source, not a standby: -R would write standby.signal and
# make a point-in-time recovery unexpectedly follow the former primary.
pg_basebackup -D "$target" -Fp -Xs -P
date -u +%FT%TZ > "$target/karst-backup-complete-at"
echo "pg-backup: $target"
