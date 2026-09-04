#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
set -euo pipefail
[ "${1:-}" = --destination ] && [ -n "${2:-}" ] || { echo "usage: $0 --destination OFF_HOST_DIR" >&2; exit 2; }
: "${PGHOST:?set PGHOST}"; : "${PGUSER:?set PGUSER (replication role)}"
target="$2/$(date -u +%Y%m%dT%H%M%SZ)"; mkdir -p "$target"
# This is a restore source, not a standby: -R would write standby.signal and
# make a point-in-time recovery unexpectedly follow the former primary.
pg_basebackup -D "$target" -Fp -Xs -P
date -u +%FT%TZ > "$target/karst-backup-complete-at"
echo "pg-backup: $target"
