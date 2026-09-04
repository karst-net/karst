#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
set -euo pipefail
[ "${1:-}" = --destination ] && [ -n "${2:-}" ] || { echo "usage: $0 --destination OFF_HOST_DIR" >&2; exit 2; }
: "${PGHOST:?set PGHOST}"; : "${PGUSER:?set PGUSER (replication role)}"
target="$2/$(date -u +%Y%m%dT%H%M%SZ)"; mkdir -p "$target"
pg_basebackup -D "$target" -Fp -Xs -P -R
date -u +%FT%TZ > "$target/karst-backup-complete-at"
echo "pg-backup: $target"
