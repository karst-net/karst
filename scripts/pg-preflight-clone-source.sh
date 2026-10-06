#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
set -euo pipefail
: "${PGDATA:?set PGDATA to the primary data directory}"
conf="$PGDATA/postgresql.auto.conf"

# Run this ON THE PRIMARY, before anyone runs `pg_basebackup -R` against it
# to build or rebuild a replica.
#
# pg_basebackup copies PGDATA's files verbatim, including
# postgresql.auto.conf -- so a primary that was itself restored with
# pg-restore.sh and never had its recovery_target_time/recovery_target_action
# cleared (OPERATIONS.md §4 step 4) hands that stale, already-elapsed target
# straight to the new replica. The clone reports success; the "replica" then
# replays past that target on its first start and silently promotes itself
# onto a new timeline instead of staying a standby (#244) -- split-brain,
# with no error at the moment of the mistake.
#
# This cannot be checked over a live connection: recovery_target_time has
# postmaster context, so a running primary's own `SHOW recovery_target_time`
# keeps reporting whatever was true when recovery last started, forever,
# regardless of any later `ALTER SYSTEM RESET` + `pg_reload_conf()` --
# confirmed live while fixing #244. The file is the only ground truth.
if grep -qE '^\s*recovery_target_(time|action)\s*=' "$conf" 2>/dev/null; then
	echo "pg-preflight-clone-source: $conf still sets recovery_target_time/action." >&2
	echo "A replica cloned from this primary now would self-promote instead of" >&2
	echo "staying a standby. Clear it first (OPERATIONS.md §4 step 4):" >&2
	echo >&2
	echo "  ALTER SYSTEM RESET recovery_target_time;" >&2
	echo "  ALTER SYSTEM RESET recovery_target_action;" >&2
	echo "  SELECT pg_reload_conf();" >&2
	exit 1
fi
echo "pg-preflight-clone-source: $conf is clean; safe to clone a replica from this primary"
