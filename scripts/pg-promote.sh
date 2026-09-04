#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
set -euo pipefail
dir=deploy/compose/ha
while [ $# -gt 0 ]; do case "$1" in --compose-dir) dir=$2; shift 2;; *) echo "usage: $0 [--compose-dir DIR]" >&2; exit 2;; esac; done
cd "$dir"
# The operator must fence the former primary before this script is run.
docker compose exec -T postgres psql -U "${POSTGRES_USER:-karst}" -d "${POSTGRES_DB:-karst}" -Atqc 'SELECT pg_is_in_recovery()' | grep -qx t || { echo "pg-promote: local postgres is not a standby" >&2; exit 1; }
start=$(date +%s)
docker compose exec -T postgres pg_ctl promote -D /var/lib/postgresql/data -w
docker compose exec -T postgres psql -U "${POSTGRES_USER:-karst}" -d "${POSTGRES_DB:-karst}" -Atqc 'SELECT NOT pg_is_in_recovery()' | grep -qx t
# Update NB_STORE_ENGINE_POSTGRES_DSN on both hosts before recreating controls.
docker compose up -d --force-recreate control
echo "pg-promote: completed in $(( $(date +%s) - start ))s"
