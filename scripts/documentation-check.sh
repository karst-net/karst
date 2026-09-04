#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright the Karst contributors.

set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo"

fail() { echo "documentation-check: $*" >&2; exit 1; }
has() { grep -Fq -- "$2" "$1" || fail "$1 does not contain: $2"; }

for file in \
  docs/GETTING-STARTED.md \
  docs/OPERATIONS.md \
  docs/SECURITY-WHITEPAPER.md \
  docs/MIGRATING-FROM-WIREGUARD-TAILSCALE.md; do
  test -s "$file" || fail "missing or empty: $file"
done
test ! -e docs/INSTALL.md || fail "GETTING-STARTED.md is the install guide; do not add docs/INSTALL.md"

# The correction must remain stricter than the prose requirement: no Phase 6
# mention means it cannot quietly regain a Phase 6 external-review promise.
if grep -n "Phase 6" docs/THREAT-MODEL.md; then
  fail "THREAT-MODEL.md still mentions Phase 6"
fi
has docs/THREAT-MODEL.md "External cryptographic review"
has docs/THREAT-MODEL.md "Phase 8"

has docs/GETTING-STARTED.md "### 7.1 The node control channel is plaintext h2c"
has docs/GETTING-STARTED.md "### 7.2 A single TLS origin needs a separate node-control port"
has docs/GETTING-STARTED.md "[operations manual](OPERATIONS.md)"

for heading in \
  "## 1. Deployment topologies" \
  "## 2. Day-to-day operations" \
  "## 3. Observability and diagnostics" \
  "## 4. Backup and restore" \
  "## 5. Failover" \
  '## 6. Operator `justfile` index' \
  "## 7. Upgrading a deployment"; do
  has docs/OPERATIONS.md "$heading"
done
has docs/OPERATIONS.md "2026-09-04"
has docs/OPERATIONS.md "RPO ≈38.5 seconds"
has docs/OPERATIONS.md "RTO ≈45"
has docs/OPERATIONS.md "scripts/pg-backup.sh --destination"
has docs/OPERATIONS.md "scripts/pg-restore.sh --backup"
has docs/OPERATIONS.md "scripts/pg-promote.sh --compose-dir"
has docs/OPERATIONS.md "[security whitepaper](SECURITY-WHITEPAPER.md)"

operator_targets=(packages packages-verify packages-verify-systemd macos-package licenses licenses-check secrets-scan deny verify verify-slow)
for target in "${operator_targets[@]}"; do
  grep -Eq "^${target}([[:space:]].*)?:" justfile || fail "justfile target disappeared: $target"
  grep -Fq -- "just ${target}" docs/OPERATIONS.md || fail "operator target absent from manual: $target"
done

has docs/MIGRATING-FROM-WIREGUARD-TAILSCALE.md "Karst has **no WireGuard interoperability bridge**"
has docs/MIGRATING-FROM-WIREGUARD-TAILSCALE.md '```json migration-policy'
has docs/MIGRATING-FROM-WIREGUARD-TAILSCALE.md "## 4. Clean-cutover procedure"

has docs/SECURITY-WHITEPAPER.md "No external cryptographic review and no external penetration test have"
has docs/SECURITY-WHITEPAPER.md "**Crypto lead:**"
has README.md "[install guide](docs/GETTING-STARTED.md)"
has README.md "[operations manual](docs/OPERATIONS.md)"
has README.md "[security whitepaper](docs/SECURITY-WHITEPAPER.md)"
has README.md "[WireGuard/Tailscale migration guide](docs/MIGRATING-FROM-WIREGUARD-TAILSCALE.md)"

# Reject the two misleading status claims this workstream exists to prevent.
if grep -Eiq '(external (cryptographic review|penetration test) (is |was )?(complete|completed)|external (cryptographic review|penetration test) happened in Phase 6)' \
    README.md docs/GETTING-STARTED.md docs/OPERATIONS.md \
    docs/SECURITY-WHITEPAPER.md docs/MIGRATING-FROM-WIREGUARD-TAILSCALE.md; then
  fail "a public document appears to claim completed external review"
fi

./scripts/getting-started-walkthrough.sh tags
echo "documentation-check: static documentation invariants pass"
