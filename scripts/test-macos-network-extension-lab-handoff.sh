#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
helper="$root/scripts/macos-network-extension-lab-handoff.sh"
temp=$(mktemp -d)
trap "rm -rf \"$temp\"" EXIT

make_fixture() {
  local name=$1
  local route_churn=$2
  local extra=${3:-}
  local invitation="$temp/$name.invitation"
  local handoff="$temp/$name.env"
  printf "karst-invite-v1:test\n" > "$invitation"
  chmod 600 "$invitation"
  {
    printf "KARST_CI_INVITATION_FILE=%s\n" "$invitation"
    printf "KARST_CI_PROBE_URL=http://100.64.0.2/probe\n"
    printf "KARST_CI_UDP_HOST=100.64.0.2\nKARST_CI_UDP_PORT=9000\n"
    if [[ "$route_churn" == true ]]; then
      printf "KARST_CI_SUBNET_PROBE_URL=http://10.23.0.2/probe\n"
      printf "KARST_CI_SUBNET_ROUTE_PREFIX=10.23.0.0/24\n"
    fi
    printf "%s" "$extra"
  } > "$handoff"
  chmod 600 "$handoff"
}

make_fixture basic false
GITHUB_ENV="$temp/basic.github-env" KARST_CI_ROUTE_CHURN=false "$helper" "$temp/basic.env"
grep -qx "KARST_CI_UDP_PORT=9000" "$temp/basic.github-env"
test ! -e "$temp/basic.env"

make_fixture route true
GITHUB_ENV="$temp/route.github-env" KARST_CI_ROUTE_CHURN=true "$helper" "$temp/route.env"
grep -qx "KARST_CI_SUBNET_ROUTE_PREFIX=10.23.0.0/24" "$temp/route.github-env"

make_fixture exit false
{
  printf "KARST_CI_EXIT_PROBE_URL=http://198.51.100.2/probe\n"
  printf "KARST_CI_EXIT_ROUTE_PREFIX=0.0.0.0/0\n"
  printf "KARST_CI_CONTROL_PLANE_PROBE_URL=https://control.example/probe\n"
  printf "KARST_CI_CONTROL_PLANE_HOST=control.example\nKARST_CI_CONTROL_PLANE_INTERFACE=en0\n"
  printf "KARST_CI_RELAY_PROBE_URL=https://relay.example/probe\n"
  printf "KARST_CI_RELAY_HOST=relay.example\nKARST_CI_RELAY_INTERFACE=en0\n"
} >> "$temp/exit.env"
GITHUB_ENV="$temp/exit.github-env" KARST_CI_EXIT_ROUTE=true "$helper" "$temp/exit.env"
grep -qx "KARST_CI_EXIT_ROUTE_PREFIX=0.0.0.0/0" "$temp/exit.github-env"

make_fixture forbidden false $'NOT_ALLOWED=value\n'
if GITHUB_ENV="$temp/forbidden.github-env" KARST_CI_ROUTE_CHURN=false "$helper" "$temp/forbidden.env" 2>/dev/null; then
  echo "unexpected handoff entry was accepted" >&2
  exit 1
fi

make_fixture unexpected-route false $'KARST_CI_SUBNET_ROUTE_PREFIX=10.23.0.0/24\n'
if GITHUB_ENV="$temp/unexpected-route.github-env" KARST_CI_ROUTE_CHURN=false "$helper" "$temp/unexpected-route.env" 2>/dev/null; then
  echo "route entry without route-churn was accepted" >&2
  exit 1
fi

make_fixture unexpected-exit false $'KARST_CI_EXIT_ROUTE_PREFIX=0.0.0.0/0\n'
if GITHUB_ENV="$temp/unexpected-exit.github-env" KARST_CI_EXIT_ROUTE=false "$helper" "$temp/unexpected-exit.env" 2>/dev/null; then
  echo "exit entry without exit-route was accepted" >&2
  exit 1
fi
