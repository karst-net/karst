#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Validates the root-owned macOS NE lab handoff without printing invitations.
set -euo pipefail

env_file=${1:?usage: macos-network-extension-lab-handoff.sh ENV_FILE}
: "${GITHUB_ENV:?GITHUB_ENV is required}"
route_churn=${KARST_CI_ROUTE_CHURN:-false}

file_mode() {
  if [[ "$(uname -s)" == Darwin ]]; then
    stat -f "%Lp" "$1"
  else
    stat -c "%a" "$1"
  fi
}

test "$(file_mode "$env_file")" -le 600
invitation_file=
probe_url=
udp_host=
udp_port=
subnet_probe_url=
subnet_route_prefix=

while IFS= read -r line; do
  case "$line" in
    KARST_CI_INVITATION_FILE=*) invitation_file=${line#*=} ;;
    KARST_CI_PROBE_URL=*) probe_url=${line#*=} ;;
    KARST_CI_UDP_HOST=*) udp_host=${line#*=} ;;
    KARST_CI_UDP_PORT=*) udp_port=${line#*=} ;;
    KARST_CI_SUBNET_PROBE_URL=*)
      [[ "$route_churn" == true ]] || { echo "unexpected route-churn environment entry" >&2; exit 1; }
      subnet_probe_url=${line#*=} ;;
    KARST_CI_SUBNET_ROUTE_PREFIX=*)
      [[ "$route_churn" == true ]] || { echo "unexpected route-churn environment entry" >&2; exit 1; }
      subnet_route_prefix=${line#*=} ;;
    *) echo "unexpected lab environment entry" >&2; exit 1 ;;
  esac
  echo "$line" >> "$GITHUB_ENV"
done < "$env_file"
rm -f "$env_file"

: "${invitation_file:?lab bootstrap did not provide an invitation file}"
: "${probe_url:?lab bootstrap did not provide an overlay probe URL}"
: "${udp_host:?lab bootstrap did not provide an overlay UDP host}"
: "${udp_port:?lab bootstrap did not provide an overlay UDP port}"
test -r "$invitation_file"
test "$(file_mode "$invitation_file")" -le 600
case "$probe_url" in http://*|https://*) ;; *) exit 1 ;; esac
case "$udp_port" in *[!0-9]*|"" ) exit 1 ;; esac
if [[ "$route_churn" == true ]]; then
  : "${subnet_probe_url:?lab bootstrap did not provide a subnet probe URL}"
  : "${subnet_route_prefix:?lab bootstrap did not provide a subnet route prefix}"
  case "$subnet_probe_url" in http://*|https://*) ;; *) exit 1 ;; esac
  case "$subnet_route_prefix" in */*) ;; *) exit 1 ;; esac
fi
