#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Validates the root-owned macOS NE lab handoff without printing invitations.
set -euo pipefail

env_file=${1:?usage: macos-network-extension-lab-handoff.sh ENV_FILE}
: "${GITHUB_ENV:?GITHUB_ENV is required}"
route_churn=${KARST_CI_ROUTE_CHURN:-false}
exit_route=${KARST_CI_EXIT_ROUTE:-false}

file_mode() {
  if [[ "$(uname -s)" == Darwin ]]; then stat -f "%Lp" "$1"; else stat -c "%a" "$1"; fi
}
require_url() { case "$1" in http://*|https://*) ;; *) exit 1 ;; esac; }
require_prefix() { case "$1" in */*) ;; *) exit 1 ;; esac; }

test "$(file_mode "$env_file")" -le 600
invitation_file= probe_url= udp_host= udp_port=
subnet_probe_url= subnet_route_prefix=
exit_probe_url= exit_route_prefix=
control_plane_probe_url= control_plane_host= control_plane_interface=
relay_probe_url= relay_host= relay_interface=

while IFS= read -r line; do
  case "$line" in
    KARST_CI_INVITATION_FILE=*) invitation_file=${line#*=} ;;
    KARST_CI_PROBE_URL=*) probe_url=${line#*=} ;;
    KARST_CI_UDP_HOST=*) udp_host=${line#*=} ;;
    KARST_CI_UDP_PORT=*) udp_port=${line#*=} ;;
    KARST_CI_SUBNET_PROBE_URL=*) [[ "$route_churn" == true ]] || { echo "unexpected route-churn environment entry" >&2; exit 1; }; subnet_probe_url=${line#*=} ;;
    KARST_CI_SUBNET_ROUTE_PREFIX=*) [[ "$route_churn" == true ]] || { echo "unexpected route-churn environment entry" >&2; exit 1; }; subnet_route_prefix=${line#*=} ;;
    KARST_CI_EXIT_PROBE_URL=*) [[ "$exit_route" == true ]] || { echo "unexpected exit-route environment entry" >&2; exit 1; }; exit_probe_url=${line#*=} ;;
    KARST_CI_EXIT_ROUTE_PREFIX=*) [[ "$exit_route" == true ]] || { echo "unexpected exit-route environment entry" >&2; exit 1; }; exit_route_prefix=${line#*=} ;;
    KARST_CI_CONTROL_PLANE_PROBE_URL=*) [[ "$exit_route" == true ]] || { echo "unexpected exit-route environment entry" >&2; exit 1; }; control_plane_probe_url=${line#*=} ;;
    KARST_CI_CONTROL_PLANE_HOST=*) [[ "$exit_route" == true ]] || { echo "unexpected exit-route environment entry" >&2; exit 1; }; control_plane_host=${line#*=} ;;
    KARST_CI_CONTROL_PLANE_INTERFACE=*) [[ "$exit_route" == true ]] || { echo "unexpected exit-route environment entry" >&2; exit 1; }; control_plane_interface=${line#*=} ;;
    KARST_CI_RELAY_PROBE_URL=*) [[ "$exit_route" == true ]] || { echo "unexpected exit-route environment entry" >&2; exit 1; }; relay_probe_url=${line#*=} ;;
    KARST_CI_RELAY_HOST=*) [[ "$exit_route" == true ]] || { echo "unexpected exit-route environment entry" >&2; exit 1; }; relay_host=${line#*=} ;;
    KARST_CI_RELAY_INTERFACE=*) [[ "$exit_route" == true ]] || { echo "unexpected exit-route environment entry" >&2; exit 1; }; relay_interface=${line#*=} ;;
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
require_url "$probe_url"
case "$udp_port" in *[!0-9]*|"") exit 1 ;; esac
if [[ "$route_churn" == true ]]; then
  : "${subnet_probe_url:?lab bootstrap did not provide a subnet probe URL}"
  : "${subnet_route_prefix:?lab bootstrap did not provide a subnet route prefix}"
  require_url "$subnet_probe_url"; require_prefix "$subnet_route_prefix"
fi
if [[ "$exit_route" == true ]]; then
  : "${exit_probe_url:?lab bootstrap did not provide an exit probe URL}"
  : "${exit_route_prefix:?lab bootstrap did not provide an exit route prefix}"
  : "${control_plane_probe_url:?lab bootstrap did not provide a control-plane probe URL}"
  : "${control_plane_host:?lab bootstrap did not provide a control-plane host}"
  : "${control_plane_interface:?lab bootstrap did not provide a control-plane interface}"
  : "${relay_probe_url:?lab bootstrap did not provide a relay probe URL}"
  : "${relay_host:?lab bootstrap did not provide a relay host}"
  : "${relay_interface:?lab bootstrap did not provide a relay interface}"
  require_url "$exit_probe_url"; require_prefix "$exit_route_prefix"
  require_url "$control_plane_probe_url"; require_url "$relay_probe_url"
fi
