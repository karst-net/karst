#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright the Karst contributors.
#
# ADR-0045 §7b (issue #311): the reference coturn bootstrap #310 named as
# a non-goal. Mints nothing of its own -- it redeems a single-use token
# against /karst/v1/turn/enroll, the TURN-side equivalent of the relay
# bundle-Secret karst-scaler-k8s's own init container reads (see that
# driver's own doc, docs/operations/scaler-k8s-driver.md). A vanilla
# coturn has no Karst code to carry this logic, so this is a shell
# wrapper rather than a subcommand on an existing Karst binary.
#
# This script's own job stops at the one invariant Karst needs from a
# coturn config it did not write: static-auth-secret must be the same
# secret the control server's turncred.Minter is configured with
# (turncred.go's own doc: "an operator-configured list of server URIs,
# and a shared secret this package never puts on the wire" -- enrollment
# registers a URI, nothing else, and never carries this secret). Every
# other coturn setting (TLS certs for turns:, min-port/max-port, external-ip
# for NAT, ...) is the operator's own config, supplied via
# KARST_TURN_BASE_CONF -- this script appends to it, never replaces it.

set -eu

# If a per-pod bundle file is mounted, source it before the required-var
# checks below so its values can supply them -- karst-scaler-turn-k8s's
# own Secret-volume-with-per-ordinal-keys delivery (a StatefulSet's one
# shared pod template cannot reference a different Secret key per pod any
# other way; see that crate's own bundle.rs doc comment). Defaults to a
# path derived from this pod's own hostname, matching
# karst-scaler-k8s's own "$(POD_NAME).toml" convention -- a StatefulSet
# pod's hostname is always its own pod name. A deployment that sets
# KARST_TURN_URI etc. directly (no driver, no mounted bundle) never has
# this file and skips straight to the checks below unchanged.
KARST_TURN_ENV_FILE="${KARST_TURN_ENV_FILE:-/etc/karst/enroll/$(hostname).env}"
if [ -f "$KARST_TURN_ENV_FILE" ]; then
    # shellcheck disable=SC1090  # the path is only known at runtime
    . "$KARST_TURN_ENV_FILE"
fi

: "${KARST_CONTROL_API_BASE:?set to the control servers own API base, e.g. https://control.example.test/api}"
: "${KARST_TURN_ENROLL_TOKEN:?set to a single-use token minted by POST /karst/v1/turn/enroll-tokens (a UserRoleScaler- or admin-session-minted token)}"
: "${KARST_TURN_URI:?set to this instances own turn: or turns: URI, e.g. turn:turn-0.turn.example.test:3478 -- must match whatever coturn actually listens on, and whatever a driver will later pass to /karst/v1/turn/deenroll}"
: "${KARST_TURN_STATIC_AUTH_SECRET:?set to the operators own shared TURN-REST secret -- must match the control servers turncred.Minter secret exactly; this script never mints, derives, or receives it over the network}"

KARST_TURN_REGION="${KARST_TURN_REGION:-}"
KARST_TURN_REALM="${KARST_TURN_REALM:-karst}"
KARST_TURN_BASE_CONF="${KARST_TURN_BASE_CONF:-}"
KARST_TURN_GENERATED_CONF="${KARST_TURN_GENERATED_CONF:-/etc/turnserver.generated.conf}"
enroll_response="$(mktemp)"
trap 'rm -f "$enroll_response"' EXIT

echo "karst-turn-bootstrap: enrolling ${KARST_TURN_URI} (region=${KARST_TURN_REGION:-default})" >&2

# Hand-built JSON, not jq: turncred.Entry has exactly two string fields,
# and keeping this script's only dependency curl (already required to
# reach the control API at all) matches this tree's general posture of
# not pulling in a parser for a shape this fixed.
body="$(printf '{"uri":"%s","region":"%s"}' "$KARST_TURN_URI" "$KARST_TURN_REGION")"

http_code="$(curl -sS -o "$enroll_response" -w '%{http_code}' \
    -X POST "${KARST_CONTROL_API_BASE}/karst/v1/turn/enroll" \
    -H "Authorization: Bearer ${KARST_TURN_ENROLL_TOKEN}" \
    -H 'Content-Type: application/json' \
    -d "$body")"

case "$http_code" in
    201)
        echo "karst-turn-bootstrap: enrolled" >&2
        ;;
    412)
        # turncred.ErrExists -- this exact uri is already registered
        # (e.g. a restarted container redeeming an already-consumed
        # token's uri again). Not fatal: the registry entry this run
        # would have created already exists.
        echo "karst-turn-bootstrap: ${KARST_TURN_URI} is already enrolled, continuing" >&2
        ;;
    *)
        echo "karst-turn-bootstrap: enroll failed, HTTP ${http_code}: $(cat "$enroll_response")" >&2
        exit 1
        ;;
esac

if [ -n "$KARST_TURN_BASE_CONF" ]; then
    cp "$KARST_TURN_BASE_CONF" "$KARST_TURN_GENERATED_CONF"
else
    : > "$KARST_TURN_GENERATED_CONF"
fi

cat >> "$KARST_TURN_GENERATED_CONF" <<CONF
use-auth-secret
static-auth-secret=${KARST_TURN_STATIC_AUTH_SECRET}
realm=${KARST_TURN_REALM}
CONF

exec turnserver -c "$KARST_TURN_GENERATED_CONF" -n "$@"
