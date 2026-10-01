#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright the Karst contributors.
#
# Generates what this deployment (../docker-compose.yml's Caddy + Keycloak
# variant) needs and docker-compose.yml alone cannot invent: the Keycloak
# master admin password it reads from KC_MASTER_ADMIN_PASSWORD, and
# ./state/keycloak-realm.json — the file keycloak-realm.template.json's
# __ORIGIN__/__ADMIN_USERNAME__/__ADMIN_EMAIL__/__ADMIN_PASSWORD__
# placeholders exist to become, substituted for *this* deployment's own
# address and first user rather than shannon's (see plans/phase-6/04-pentest.md
# and GitHub issue #126).
#
# Idempotent, same pattern as ../bootstrap.sh: every generated file is left
# alone if it already exists, so re-running after a partial failure finishes
# the job instead of rotating credentials or the realm's first user under a
# deployment that already has real state.
#
# Run this once, before `docker compose up -d`. It does not start anything
# itself, and it does not run ../bootstrap.sh for you — run that first if
# ../state/ (the relay identity and roster) doesn't exist yet.

set -eu

here=$(cd "$(dirname "$0")" && pwd)
state="$here/state"

# KARST_CONSOLE_ORIGIN is what Keycloak stamps into every issuer/redirect URL
# it generates (KC_HOSTNAME_URL in docker-compose.yml) and what the realm
# template's redirect URIs and web origin are built from — it must be
# exactly what a browser or script types into its address bar, scheme and
# port included, with no trailing slash. It is not necessarily the same
# string as KARST_CONSOLE_HOST (Caddy's own on-demand-TLS matcher), which is
# host-only.
if [ -z "${KARST_CONSOLE_ORIGIN:-}" ]; then
    cat >&2 <<EOF
KARST_CONSOLE_ORIGIN is not set.

It is the externally-visible origin this deployment is reached at, exactly as
a browser would type it — scheme, host or IP, and port, no trailing slash.
Keycloak's issuer and this console's OIDC redirect URIs are both derived from
it, so it must match whatever address you (or an external tester) actually
dial.

    KARST_CONSOLE_ORIGIN=https://203.0.113.7:33073 ./setup.sh
EOF
    exit 1
fi

if [ -z "${KARST_ADMIN_EMAIL:-}" ]; then
    cat >&2 <<EOF
KARST_ADMIN_EMAIL is not set.

It becomes this deployment's first Keycloak user and the account it logs
into: the control plane auto-promotes the first real OIDC login on a
bootstrap-only account to owner (server/management/server/account.go,
accountHasOnlyBootstrapOwner — GitHub issue #85), so whoever owns this email
becomes the deployment's admin on first login. No separate database
workaround is needed for that step any more.

    KARST_ADMIN_EMAIL=admin@example.com ./setup.sh
EOF
    exit 1
fi
admin_username=${KARST_ADMIN_USERNAME:-${KARST_ADMIN_EMAIL%%@*}}

mkdir -p "$state"

# ---------------------------------------------------------------------------
# 1. The Keycloak master admin password.
#
# Read by both this script (to reach Keycloak's admin API from
# pentest_lib.py's admin_token(), which expects it at exactly this path) and
# docker-compose.yml's KEYCLOAK_ADMIN_PASSWORD. Generated once, then left
# alone — rotating it here without also updating a running Keycloak would
# lock this script's own next run out of the admin API.
# ---------------------------------------------------------------------------
kc_admin_pw_file="$state/kc-master-admin-password.txt"
if [ ! -f "$kc_admin_pw_file" ]; then
    echo "setup: generating the Keycloak master admin password"
    (umask 077 && openssl rand -base64 24 > "$kc_admin_pw_file")
else
    echo "setup: keeping the existing Keycloak master admin password"
fi

# ---------------------------------------------------------------------------
# 2. The deployment's first user (this account's eventual owner — see #85
#    above) and its realm/client definition, from keycloak-realm.template.json.
# ---------------------------------------------------------------------------
admin_pw_file="$state/karst-admin-password.txt"
if [ ! -f "$admin_pw_file" ]; then
    echo "setup: generating $KARST_ADMIN_EMAIL's password"
    (umask 077 && openssl rand -base64 18 > "$admin_pw_file")
else
    echo "setup: keeping $KARST_ADMIN_EMAIL's existing password"
fi
admin_password=$(cat "$admin_pw_file")

realm_file="$state/keycloak-realm.json"
if [ ! -f "$realm_file" ]; then
    echo "setup: writing $realm_file for origin $KARST_CONSOLE_ORIGIN"
    sed \
        -e "s#__ORIGIN__#$KARST_CONSOLE_ORIGIN#g" \
        -e "s#__ADMIN_USERNAME__#$admin_username#g" \
        -e "s#__ADMIN_EMAIL__#$KARST_ADMIN_EMAIL#g" \
        -e "s#__ADMIN_PASSWORD__#$admin_password#g" \
        "$here/keycloak-realm.template.json" > "$realm_file"
else
    echo "setup: keeping the existing $realm_file (delete it and re-run to" \
         "pick up a new KARST_CONSOLE_ORIGIN or KARST_ADMIN_EMAIL)"
fi

cat <<EOF

setup: done. Before "docker compose up -d", export:

    export KC_MASTER_ADMIN_PASSWORD="\$(cat $kc_admin_pw_file)"
    export KARST_CONSOLE_ORIGIN="$KARST_CONSOLE_ORIGIN"
    export KARST_CONSOLE_HOST=<host-only part of the above, for Caddy's matcher>
    export KARST_LAN_ADDR=<this host's LAN address, for the karstd control port>

First login (browser or pentest/'s scripts): $KARST_ADMIN_EMAIL /
$(cat "$admin_pw_file")
EOF
