#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright the Karst contributors.
#
# Stand up (or refresh) the macOS NE lab's Linux half on this host. Idempotent:
# existing state is kept, so a re-run after a reboot or an image rebuild
# keeps the same pins, relay identity, account and enrolled peer.
#
#   KARST_LAB_HOST_IP=192.168.68.101 \
#   KARST_LAB_PEER_LAN_IP=192.168.71.200 \
#   KARST_LAB_TAG=34573ec \
#     ./bootstrap.sh
#
# The images karst-ne-lab/{karst-control,karst-relay,karstd}:$KARST_LAB_TAG
# must already exist (README.md shows the build). `./bootstrap.sh --reset`
# discards all state first, which invalidates every enrolled Mac.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
cd "$here"
state="$here/state"

if [ "${1:-}" = "--reset" ]; then
    docker compose down --remove-orphans 2>/dev/null || true
    sudo rm -rf "$state" .env
fi

: "${KARST_LAB_HOST_IP:?the host LAN address the Mac dials, e.g. 192.168.68.101}"
: "${KARST_LAB_PEER_LAN_IP:?a free, static LAN address for the lab peer}"
: "${KARST_LAB_TAG:?the image tag to run}"
parent=${KARST_LAB_LAN_PARENT:-$(ip -o -4 addr show | awk -v a="$KARST_LAB_HOST_IP" 'index($4, a"/") == 1 { print $2; exit }')}
lan_subnet=${KARST_LAB_LAN_SUBNET:-$(ip -o -4 route show dev "$parent" proto kernel | awk '{ print $1; exit }')}
lan_gateway=${KARST_LAB_LAN_GATEWAY:-$(ip -o -4 route show default dev "$parent" | awk '{ print $3; exit }')}

mkdir -p "$state/tls" "$state/netbird" "$state/peer"
chmod 700 "$state/peer"

if [ ! -f .env ]; then
    umask 077
    cat > .env <<EOF
KARST_LAB_TAG=$KARST_LAB_TAG
KARST_LAB_HOST_IP=$KARST_LAB_HOST_IP
KARST_LAB_CONTROL_PORT=${KARST_LAB_CONTROL_PORT:-34073}
KARST_LAB_KEYCLOAK_PORT=${KARST_LAB_KEYCLOAK_PORT:-34080}
KARST_LAB_RELAY_PORT=${KARST_LAB_RELAY_PORT:-34443}
KARST_LAB_PEER_LAN_IP=$KARST_LAB_PEER_LAN_IP
KARST_LAB_LAN_PARENT=$parent
KARST_LAB_LAN_SUBNET=$lan_subnet
KARST_LAB_LAN_GATEWAY=$lan_gateway
KARST_LAB_SUBNET_PREFIX=10.203.0.0/24
KARST_LAB_SUBNET_ADDR=10.203.0.1
KARST_LAB_EXIT_ADDR=198.18.0.1
KARST_LAB_KC_MASTER_PASSWORD=$(openssl rand -hex 16)
EOF
    umask 022
else
    sed -i "s/^KARST_LAB_TAG=.*/KARST_LAB_TAG=$KARST_LAB_TAG/" .env
fi
set -a
# shellcheck disable=SC1091
. ./.env
set +a

if [ ! -f "$state/tls/relay.crt" ]; then
    openssl req -x509 -newkey rsa:4096 -sha256 -days 825 -nodes \
        -keyout "$state/tls/relay.key" -out "$state/tls/relay.crt" \
        -subj "/CN=relay.karst-ne-lab" \
        -addext "subjectAltName=DNS:relay.karst-ne-lab,IP:$KARST_LAB_HOST_IP" \
        -addext "basicConstraints=critical,CA:FALSE" \
        -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
        -addext "extendedKeyUsage=serverAuth" >/dev/null 2>&1
    chmod 600 "$state/tls/relay.key"
fi
cp "$state/tls/relay.crt" "$state/peer/relay-ca.crt"
[ -f "$state/relay.toml" ] || cat > "$state/relay.toml" <<EOF
listen = "0.0.0.0:443"
identity_key = "/var/lib/karst/relay.key"
roster = "/var/lib/karst/roster.toml"
tls_cert = "/var/lib/karst/tls/relay.crt"
tls_key = "/var/lib/karst/tls/relay.key"
region = "lab"
EOF
[ -f "$state/roster.toml" ] || printf '# karst-control overwrites this every 25s.\n' > "$state/roster.toml"
if [ ! -f "$state/relays.json" ]; then
    identity=$(docker run --rm -v "$state:/var/lib/karst" "karst-ne-lab/karst-relay:$KARST_LAB_TAG" \
        pubkey --config /var/lib/karst/relay.toml | awk '/^identity_pk/ { print $2 }')
    [ -n "$identity" ] || { echo "bootstrap: karst-relay printed no identity" >&2; exit 1; }
    cat > "$state/relays.json" <<EOF
{ "relays": [ { "address": "$KARST_LAB_HOST_IP:$KARST_LAB_RELAY_PORT", "tls_server_name": "relay.karst-ne-lab", "identity_key": "$identity", "region": "lab" } ] }
EOF
fi
# "*:*" covers mesh nodes only; routed destinations need CIDR grants. The
# subnet-route fixture and the exit probe (198.18.0.1) are both reachable
# only through route offers, so the lab grants their networks explicitly.
cat > "$state/policy.json" <<EOF
{ "acls": [ { "action": "accept", "src": ["*"], "dst": ["*:*", "$KARST_LAB_SUBNET_PREFIX:*", "198.18.0.0/24:*"] } ] }
EOF
if [ ! -f "$state/management.json" ]; then
    umask 077
    cat > "$state/management.json" <<EOF
{
  "Stuns": [],
  "TURNConfig": { "Turns": [], "CredentialsTTL": "12h", "Secret": "$(openssl rand -hex 16)", "TimeBasedCredentials": false },
  "Signal": { "Proto": "http", "URI": "localhost:10000" },
  "Datadir": "/var/lib/netbird",
  "DataStoreEncryptionKey": "$(openssl rand -base64 32)",
  "StoreConfig": { "Engine": "sqlite" },
  "HttpConfig": {
    "Address": "0.0.0.0:33071",
    "AuthIssuer": "http://$KARST_LAB_HOST_IP:$KARST_LAB_KEYCLOAK_PORT/auth/realms/karst",
    "AuthAudience": "karst-console",
    "AuthKeysLocation": "http://keycloak:8080/auth/realms/karst/protocol/openid-connect/certs",
    "IdpSignKeyRefreshEnabled": true
  }
}
EOF
    umask 022
fi
if [ ! -f "$state/lab-admin.json" ]; then
    umask 077
    password=$(openssl rand -hex 20)
    printf '{"username": "lab-admin", "password": "%s"}\n' "$password" > "$state/lab-admin.json"
    # A password-grant client: labctl.py is the only thing that ever logs in.
    python3 - "$password" > "$state/keycloak-realm.json" <<'EOF'
import json, sys
print(json.dumps({
    "realm": "karst", "enabled": True, "sslRequired": "none",
    "clients": [{
        "clientId": "karst-console", "publicClient": True, "protocol": "openid-connect",
        "standardFlowEnabled": False, "directAccessGrantsEnabled": True,
        "protocolMappers": [{
            "name": "karst-console-audience", "protocol": "openid-connect",
            "protocolMapper": "oidc-audience-mapper", "consentRequired": False,
            "config": {"included.client.audience": "karst-console",
                       "id.token.claim": "false", "access.token.claim": "true"},
        }],
    }],
    "users": [{
        "username": "lab-admin", "email": "lab-admin@karst-ne-lab.invalid",
        "firstName": "Lab", "lastName": "Admin", "enabled": True, "emailVerified": True,
        "credentials": [{"type": "password", "value": sys.argv[1], "temporary": False}],
    }],
}, indent=1))
EOF
    chmod 644 "$state/keycloak-realm.json"   # read by the keycloak container's uid
    umask 022
fi

docker compose build peer
docker compose up -d control relay keycloak
python3 "$here/labctl.py" init
python3 "$here/labctl.py" status
