#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright the Karst contributors.
# Exercise the packaged invitation GUI and real OS authorization in a fresh
# disposable desktop. The control fixture uses real wire handlers but a fixture
# account; account authorization/redemption has separate real-store tests.
# Also enroll a real peer and verify permitted TCP traffic across the tunnel.
set -euo pipefail
package=$(realpath "${1:?usage: enrollment-desktop-verify.sh CLIENT.deb TESTSERVER [ARTIFACT_DIR]}")
fixture=$(realpath "${2:?provide the compiled Go testserver}")
artifacts=${3:-/tmp/karst-enrollment-desktop-results}
mkdir -p "$artifacts"
repo=$(cd "$(dirname "$0")/.." && pwd)
relay=$(realpath "${4:-$repo/target/debug/karst-relay}")
image=karst-enrollment-desktop-verify
docker build -q -t "$image" -f "$repo/packaging/test/enrollment.Dockerfile" "$repo/packaging/test"
container=$(docker run -d --privileged --tmpfs /run --tmpfs /run/lock "$image")
peer_container=""
pending_approval=${KARST_ACCEPTANCE_PENDING:-0}
cleanup() {
    result=$?
    docker exec "$container" journalctl -u karstd.service --no-pager > "$artifacts/service.log" 2>&1 || true
    docker exec "$container" cat /tmp/relay.log > "$artifacts/relay.log" 2>&1 || true
    docker exec "$container" /usr/bin/karst status > "$artifacts/status-final.txt" 2>&1 || true
    if [[ -n "$peer_container" ]]; then
        docker exec "$peer_container" journalctl -u karstd.service --no-pager > "$artifacts/peer-service.log" 2>&1 || true
        docker exec "$peer_container" /usr/bin/karst status > "$artifacts/peer-status-final.txt" 2>&1 || true
    fi
    docker rm -f "$container" ${peer_container:+"$peer_container"} >/dev/null 2>&1 || true
    return "$result"
}
trap cleanup EXIT
run() { docker exec "$container" "$@"; }
gui() { docker exec -e DISPLAY=:99 "$container" "$@"; }
wait_for() {
    for _ in $(seq 60); do
        if "$@" >/dev/null 2>&1; then return 0; fi
        sleep 1
    done
    echo "Acceptance timed out waiting for: $*" >&2
    return 1
}
wait_for run bash -c 'state=$(systemctl is-system-running 2>/dev/null || true); [[ "$state" == running || "$state" == degraded ]]'
run mkdir -p /opt/karst-acceptance
docker cp "$package" "$container:/opt/karst-acceptance/client.deb" >/dev/null
docker cp "$fixture" "$container:/opt/karst-acceptance/control-fixture" >/dev/null
run dpkg --install /opt/karst-acceptance/client.deb
run test ! -e /etc/karst/karstd.toml
if run systemctl is-enabled karstd.service >/dev/null 2>&1; then
    echo 'An unconfigured installation enabled the daemon' >&2; exit 1
fi
control_ip=$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$container")
docker cp "$relay" "$container:/opt/karst-acceptance/karst-relay" >/dev/null
# Give both disposable operating systems a test CA, just as a deployment uses
# an already trusted certificate. No TLS-verification bypass is enabled.
docker exec -e KARST_ACCEPTANCE_CONTROL_IP="$control_ip" "$container" bash -c '
cd /opt/karst-acceptance
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=KarstAcceptanceCA -keyout ca.key -out ca.crt >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -subj /CN=KarstAcceptanceRelay -keyout relay.key -out relay.csr >/dev/null 2>&1
printf "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:relay.test,IP:%s\n" "$KARST_ACCEPTANCE_CONTROL_IP" > relay.ext
openssl x509 -req -in relay.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 1 -extfile relay.ext -out relay.crt >/dev/null 2>&1
cp ca.crt /usr/local/share/ca-certificates/karst-acceptance.crt
update-ca-certificates >/dev/null 2>&1
printf "listen = \"0.0.0.0:9443\"\nidentity_key = \"/opt/karst-acceptance/relay.identity\"\nroster = \"/opt/karst-acceptance/roster.toml\"\ntls_cert = \"/opt/karst-acceptance/relay.crt\"\ntls_key = \"/opt/karst-acceptance/relay.key\"\n" > relay.toml
: > roster.toml
/opt/karst-acceptance/karst-relay pubkey --config relay.toml > relay-public.txt
'
relay_pk=$(run python3 -c 'import base64; print(base64.b64decode(open("/opt/karst-acceptance/relay-public.txt").read().split("identity_pk")[1].strip()).hex())')
docker exec -d -e KARST_ACCEPTANCE_CONTROL_IP="$control_ip" -e KARST_ACCEPTANCE_RELAY_PK="$relay_pk" -e KARST_ACCEPTANCE_PENDING="$pending_approval" "$container" bash -c '
extra=(); if [[ "$KARST_ACCEPTANCE_PENDING" == 1 ]]; then extra=(--bedrock 0:enforcing:nocover); fi
/opt/karst-acceptance/control-fixture "${extra[@]}" --control 127.0.0.1:8444 --netmap 0 --listen 0.0.0.0:8443 --relay "$KARST_ACCEPTANCE_CONTROL_IP:9443" "$KARST_ACCEPTANCE_RELAY_PK" --roster /opt/karst-acceptance/roster.toml >/tmp/control.json 2>/tmp/control.log
'
docker exec -d "$container" bash -c '/opt/karst-acceptance/karst-relay --config /opt/karst-acceptance/relay.toml >/tmp/relay.log 2>&1'
wait_for run test -s /tmp/control.json
approve_node() {
    docker exec -i "$container" python3 - "$1" <<'PYAPPROVE'
import json,sys,urllib.request,urllib.parse
nodes=json.load(urllib.request.urlopen("http://127.0.0.1:8444/peers"))
handle=next(node["handle"] for node in nodes if node["ip"]==sys.argv[1])
request=urllib.request.Request("http://127.0.0.1:8444/approve?handle="+urllib.parse.quote(handle,safe=""),method="POST")
assert urllib.request.urlopen(request).status==200
PYAPPROVE
}
# The peer is test infrastructure; the recipient device below uses the GUI.
peer_container=$(docker run -d --privileged --tmpfs /run --tmpfs /run/lock "$image")
peer_run() { docker exec "$peer_container" "$@"; }
wait_for peer_run bash -c 'state=$(systemctl is-system-running 2>/dev/null || true); [[ "$state" == running || "$state" == degraded ]]'
peer_run mkdir -p /opt/karst-acceptance
docker cp "$package" "$peer_container:/opt/karst-acceptance/client.deb" >/dev/null
peer_run dpkg --install /opt/karst-acceptance/client.deb
run cat /opt/karst-acceptance/ca.crt | docker exec -i "$peer_container" bash -c 'cat > /usr/local/share/ca-certificates/karst-acceptance.crt; update-ca-certificates >/dev/null 2>&1'
control_ip=$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$container")
# Encode on the control fixture and stream directly to the installed peer helper.
docker exec -e KARST_ACCEPTANCE_CONTROL_IP="$control_ip" "$container" python3 -c '
import base64,json,os
with open("/tmp/control.json") as f: server=json.loads(f.readline())
payload={"server":"http://"+os.environ["KARST_ACCEPTANCE_CONTROL_IP"]+":8443","server_kem_pin":server["static_kem"],"server_verify_pin":server["verify_key"],"setup_key":"fixture","control_minimum_version":1}
print("karst-invite-v1:"+base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("="),end="")
' | docker exec -i "$peer_container" /usr/bin/karst setup --stdin > "$artifacts/peer-setup.txt"
peer_run systemctl stop karstd.service
if [[ "$pending_approval" == 1 ]]; then approve_node 100.64.0.2; fi
docker exec -d "$container" Xvfb :99 -screen 0 1280x800x24 -ac
wait_for gui xdotool getdisplaygeometry
run systemd-run --unit=karst-desktop-acceptance --property=User=enrollment-test \
    --property=PAMName=login --setenv=DISPLAY=:99 \
    /usr/bin/dbus-run-session -- /bin/bash -c \
    'openbox >/tmp/openbox.log 2>&1 & /usr/lib/policykit-1-gnome/polkit-gnome-authentication-agent-1 >/tmp/auth-agent.log 2>&1 & /usr/bin/karst-setup >/tmp/setup.log 2>&1'
wait_for gui xdotool search --onlyvisible --name 'Karst Setup'
# Put the test invitation on the desktop clipboard. The product does not write
# a credential file, pass it in argv, or require a terminal from the recipient.
gui bash -c 'python3 - <<'"'"'PY'"'"' | xclip -selection clipboard
import base64, json
with open("/tmp/control.json") as source:
    server = json.loads(source.readline())
payload = {"server": "http://127.0.0.1:8443", "server_kem_pin": server["static_kem"], "server_verify_pin": server["verify_key"], "setup_key": "fixture", "control_minimum_version": 1}
print("karst-invite-v1:" + base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("="), end="")
PY
'
gui bash -c 'xdotool search --onlyvisible --name "Karst Setup" windowfocus key ctrl+v; xdotool key Return'
wait_for gui xdotool search --onlyvisible --name Authenticate
# The disposable user's password is defined by enrollment.Dockerfile. Exercise
# the actual polkit authentication agent, without a permissive authorization rule.
gui bash -c 'xdotool search --onlyvisible --name Authenticate windowfocus type --clearmodifiers test-password; xdotool key Return'
wait_for run test -f /etc/karst/karstd.toml
if [[ "$pending_approval" == 1 ]]; then
    wait_for run bash -c '! pgrep -x karst >/dev/null'
    wait_for gui xdotool search --onlyvisible --name 'Karst Setup'
    if run ip link show karst0 >/dev/null 2>&1; then
        echo 'The unapproved device started a tunnel' >&2; exit 1
    fi
    sleep 1
    gui import -window root /tmp/setup-pending.png
    docker cp "$container:/tmp/setup-pending.png" "$artifacts/setup-pending.png" >/dev/null
    approve_node 100.64.0.3
    gui bash -c 'xdotool search --onlyvisible --name "Karst Setup" windowfocus key Return'
    wait_for gui xdotool search --onlyvisible --name Authenticate
    gui bash -c 'xdotool search --onlyvisible --name Authenticate windowfocus type --clearmodifiers test-password; xdotool key Return'
fi
wait_for run systemctl is-active karstd.service
wait_for run bash -c '! pgrep -x karst >/dev/null'
wait_for gui xdotool search --onlyvisible --name 'Karst Setup'
run systemctl is-enabled karstd.service
run /usr/bin/karst status > "$artifacts/status.txt"
run python3 -c 'import pathlib,tomllib; c=tomllib.loads(pathlib.Path("/etc/karst/karstd.toml").read_text()); assert "setup_key" not in c["control"]; assert pathlib.Path("/var/lib/karst/identity.key.enrolled").exists(); assert not pathlib.Path("/var/lib/karst/enrollment.toml").exists()'
# Allow the newly mapped GTK dialog to paint before capturing the artifact.
sleep 1
gui import -window root /tmp/setup-result.png
docker cp "$container:/tmp/setup-result.png" "$artifacts/setup-result.png" >/dev/null
# Start the peer against a netmap that now includes the newly enrolled GUI
# device. Fixture policy permits TCP/22; bind a test HTTP responder there.
peer_run systemctl start karstd.service
wait_for peer_run systemctl is-active karstd.service
peer_run mkdir -p /var/tmp/karst-acceptance-http
peer_run bash -c 'printf "%s" "karst-enrollment-tunnel-passed" > /var/tmp/karst-acceptance-http/proof'
docker exec -d "$peer_container" python3 -m http.server 22 --bind 0.0.0.0 --directory /var/tmp/karst-acceptance-http
wait_for run python3 -c 'import urllib.request; opener=urllib.request.build_opener(urllib.request.ProxyHandler({})); assert opener.open("http://100.64.0.2:22/proof",timeout=2).read()==b"karst-enrollment-tunnel-passed"'
run /usr/bin/karst status > "$artifacts/status-after-traffic.txt"
peer_run /usr/bin/karst status > "$artifacts/peer-status.txt"
# A failed service start must not spend another invitation or change identity.
run sha256sum /var/lib/karst/identity.key > "$artifacts/identity-before.sha256"
run systemctl stop karstd.service
run mkdir -p /etc/systemd/system/karstd.service.d
run bash -c 'printf "[Service]\nExecStart=\nExecStart=/bin/false\n" > /etc/systemd/system/karstd.service.d/acceptance-failure.conf'
run systemctl daemon-reload
if run /usr/bin/karst setup --resume > "$artifacts/failed-start.txt" 2>&1; then
    echo 'Setup incorrectly reported success with a failing service' >&2; exit 1
fi
grep -qi 'no new invitation' "$artifacts/failed-start.txt"
run rm /etc/systemd/system/karstd.service.d/acceptance-failure.conf
run systemctl daemon-reload
run systemctl reset-failed karstd.service
run /usr/bin/karst setup --resume > "$artifacts/recovered-start.txt"
wait_for run python3 -c 'import urllib.request; opener=urllib.request.build_opener(urllib.request.ProxyHandler({})); assert opener.open("http://100.64.0.2:22/proof",timeout=2).read()==b"karst-enrollment-tunnel-passed"'
# Cache loss is not loss of registration. Restart using only the saved identity.
run systemctl stop karstd.service
run rm -f /var/lib/karst/netmap.cache
run /usr/bin/karst setup --resume > "$artifacts/cacheless-restart.txt"
wait_for run python3 -c 'import urllib.request; opener=urllib.request.build_opener(urllib.request.ProxyHandler({})); assert opener.open("http://100.64.0.2:22/proof",timeout=2).read()==b"karst-enrollment-tunnel-passed"'
run sha256sum /var/lib/karst/identity.key > "$artifacts/identity-after.sha256"
cmp "$artifacts/identity-before.sha256" "$artifacts/identity-after.sha256"
run journalctl -u karstd.service --no-pager > "$artifacts/service.log"
run cat /tmp/relay.log > "$artifacts/relay.log"
echo "Packaged invitation entry, OS authorization, provisioning, service startup, permitted tunnel traffic, failed-start recovery, and cacheless restart passed. Review $artifacts/setup-result.png for the displayed readiness result."
