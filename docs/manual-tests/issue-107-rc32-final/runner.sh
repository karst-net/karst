#!/usr/bin/env bash
set -euo pipefail
umask 077
run=/tmp/karst-107-rc32-run3
test ! -e "$run"
mkdir -p "$run/assets" "$run/evidence" "$run/gnupg"
python3 - "$run" <<'PY'
import datetime,json,pathlib,sys,time
pathlib.Path(sys.argv[1],'timing.json').write_text(json.dumps({'release':'v0.1.0-rc.32','start_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'start_monotonic':time.monotonic(),'runner':'Codex autonomous via SSH','prerequisites':'Ubuntu 24.04.3 amd64, sudo, curl, GnuPG, Docker, openssl; host cleaned of Karst services before timing'},indent=2)+'\n')
PY
cd "$run/assets"
base=https://github.com/karst-net/karst/releases/download/v0.1.0-rc.32
for file in SHA256SUMS SHA256SUMS.asc manifest.json karst-web.tar.gz karst-control_0.1.0-0.rc.32_amd64.deb karst-relay_0.1.0-0.rc.32_amd64.deb karst-client-linux_0.1.0-0.rc.32_amd64.deb; do
  curl -fsSL --connect-timeout 10 --max-time 180 "$base/$file" -o "$file"
done
curl -fsSL https://raw.githubusercontent.com/karst-net/karst/v0.1.0-rc.32/docs/release-key.asc -o "$run/release-key.asc"
curl -fsSL https://raw.githubusercontent.com/karst-net/karst/v0.1.0-rc.32/docs/GETTING-STARTED.md -o "$run/GETTING-STARTED.md"
gpg --homedir "$run/gnupg" --batch --import "$run/release-key.asc" >"$run/evidence/key-import.txt" 2>&1
gpg --homedir "$run/gnupg" --batch --status-fd 1 --verify SHA256SUMS.asc SHA256SUMS >"$run/evidence/signature.txt" 2>&1
sha256sum -c --ignore-missing SHA256SUMS | tee "$run/evidence/checksums.txt"
sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y ./*.deb >"$run/evidence/package-install.txt" 2>&1
tar -xzf karst-web.tar.gz -C "$run"
sudo install -d -m 0755 /etc/karst/tls /etc/netbird
sudo install -d -m 0700 /var/lib/karst /var/lib/netbird
sudo openssl req -x509 -newkey rsa:4096 -sha256 -days 7 -nodes -keyout /etc/karst/tls/relay.key -out /etc/karst/tls/relay.crt -subj /CN=192.168.68.101 -addext subjectAltName=IP:192.168.68.101 -addext basicConstraints=critical,CA:FALSE -addext keyUsage=critical,digitalSignature,keyEncipherment -addext extendedKeyUsage=serverAuth >"$run/evidence/relay-cert.txt" 2>&1
sudo chmod 600 /etc/karst/tls/relay.key
sudo tee /etc/karst/relay.toml >/dev/null <<'EOF'
listen = "0.0.0.0:35444"
identity_key = "/etc/karst/relay.key"
roster = "/etc/karst/roster.toml"
tls_cert = "/etc/karst/tls/relay.crt"
tls_key = "/etc/karst/tls/relay.key"
region = "issue107"
[reflect]
listen = "0.0.0.0:35445"
advertise = "192.168.68.101:35445"
[metrics]
listen = "127.0.0.1:35446"
EOF
printf '# Placeholder. karst-control overwrites this every 25s.\n' | sudo tee /etc/karst/roster.toml >/dev/null
sudo /usr/bin/karst-relay check --config /etc/karst/relay.toml | tee "$run/evidence/relay-check.txt"
sudo /usr/bin/karst-relay pubkey --config /etc/karst/relay.toml >"$run/evidence/relay-public.txt"
sudo systemctl enable --now karst-relay
sudo python3 - "$run" <<'PY'
import base64,json,pathlib,secrets,sys
root=pathlib.Path(sys.argv[1]);lines=(root/'evidence/relay-public.txt').read_text().splitlines()
key=next(l.split()[-1] for l in lines if l.strip().startswith('identity_pk'))
pathlib.Path('/etc/karst/relays.json').write_text(json.dumps({'relays':[{'address':'192.168.68.101:35444','tls_server_name':'192.168.68.101','identity_key':key,'region':'issue107'}]}))
pathlib.Path('/etc/karst/policy.json').write_text(json.dumps({'acls':[{'action':'accept','src':['*'],'dst':['*:*']}]}))
config={'Stuns':[],'TURNConfig':{'Turns':[],'CredentialsTTL':'12h','Secret':secrets.token_hex(16),'TimeBasedCredentials':False},'Signal':{'Proto':'http','URI':'localhost:10000'},'Datadir':'/var/lib/netbird','DataStoreEncryptionKey':base64.b64encode(secrets.token_bytes(32)).decode(),'StoreConfig':{'Engine':'sqlite'},'HttpConfig':{'Address':'0.0.0.0:33071','AuthIssuer':'','AuthAudience':'','AuthKeysLocation':''}}
p=pathlib.Path('/etc/netbird/management.json');p.write_text(json.dumps(config,indent=2));p.chmod(0o600)
PY
sudo tee /etc/karst/control.env >/dev/null <<'EOF'
NB_DISABLE_GEOLOCATION=true
KARST_RELAY_ROSTER_FILE=/etc/karst/roster.toml
KARST_RELAY_REGISTRY_FILE=/etc/karst/relays.json
KARST_POLICY_FILE=/etc/karst/policy.json
KARST_BOOTSTRAP_SETUP_KEY_FILE=/var/lib/karst/bootstrap.key
EOF
sudo chmod 600 /etc/karst/control.env
sudo systemctl enable --now karst-control
for i in $(seq 1 30); do sudo test -s /var/lib/karst/bootstrap.key && break; sleep 1; done
invocation=$(systemctl show karst-control --property=InvocationID --value)
sudo journalctl "_SYSTEMD_INVOCATION_ID=$invocation" --no-pager -o cat | grep 'karst: server' >"$run/evidence/control-pins.txt"
cat >"$run/Caddyfile" <<'EOF'
{
  auto_https disable_redirects
  default_sni 192.168.68.101
}
https://192.168.68.101:35443 {
  tls internal
  @grpc path /management.*
  handle @grpc {
    reverse_proxy h2c://127.0.0.1:33073
  }
  @api path /api* /karst*
  handle @api {
    reverse_proxy 127.0.0.1:33073
  }
  handle /auth* {
    reverse_proxy 127.0.0.1:35080
  }
  handle /releases/* {
    uri strip_prefix /releases
    root * /srv/releases
    file_server
  }
  handle /portal/* {
    uri strip_prefix /portal
    root * /srv/portal
    try_files {path} /index.html
    file_server
  }
  handle {
    root * /srv/console
    try_files {path} /index.html
    file_server
  }
}
EOF
# The published web tarball is world-readable inside the test web container.
chmod 755 "$run" "$run/assets"
chmod -R a+rX "$run/karst-web"
chmod 644 "$run/Caddyfile" "$run/assets/manifest.json" "$run/assets/"*.deb
mkdir "$run/caddy-data" "$run/caddy-config"
docker run -d --name karst-107-caddy --label karst.issue=107 --network host -v "$run/Caddyfile:/etc/caddy/Caddyfile:ro" -v "$run/karst-web/console:/srv/console:ro" -v "$run/karst-web/portal:/srv/portal:ro" -v "$run/assets:/srv/releases:ro" -v "$run/caddy-data:/data" -v "$run/caddy-config:/config" caddy:2.10 >"$run/evidence/caddy-id.txt"
for i in $(seq 1 30); do curl -ksf https://192.168.68.101:35443/releases/manifest.json >"$run/evidence/served-manifest.json" && break; sleep 1; done
sudo sh -c 'umask 077; /usr/bin/karstd genkey > /etc/karst/node.key'
sudo python3 - "$run" <<'PY'
import base64,pathlib,re,sys
root=pathlib.Path(sys.argv[1]);pins=(root/'evidence/control-pins.txt').read_text()
kem=base64.b64decode(re.search(r'server KEM pin\s+(\S+)',pins).group(1)).hex()
sig=base64.b64decode(re.search(r'server sign pin\s+(\S+)',pins).group(1)).hex()
setup=pathlib.Path('/var/lib/karst/bootstrap.key').read_text().strip()
p=pathlib.Path('/etc/karst/karstd.toml');p.write_text(f'''[node]
listen = "10.107.0.1:51820"
interface = "karst0"
private_key_file = "/etc/karst/node.key"
[control]
server = "https://192.168.68.101:35443"
server_kem_pin = "{kem}"
server_verify_pin = "{sig}"
identity_key_file = "/etc/karst/identity.key"
setup_key = "{setup}"
cache_file = "/var/lib/karst/netmap.cache"
relay_ca_file = "/etc/karst/tls/relay.crt"
[dns]
enabled = false
''');p.chmod(0o600)
PY
sudo /usr/bin/karstd check --config /etc/karst/karstd.toml | tee "$run/evidence/node-check.txt"
sudo systemctl enable --now karstd
for i in $(seq 1 45); do
  sudo /usr/bin/karst status >"$run/evidence/first-node-status.txt" 2>/dev/null || true
  if grep -q 'control_synchronized = true' "$run/evidence/first-node-status.txt"; then
    python3 - "$run" <<'PY'
import datetime,json,pathlib,sys,time
p=pathlib.Path(sys.argv[1],'timing.json');x=json.loads(p.read_text());x['first_node_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat();x['first_node_elapsed_seconds']=round(time.monotonic()-x['start_monotonic'],3);x['within_30_minutes']=x['first_node_elapsed_seconds']<=1800;p.write_text(json.dumps(x,indent=2)+'\n');print(json.dumps(x))
PY
    cat "$run/evidence/first-node-status.txt"
    break
  fi
  sleep 1
done
if ! grep -q 'control_synchronized = true' "$run/evidence/first-node-status.txt"; then
 echo 'First-node synchronization not observed' >&2
 exit 1
fi

#!/usr/bin/env bash
set -euo pipefail
run=/tmp/karst-107-rc32-run3
sudo install -d -m 0700 /var/lib/karst-107-peer2 /run/karst-107-peer2
sudo sh -c 'umask 077; /usr/bin/karstd genkey > /var/lib/karst-107-peer2/node.key'
sudo python3 - <<'PY'
from pathlib import Path
s=Path('/etc/karst/karstd.toml').read_text().replace('listen = "10.107.0.1:51820"','listen = "10.107.0.2:51820"').replace('/etc/karst/node.key','/var/lib/karst-107-peer2/node.key').replace('/etc/karst/identity.key','/var/lib/karst-107-peer2/identity.key').replace('/var/lib/karst/netmap.cache','/var/lib/karst-107-peer2/netmap.cache')
p=Path('/var/lib/karst-107-peer2/karstd.toml');p.write_text(s);p.chmod(0o600)
PY
sudo systemd-run --unit=karst-107-peer2 --property=NetworkNamespacePath=/run/netns/karst107b /usr/bin/karstd --config /var/lib/karst-107-peer2/karstd.toml --socket /run/karst-107-peer2/karstd.sock
for i in $(seq 1 30); do
 sudo /usr/bin/karst status --json --socket /run/karst-107-peer2/karstd.sock >"$run/evidence/second-node-status.json" 2>/dev/null || true
 if python3 - "$run/evidence/second-node-status.json" <<'PY'
import json,sys
try:
 x=json.load(open(sys.argv[1]));sys.exit(0 if x['control']['control_synchronized'] and x['peers'] else 1)
except Exception:sys.exit(1)
PY
 then break; fi
 sleep 1
done
sudo /usr/bin/karst status --json >"$run/evidence/host-node-status.json"
peer=$(python3 -c 'import json;print(json.load(open("/tmp/karst-107-rc32-run3/evidence/second-node-status.json"))["addresses"][0].split("/")[0])')
network=$(sudo /usr/bin/karst status --json | python3 -c 'import ipaddress,json,sys;print(ipaddress.ip_network(json.load(sys.stdin)["addresses"][0],strict=False))')
sudo iptables -I INPUT 1 -i karst0 -s "$network" -m comment --comment karst107 -j ACCEPT
host=$(sudo /usr/bin/karst status --json | python3 -c 'import json,sys;print(json.load(sys.stdin)["addresses"][0].split("/")[0])')
for i in $(seq 1 30); do sudo ip netns exec karst107b ping -c 1 -W 1 "$host" >/dev/null && break; sleep 1; done
sudo ip netns exec karst107b ping -c 4 -W 2 "$host" | tee "$run/evidence/overlay-ping-peer2.txt"
sudo ping -I karst0 -c 4 -W 2 "$peer" | tee "$run/evidence/overlay-ping.txt"
sudo /usr/bin/karst status --json >"$run/evidence/host-node-status.json"
sudo /usr/bin/karst status --json --socket /run/karst-107-peer2/karstd.sock >"$run/evidence/second-node-status.json"
python3 - "$run" <<'PY'
import datetime,json,pathlib,sys,time
p=pathlib.Path(sys.argv[1],'timing.json');x=json.loads(p.read_text());x['first_peer_traffic_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat();x['first_peer_traffic_elapsed_seconds']=round(time.monotonic()-x['start_monotonic'],3);p.write_text(json.dumps(x,indent=2)+'\n');print(json.dumps(x))
PY
