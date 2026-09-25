#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright the Karst contributors.
"""Drive the disposable macOS NE lab's control plane and peer.

Runs on the lab host, next to docker-compose.yml. The Mac never talks to this
directly: /usr/local/libexec/karst-ne-lab on the runner reaches it over SSH
with a forced command (see karst-ne-lab and README.md), so the lab admin's
credentials never leave this host.

    labctl.py init                       one-time: account, group, peer, routes
    labctl.py prepare --scenario direct|relay [--route-churn] [--exit-route]
    labctl.py mutate --route subnet --state add|remove
    labctl.py mutate --route exit --state active|withdrawn
    labctl.py status

`prepare` prints one JSON object on stdout: the fresh invitation and the
non-secret handoff entries. Everything else goes to stderr.
"""
import argparse
import base64
import json
import os
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
STATE = os.path.join(HERE, "state")
PEER_NAME = "lab-peer"
MAC_PREFIX = "lab-mac-"
GROUP = "lab"
SUBNET_ROUTE = ("lab-subnet", "subnet")
EXIT_ROUTE = ("lab-exit", "exit")
FIXTURE_HTTP_PORT = 8080
FIXTURE_UDP_PORT = 7777


def log(*args):
    print("labctl:", *args, file=sys.stderr)


def env():
    values = {}
    with open(os.path.join(HERE, ".env")) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                values[key] = value
    return values


ENV = env()
HOST = ENV["KARST_LAB_HOST_IP"]
# labctl's own admin API calls use the host's published port.
CONTROL = f"http://{HOST}:{ENV['KARST_LAB_CONTROL_PORT']}"
# Invitations name the control plane's core address, which the Mac reaches
# only through labgw (its default gateway), so an active exit route covers
# it (ADR-0036 §2). Labs from before the core network fall back to CONTROL.
CORE_CONTROL_IP = ENV.get("KARST_LAB_CORE_CONTROL_IP")
CORE_RELAY_IP = ENV.get("KARST_LAB_CORE_RELAY_IP")
ENROLL_CONTROL = f"http://{CORE_CONTROL_IP}:33073" if CORE_CONTROL_IP else CONTROL
KEYCLOAK = f"http://{HOST}:{ENV['KARST_LAB_KEYCLOAK_PORT']}/auth/realms/karst"
SUBNET_ADDR = ENV["KARST_LAB_SUBNET_ADDR"]
SUBNET_PREFIX = ENV["KARST_LAB_SUBNET_PREFIX"]
EXIT_ADDR = ENV["KARST_LAB_EXIT_ADDR"]


def token():
    with open(os.path.join(STATE, "lab-admin.json")) as f:
        admin = json.load(f)
    data = urllib.parse.urlencode({
        "grant_type": "password", "client_id": "karst-console",
        "username": admin["username"], "password": admin["password"],
    }).encode()
    with urllib.request.urlopen(KEYCLOAK + "/protocol/openid-connect/token", data, timeout=15) as r:
        return json.load(r)["access_token"]


class Api:
    def __init__(self):
        self.bearer = token()

    def __call__(self, method, path, body=None, headers=None):
        request = urllib.request.Request(
            CONTROL + path, method=method,
            data=None if body is None else json.dumps(body).encode(),
            headers={"Authorization": f"Bearer {self.bearer}", "Content-Type": "application/json", **(headers or {})},
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as r:
                raw = r.read()
        except urllib.error.HTTPError as e:
            # Response bodies can echo request fields; never an invitation, but
            # keep the message short regardless.
            raise SystemExit(f"labctl: {method} {path} -> HTTP {e.code}: {e.read()[:300]!r}")
        return json.loads(raw) if raw else None


def wait_for(what, check, timeout=120):
    deadline = time.monotonic() + timeout
    while True:
        try:
            result = check()
            if result:
                return result
        except (OSError, urllib.error.URLError, SystemExit):
            pass
        if time.monotonic() > deadline:
            raise SystemExit(f"labctl: timed out waiting for {what}")
        time.sleep(2)


def group_id(api):
    for group in api("GET", "/api/groups"):
        if group["name"] == GROUP:
            return group["id"]
    return api("POST", "/api/groups", {"name": GROUP})["id"]


def invitation(api, name):
    """A fresh single-use invitation, encoded exactly as the console does."""
    metadata = api("GET", "/api/karst/v1/me/enrollment")
    grant = api("POST", "/api/karst/v1/invitations", {"name": name, "groups": [group_id(api)]})
    # The relay's self-signed certificate rides in the invitation, so the
    # Mac trusts it for relay TLS only (enrollment writes relay_ca_file)
    # instead of needing it in the system trust store.
    with open(os.path.join(STATE, "tls", "relay.crt")) as f:
        relay_ca = f.read()
    payload = json.dumps({"server": ENROLL_CONTROL, **metadata, "setup_key": grant["credential"], "relay_ca": relay_ca}, separators=(",", ":"))
    encoded = base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")
    return f"karst-invite-v1:{encoded}", metadata, grant


def peers(api):
    return api("GET", "/api/peers")


def lab_peer(api):
    for peer in peers(api):
        if peer["name"] == PEER_NAME:
            return peer
    return None


def route_draft(route, enabled, peer_id, gid):
    network = SUBNET_PREFIX if route is SUBNET_ROUTE else "0.0.0.0/0"
    return {
        "network_id": route[0], "description": f"macOS NE lab {route[1]} route",
        "enabled": enabled, "peer": peer_id, "network": network, "metric": 100,
        "masquerade": True, "groups": [gid], "access_control_groups": [],
        "keep_route": False, "skip_auto_apply": route is EXIT_ROUTE,
    }


def find_route(api, route):
    return next((r for r in api("GET", "/api/routes") if r["network_id"] == route[0]), None)


def peer_running():
    """NetBird's `connected` flag is never set by Karst nodes, so readiness is
    the container being up with a netmap it has fetched."""
    ps = docker("ps", "--status", "running", "--services", check=False).stdout.split()
    cached = docker("exec", "-T", "peer", "test", "-s", "/etc/karst/netmap.cache", check=False)
    return "peer" in ps and cached.returncode == 0


def set_route(api, route, enabled):
    peer, gid = lab_peer(api), group_id(api)
    existing = find_route(api, route)
    draft = route_draft(route, enabled, peer["id"], gid)
    if existing is None:
        api("POST", "/api/routes", draft)
    elif existing["enabled"] != enabled:
        api("PUT", f"/api/routes/{existing['id']}", draft)


def docker(*args, check=True):
    return subprocess.run(["docker", "compose", "--project-directory", HERE, *args],
                          check=check, capture_output=True, text=True)


def set_direct_blocked(blocked):
    docker("exec", "-T", "peer", "iptables", "-F", "LAB-DIRECT")
    if blocked:
        docker("exec", "-T", "peer", "iptables", "-A", "LAB-DIRECT", "-j", "DROP")


def ensure_policy(api):
    """Publish state/policy.json as the account's current policy version.

    With a policy store configured, karst-control compiles node filters from
    the store's current version only; KARST_POLICY_FILE is loaded (and
    logged) but never consulted, so a lab without a published version is
    default deny everywhere even though the file allows everything.
    """
    try:
        current = api("GET", "/api/karst/v1/policy")
    except SystemExit:
        current = None
    with open(os.path.join(STATE, "policy.json")) as f:
        document = f.read()
    version = (current or {}).get("version") or 0
    if version and json.loads(current["document"]) == json.loads(document):
        return version
    published = api("PUT", "/api/karst/v1/policy", {"document": document}, headers={"If-Match": str(version)})
    log(f"published lab policy as version {published.get('version')}")
    return published.get("version")


def cmd_init(_args):
    wait_for("Keycloak", token)
    api = Api()
    gid = group_id(api)
    log(f"group {GROUP}: {gid}")
    log(f"policy version {ensure_policy(api)}")
    config = os.path.join(STATE, "peer", "karstd.toml")
    if not os.path.exists(config):
        _, metadata, grant = invitation(api, PEER_NAME)
        os.makedirs(os.path.dirname(config), mode=0o700, exist_ok=True)
        key = os.path.join(STATE, "peer", "node.key")
        with open(os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as f:
            f.write(secrets.token_hex(64) + "\n")
        text = (
            "[node]\n"
            'listen = "0.0.0.0:51820"\n'
            'interface = "karst0"\n'
            'private_key_file = "/etc/karst/node.key"\n'
            'exit_node_state_file = "/etc/karst/exit-node.json"\n'
            "\n[control]\n"
            f'server = "{CONTROL}"\n'
            f'server_kem_pin = "{metadata["server_kem_pin"]}"\n'
            f'server_verify_pin = "{metadata["server_verify_pin"]}"\n'
            f'control_minimum_version = {metadata["control_minimum_version"]}\n'
            'identity_key_file = "/etc/karst/identity.key"\n'
            'cache_file = "/etc/karst/netmap.cache"\n'
            # bootstrap.sh copies the lab relay's self-signed certificate here.
            'relay_ca_file = "/etc/karst/relay-ca.crt"\n'
            f'setup_key = "{grant["credential"]}"\n'
        )
        with open(os.open(config, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as f:
            f.write(text)
        log("peer configuration written")
    docker("up", "-d", "peer")
    peer = wait_for("the lab peer to enroll", lambda: peer_running() and lab_peer(Api()))
    log(f"peer {PEER_NAME}: {peer['ip']}")
    set_route(api, SUBNET_ROUTE, False)
    set_route(api, EXIT_ROUTE, False)
    log("routes present and withdrawn")


def cmd_prepare(args):
    api = Api()
    # One Mac identity at a time: the invitation name becomes the device's
    # mesh name, so stale ones would collide and pile up.
    for peer in peers(api):
        if peer["name"].startswith(MAC_PREFIX):
            api("DELETE", f"/api/peers/{peer['id']}")
    for grant in api("GET", "/api/karst/v1/invitations"):
        if grant["state"] == "pending":
            api("POST", f"/api/karst/v1/invitations/{grant['id']}/revoke")
    set_route(api, SUBNET_ROUTE, False)
    set_route(api, EXIT_ROUTE, False)
    set_direct_blocked(args.scenario == "relay")
    peer = lab_peer(api)
    if not peer or not peer_running():
        raise SystemExit("labctl: the lab peer is not connected; run `labctl.py init`")
    invite, _, _ = invitation(api, f"{MAC_PREFIX}{int(time.time())}")
    overlay = peer["ip"]
    handoff = {
        "KARST_CI_PROBE_URL": f"http://{overlay}:{FIXTURE_HTTP_PORT}/probe",
        "KARST_CI_UDP_HOST": overlay,
        "KARST_CI_UDP_PORT": str(FIXTURE_UDP_PORT),
    }
    if args.route_churn:
        handoff["KARST_CI_SUBNET_PROBE_URL"] = f"http://{SUBNET_ADDR}:{FIXTURE_HTTP_PORT}/probe"
        handoff["KARST_CI_SUBNET_ROUTE_PREFIX"] = SUBNET_PREFIX
    if args.exit_route:
        # Control and relay at their core addresses, reachable from the Mac
        # only through its default route; each has an HTTP responder sharing
        # its network namespace on :8081, since neither serves an
        # unauthenticated 2xx itself.
        control_host = CORE_CONTROL_IP or HOST
        relay_host = CORE_RELAY_IP or HOST
        handoff["KARST_CI_EXIT_PROBE_URL"] = f"http://{EXIT_ADDR}:{FIXTURE_HTTP_PORT}/probe"
        handoff["KARST_CI_EXIT_ROUTE_PREFIX"] = "0.0.0.0/0"
        handoff["KARST_CI_CONTROL_PLANE_PROBE_URL"] = f"http://{control_host}:8081/"
        handoff["KARST_CI_CONTROL_PLANE_HOST"] = control_host
        handoff["KARST_CI_RELAY_PROBE_URL"] = f"http://{relay_host}:8081/"
        handoff["KARST_CI_RELAY_HOST"] = relay_host
    log(f"prepared scenario={args.scenario} route_churn={args.route_churn} exit_route={args.exit_route}")
    json.dump({"invitation": invite, "handoff": handoff}, sys.stdout)
    print()


def cmd_mutate(args):
    api = Api()
    if args.route == "subnet" and args.state in ("add", "remove"):
        set_route(api, SUBNET_ROUTE, args.state == "add")
    elif args.route == "exit" and args.state in ("active", "withdrawn"):
        set_route(api, EXIT_ROUTE, args.state == "active")
    else:
        raise SystemExit(f"labctl: unsupported mutation {args.route} {args.state}")
    log(f"{args.route} route {args.state}")


def cmd_status(_args):
    api = Api()
    for peer in peers(api):
        print(f"peer  {peer['name']:<24} {peer['ip']}")
    for route in api("GET", "/api/routes"):
        print(f"route {route['network_id']:<24} {route['network']:<16} enabled={route['enabled']}")
    print("lab peer container", "running" if peer_running() else "NOT running")
    rules = docker("exec", "-T", "peer", "iptables", "-S", "LAB-DIRECT", check=False).stdout
    print("direct UDP", "blocked" if "DROP" in rules else "allowed")


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init")
    prepare = sub.add_parser("prepare")
    prepare.add_argument("--scenario", choices=["direct", "relay"], required=True)
    prepare.add_argument("--route-churn", action="store_true")
    prepare.add_argument("--exit-route", action="store_true")
    mutate = sub.add_parser("mutate")
    mutate.add_argument("--route", choices=["subnet", "exit"], required=True)
    mutate.add_argument("--state", required=True)
    sub.add_parser("status")
    args = parser.parse_args()
    {"init": cmd_init, "prepare": cmd_prepare, "mutate": cmd_mutate, "status": cmd_status}[args.command](args)


if __name__ == "__main__":
    main()
