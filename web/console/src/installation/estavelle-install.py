#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright the Karst contributors.
"""Console-generated handoff for one co-located reference Compose estavelle.

Python 3.11+, Docker Compose v2 and OpenSSL are required on the control host.
This program contains public settings only. It never calls the admin API.
"""

import argparse
import base64
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

SETTINGS = None  # Replaced by the console; no credentials are embedded.


class Invalid(ValueError):
    pass


def validate(settings):
    if not isinstance(settings, dict) or set(settings) != {"schema_version", "address", "tls_server_name", "region", "image", "control_image", "location"} or type(settings["schema_version"]) is not int or settings["schema_version"] != 1:
        raise Invalid("unsupported installation settings")
    address = settings["address"]
    if not isinstance(address, str):
        raise Invalid("an IP address and port are required")
    host, sep, port = address.rpartition(":")
    if not sep or not port.isascii() or not port.isdecimal() or not 1 <= int(port) <= 65535:
        raise Invalid("port must be between 1 and 65535")
    ip = ipaddress.ip_address(host[1:-1] if host.startswith("[") and host.endswith("]") else host)
    if ip.version == 6 and not host.startswith("["):
        raise Invalid("IPv6 addresses require brackets")
    name = settings["tls_server_name"]
    if not isinstance(name, str) or len(name) > 253 or not all(re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?", label) for label in name.split(".")):
        raise Invalid("a valid TLS DNS server name is required")
    if not isinstance(settings["region"], str) or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}", settings["region"]):
        raise Invalid("region must use 1-64 letters, digits, underscores or hyphens")
    if not isinstance(settings["image"], str) or not re.fullmatch(r"ghcr\.io/karst-net/karst-estavelle(?::[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,127}|@sha256:[a-f0-9]{64})", settings["image"]):
        raise Invalid("choose a Karst estavelle image tag or sha256 digest")
    if not isinstance(settings["control_image"], str) or not re.fullmatch(r"ghcr\.io/karst-net/karst-control(?::[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,127}|@sha256:[a-f0-9]{64})", settings["control_image"]):
        raise Invalid("choose a Karst control image tag or sha256 digest")
    location = settings["location"]
    if location is not None and (not isinstance(location, dict) or set(location) - {"lat", "lon", "label"} or type(location.get("lat")) not in (float, int) or type(location.get("lon")) not in (float, int) or not -90 <= location["lat"] <= 90 or not -180 <= location["lon"] <= 180 or not isinstance(location.get("label", ""), str)):
        raise Invalid("invalid declared location")
    return int(port)


def run(args, capture=False):
    return subprocess.run(args, check=True, text=True, capture_output=capture, timeout=180, stdin=subprocess.DEVNULL)


def compose(directory, *args):
    return ["docker", "compose", "--project-directory", str(directory), "-f", str(directory / "docker-compose.yml"), *args]


def parse_rows(source):
    source = source.strip()
    return json.loads(source) if source.startswith("[") else [json.loads(line) for line in source.splitlines() if line]


def inspect(directory, settings):
    validate(settings)
    config = json.loads(run(compose(directory, "config", "--format", "json"), capture=True).stdout)
    control = config.get("services", {}).get("control")
    if not control or control.get("entrypoint"):
        raise Invalid("the directory must contain the existing reference Compose control service")
    state = directory / "state"
    mounts = [v for v in control.get("volumes", []) if v.get("target") == "/var/lib/karst"]
    if len(mounts) != 1 or mounts[0].get("type") != "bind" or Path(mounts[0]["source"]).resolve() != state.resolve() or mounts[0].get("read_only", False):
        raise Invalid("control must share this directory's writable state at /var/lib/karst")
    if control.get("scale", 1) != 1 or control.get("deploy", {}).get("replicas", 1) != 1:
        raise Invalid("this handoff supports one control replica only")
    environment = control.get("environment", {})
    if environment.get("KARST_ESTAVELLE_ROSTER_FILE") not in (None, "", "/var/lib/karst/roster.toml"):
        raise Invalid("another roster writer is configured; this handoff supports one local estavelle only")
    if environment.get("KARST_ESTAVELLE_ROSTER_ID"):
        raise Invalid("a fixed roster identity is configured; use the identity-file reference deployment")
    if environment.get("KARST_ESTAVELLE_ROSTER_ID_FILE") not in (None, "", "/var/lib/karst/estavelle-roster.id"):
        raise Invalid("another roster identity file is configured")
    # Reuse the deployment's existing trusted TLS material. Rotating it would
    # require a separate trust rollout to already enrolled clients.
    for name in ("tls/estavelle.crt", "tls/estavelle.key"):
        if not (state / name).is_file() or not (state / name).stat().st_size:
            raise Invalid("existing estavelle TLS certificate and key are required; initialize reference deployment trust first")
    try:
        # x509 -checkhost reports mismatches with exit status 0 on OpenSSL 3.
        # verify enforces hostname, validity and server purpose with a failing
        # status. Treat the existing leaf as locally trusted for this check;
        # this does not install a new trust anchor on clients.
        run(["openssl", "verify", "-trusted", str(state / "tls/estavelle.crt"), "-partial_chain", "-purpose", "sslserver", "-verify_hostname", settings["tls_server_name"], str(state / "tls/estavelle.crt")], capture=True)
    except subprocess.CalledProcessError:
        raise Invalid("existing estavelle certificate must be valid for the selected TLS server name") from None
    cert_key = run(["openssl", "x509", "-in", str(state / "tls/estavelle.crt"), "-pubkey", "-noout"], capture=True).stdout
    private_key = run(["openssl", "pkey", "-in", str(state / "tls/estavelle.key"), "-pubout"], capture=True).stdout
    if cert_key != private_key:
        raise Invalid("estavelle TLS certificate does not match its private key")
    # A Compose project name may also exist in another directory. Verify the
    # actual control container before any stop/up command can affect it.
    rows = parse_rows(run(compose(directory, "ps", "--all", "--format", "json"), capture=True).stdout)
    controls = [row for row in rows if row.get("Service") == "control"]
    if len(controls) != 1 or not controls[0].get("ID"):
        raise Invalid("one existing reference control container is required")
    labels = json.loads(run(["docker", "inspect", controls[0]["ID"], "--format", "{{json .Config.Labels}}"], capture=True).stdout)
    if not isinstance(labels, dict) or Path(labels.get("com.docker.compose.project.working_dir", "")).resolve() != directory:
        raise Invalid("the Compose project belongs to another directory; refusing to change it")
    if not control.get("image"):
        raise Invalid("control must use an explicit image supporting managed-roster-v1")
    capability = run(["docker", "run", "--rm", "--network", "none", "--read-only", "--entrypoint", "/usr/local/bin/karst-control", settings["control_image"], "--estavelle-installation-capabilities"], capture=True).stdout.strip()
    if capability != "managed-roster-v1":
        raise Invalid("upgrade control to an image supporting managed-roster-v1 before installation")
    return state


def atomic(path, data):
    fd, temporary = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, "w") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def overlay(state, settings):
    port = validate(settings)
    return {"services": {
        "control": {"image": settings["control_image"], "environment": {"KARST_ESTAVELLE_ROSTER_FILE": "/var/lib/karst/roster.toml", "KARST_ESTAVELLE_ROSTER_ID_FILE": "/var/lib/karst/estavelle-roster.id", "KARST_ESTAVELLE_REQUIRE_MANAGED": "true", "KARST_ESTAVELLE_ROSTER_INTERVAL": "25s"}},
        "estavelle": {"image": settings["image"], "restart": "unless-stopped", "command": ["--config", "/var/lib/karst/estavelle-install/estavelle.toml"], "volumes": [{"type": "bind", "source": str(state), "target": "/var/lib/karst"}],
                  # !override is unavailable in JSON. Apply validates that the
                  # merged ports contain only this binding before any restart.
                  "ports": [{"target": 443, "published": str(port), "protocol": "tcp"}]}}}


def check_merged(config, state, settings):
    estavelle = config["services"]["estavelle"]
    ports = estavelle.get("ports", [])
    if len(ports) != 1 or ports[0].get("target") != 443 or str(ports[0].get("published")) != str(validate(settings)) or ports[0].get("protocol", "tcp") != "tcp":
        raise Invalid("existing estavelle port bindings differ; choose the existing reference estavelle port")
    mounts = estavelle.get("volumes", [])
    if len(mounts) != 1 or mounts[0].get("target") != "/var/lib/karst" or Path(mounts[0].get("source", "")).resolve() != state.resolve() or mounts[0].get("read_only", False):
        raise Invalid("existing estavelle mounts differ from the reference deployment")
    if estavelle.get("entrypoint") or estavelle.get("privileged") or estavelle.get("network_mode") or estavelle.get("cap_add"):
        raise Invalid("custom estavelle execution settings are not supported by this handoff")


def apply(directory, settings):
    state = inspect(directory, settings)
    install = state / "estavelle-install"
    install.mkdir(mode=0o700, exist_ok=True)
    # Serialize installation attempts on this host. The control writer keeps
    # its own atomic roster replacement; it never takes this installer lock.
    with (install / "lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        applied = install / "settings.json"
        encoded = json.dumps(settings, sort_keys=True)
        if applied.exists() and applied.read_text() != encoded:
            raise Invalid("this host has another installation handoff; reuse its settings to retry")
        overlay_path = install / "compose.json"
        atomic(overlay_path, json.dumps(overlay(state, settings)))
        command = compose(directory, "-f", str(overlay_path))
        merged = json.loads(run([*command, "config", "--format", "json"], capture=True).stdout)
        check_merged(merged, state, settings)
        # Fail before changing the writer if the existing registry names a
        # different endpoint. This is installation/adoption, not silent migration.
        registry = state / "estavelles.json"
        if registry.exists():
            registry_value = json.loads(registry.read_text())
            entries = registry_value.get("relays", []) if isinstance(registry_value, dict) else []
            if not isinstance(entries, list) or len(entries) != 1 or not isinstance(entries[0], dict) or any(entries[0].get(k) != settings[k] for k in ("address", "tls_server_name", "region")):
                raise Invalid("existing estavelle registry differs; use its address, TLS name and region")
        atomic(applied, encoded)
        status = install / "status.json"
        (install / "receipt.json").unlink(missing_ok=True)
        atomic(status, json.dumps({"state": "preparing", "ready": False}))
        try:
            config_path = install / "estavelle.toml"
            atomic(config_path, 'listen = "0.0.0.0:443"\nidentity_key = "/var/lib/karst/estavelle.key"\nroster = "/var/lib/karst/roster.toml"\ntls_cert = "/var/lib/karst/tls/estavelle.crt"\ntls_key = "/var/lib/karst/tls/estavelle.key"\nregion = ' + json.dumps(settings["region"]) + '\n')
            identity_output = run(["docker", "run", "--rm", "-v", f"{state}:/var/lib/karst", settings["image"], "pubkey", "--config", "/var/lib/karst/estavelle-install/estavelle.toml"], capture=True).stdout
            fields = dict(line.split(None, 1) for line in identity_output.splitlines() if line.strip())
            public = base64.b64decode(fields["identity_pk"], validate=True)
            if len(public) != 2592 or hashlib.sha256(b"karst-estavelle-id-v1" + public).hexdigest() != fields["relay_id"]:
                raise Invalid("estavelle image returned an invalid public identity")
            if registry.exists() and entries[0].get("identity_key") != fields["identity_pk"]:
                raise Invalid("existing registry and local estavelle identity do not match")
            # Stop the old writer before clearing its file: otherwise it could
            # race a final unrestricted roster into the strict installation.
            run([*command, "stop", "estavelle", "control"], capture=True)
            atomic(state / "roster.toml", "# Awaiting form-managed access; default deny.\n")
            atomic(state / "estavelle-roster.id", fields["relay_id"] + "\n")
            atomic(status, json.dumps({"state": "starting", "ready": False}))
            run([*command, "up", "-d", "--no-deps", "control", "estavelle"], capture=True)
            rows = run([*command, "ps", "--all", "--format", "json"], capture=True).stdout.strip()
            rows = parse_rows(rows)
            if any(not any(row.get("Service") == service and row.get("State") == "running" for row in rows) for service in ("control", "estavelle")):
                raise Invalid("control or estavelle is not running; inspect Docker diagnostics and retry")
            receipt = {"schema_version": 1, "kind": "karst-estavelle-installation", "entry": {k: settings[k] for k in ("address", "tls_server_name", "region", "location")}, "relay_id": fields["relay_id"]}
            receipt["entry"]["identity_key"] = fields["identity_pk"]
            atomic(install / "receipt.json", json.dumps(receipt, indent=2))
            atomic(status, json.dumps({"state": "runtime_started", "ready": False}))
        except Exception:
            atomic(status, json.dumps({"state": "failed", "ready": False, "retry": "rerun the same installer; inspect local Docker diagnostics"}))
            raise
    print("Runtime started; access is NOT configured and readiness is NOT proven.")
    print(f"Import {install / 'receipt.json'} in Estavelles, then review group access and optional egress.")
    print("Keep using the generated Compose overlay for future control/estavelle lifecycle operations.")
    print("Do not remove KARST_ESTAVELLE_REQUIRE_MANAGED or downgrade the control image.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True, help="existing reference Compose directory on this Linux host")
    parser.add_argument("--apply", action="store_true", help="restart control and estavelle; legacy unconfigured estavelle access will be denied")
    args = parser.parse_args()
    try:
        directory = args.directory.resolve()
        if args.apply:
            apply(directory, SETTINGS)
        else:
            inspect(directory, SETTINGS)
            print("Plan: reuse local keys/trusted TLS; generate estavelle config and strict identity-bound writer overlay; restart control and estavelle. No access grants or cloud resources created. Use --apply to proceed.")
    except (Invalid, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        # Do not print subprocess output, config, or exception values: the
        # inherited control environment and Docker diagnostics may hold secrets.
        if isinstance(error, Invalid):
            print(str(error), file=sys.stderr)
        print("Installation failed; no automatic rollback. Earlier actions may have completed. Inspect state/estavelle-install/status.json and local Docker diagnostics, then retry the same installer.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
