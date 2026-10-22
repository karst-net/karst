#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright the Karst contributors.
"""Manage the reference Compose Relay's Ponor and optional TURN processes.

Python 3.11+. Existing bootstrap material is reused, never regenerated. This
local process adapter does not change control's account publication authority.
"""

import argparse
import hmac
import json
import os
from pathlib import Path
import shlex
import stat
import subprocess
import sys
import tempfile
import tomllib


class Invalid(ValueError):
    pass


def manifest(path, source=None):
    value = tomllib.loads((source if source is not None else path.read_bytes()).decode())
    if set(value) != {"schema_version", "ponor", "turn"} or type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise Invalid("manifest requires schema_version = 1, [ponor] and [turn] only")
    if not isinstance(value["ponor"], dict) or set(value["ponor"]) != {"enabled"} or type(value["ponor"]["enabled"]) is not bool:
        raise Invalid("ponor requires an explicit enabled boolean")
    turn = value["turn"]
    if not isinstance(turn, dict) or set(turn) != {"enabled", "backend"} or type(turn["enabled"]) is not bool:
        raise Invalid("turn requires explicit enabled and backend fields")
    if turn["backend"] not in ("none", "coturn-companion", "external") or (turn["enabled"] and turn["backend"] == "none"):
        raise Invalid("enabled TURN requires coturn-companion or external backend")
    return value


def require_file(path):
    if not path.is_file() or path.stat().st_size == 0:
        raise Invalid(f"missing or empty {path.name}; run bootstrap first")


def validate_material(directory, desired):
    state = directory / "state"
    if desired["ponor"]["enabled"]:
        for name in ("relay.toml", "relay.key", "relays.json", "roster.toml", "tls/relay.crt", "tls/relay.key"):
            require_file(state / name)
    if not desired["turn"]["enabled"]:
        return
    for name in ("turns.json", "turn-secret"):
        require_file(state / name)
    secret_path = state / "turn-secret"
    if stat.S_IMODE(secret_path.stat().st_mode) & 0o077:
        raise Invalid("turn-secret must not be accessible by group or others")
    secret = secret_path.read_text().strip()
    if not secret or "\n" in secret or "\r" in secret:
        raise Invalid("turn-secret must contain one nonempty secret")
    registry = json.loads((state / "turns.json").read_text())
    entries = registry.get("turn", []) if isinstance(registry, dict) else []
    if not isinstance(entries, list) or not entries or not all(isinstance(item, dict) and isinstance(item.get("uri"), str) and item["uri"].startswith(("turn:", "turns:")) for item in entries):
        raise Invalid("turns.json must contain registered TURN URIs")
    # File paths must already reach control through its existing Compose env.
    env = {}
    if (directory / ".env").is_file():
        for line in (directory / ".env").read_text().splitlines():
            key, sep, value = line.partition("=")
            if sep:
                env[key.strip()] = value.strip()
    env.update(os.environ)
    for key, expected in (("KARST_TURN_REGISTRY_FILE", "/var/lib/karst/turns.json"), ("KARST_TURN_SHARED_SECRET_FILE", "/var/lib/karst/turn-secret")):
        if env.get(key) != expected:
            raise Invalid(f"{key} must select the bootstrap file; run bootstrap.sh --turn")
    if desired["turn"]["backend"] == "external":
        return
    require_file(state / "turnserver.conf")
    settings = []
    for line in (state / "turnserver.conf").read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            settings.append(line)
    secrets = [line.split("=", 1)[1] for line in settings if line.startswith("static-auth-secret=")]
    if len(secrets) != 1 or not hmac.compare_digest(secrets[0].encode(), secret.encode()) or "use-auth-secret" not in settings or any(line.split("=", 1)[0] in ("no-auth", "user", "include") for line in settings):
        raise Invalid("coturn must use the matching TURN-REST secret without conflicting authentication/includes")


def operations(desired):
    # Start before stopping, so a healthy independent mode is left available.
    enabled = []
    disabled = []
    for service, on in (("relay", desired["ponor"]["enabled"]), ("coturn", desired["turn"]["enabled"] and desired["turn"]["backend"] == "coturn-companion")):
        (enabled if on else disabled).append(service)
    return ([ ["up", "-d", "--no-deps", *enabled] ] if enabled else []) + ([ ["stop", *disabled] ] if disabled else [])


def compose_command(directory, args):
    # Explicit project file/directory: current working directory cannot select
    # another stack. Docker's normal environment/.env image and port settings
    # are retained. Never print resolved configuration or container env values.
    return ["docker", "compose", "--project-directory", str(directory), "-f", str(directory / "docker-compose.yml"), "--profile", "turn", *args]


def compose(directory, args, capture=False):
    return subprocess.run(compose_command(directory, args), check=True, text=True, capture_output=capture)


def save_applied(directory, source):
    target = directory / "state" / "relay-service.applied.toml"
    target.parent.mkdir(exist_ok=True)
    if target.exists():
        atomic_write(target.with_suffix(".toml.previous"), target.read_bytes())
    atomic_write(target, source)


def atomic_write(path, contents):
    descriptor, temporary = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(contents)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def status(directory, desired):
    raw = compose(directory, ["ps", "--all", "--format", "json"], capture=True).stdout.strip()
    rows = json.loads(raw) if raw.startswith("[") else [json.loads(line) for line in raw.splitlines() if line]
    states = {row["Service"]: {"state": row.get("State", "unknown"), "health": row.get("Health") or "unprobed"} for row in rows}
    return {"ponor": {"enabled": desired["ponor"]["enabled"], **states.get("relay", {"state": "absent", "health": "unprobed"})},
            "turn": {**desired["turn"], "companion": states.get("coturn", {"state": "absent", "health": "unprobed"}), **(states.get("coturn", {"state": "absent", "health": "unprobed"}) if desired["turn"]["backend"] == "coturn-companion" else {"state": "external" if desired["turn"]["backend"] == "external" else "unmanaged", "health": "unprobed"})},
            "readiness": "Use control Relay Services observations for admission/allocation readiness; container state alone is not readiness."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("plan", "apply", "status"))
    parser.add_argument("--directory", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--manifest", type=Path, help="defaults to relay-service.toml in the Compose directory")
    parser.add_argument("--acknowledge-process-change", action="store_true", help="apply can interrupt active allocations and connections")
    args = parser.parse_args()
    directory = args.directory.resolve()
    path = args.manifest or directory / "relay-service.toml"
    try:
        source = path.read_bytes()
        desired = manifest(path, source)
        if args.command == "status":
            print(json.dumps(status(directory, desired), indent=2))
            return
        validate_material(directory, desired)
        commands = operations(desired)
        if args.command == "plan":
            print(json.dumps({"schema_version": 1, "desired": desired, "commands": [shlex.join(compose_command(directory, command)) for command in commands], "publication": "unchanged; withdraw disabled endpoints through Relay Services before stopping processes"}, indent=2))
            return
        if not args.acknowledge_process_change:
            raise Invalid("apply requires --acknowledge-process-change; withdraw affected endpoints through Relay Services first")
        # Validate Compose before any lifecycle action. Captured output is not
        # printed: Compose config includes control environment and credentials.
        compose(directory, ["config", "--quiet"], capture=True)
        for command in commands:
            compose(directory, command)
        save_applied(directory, source)
        print("Relay processes reconciled; publication unchanged. Use status and control readiness observations.")
    except (Invalid, OSError, ValueError, subprocess.CalledProcessError) as error:
        # Do not echo arbitrary Docker output or config parse values: these can
        # include secret-bearing configuration. Partial actions are not undone.
        if isinstance(error, Invalid):
            message = str(error)
        else:
            message = f"{type(error).__name__}; inspect local files or Docker diagnostics"
        print(f"relay-service: {message}. No automatic rollback; earlier actions may have completed.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
