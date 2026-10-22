#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright the Karst contributors.
"""Manage the reference Compose Relay's Ponor process.

Python 3.11+. Existing bootstrap material is reused, never regenerated. This
local process adapter does not change control's account publication authority.
"""

import argparse
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import tomllib


class Invalid(ValueError):
    pass


def manifest(path, source=None):
    value = tomllib.loads((source if source is not None else path.read_bytes()).decode())
    if set(value) != {"schema_version", "ponor"} or type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise Invalid("manifest requires schema_version = 1 and [ponor] only")
    if not isinstance(value["ponor"], dict) or set(value["ponor"]) != {"enabled"} or type(value["ponor"]["enabled"]) is not bool:
        raise Invalid("ponor requires an explicit enabled boolean")
    return value


def require_file(path):
    if not path.is_file() or path.stat().st_size == 0:
        raise Invalid(f"missing or empty {path.name}; run bootstrap first")


def validate_material(directory, desired):
    state = directory / "state"
    if desired["ponor"]["enabled"]:
        for name in ("relay.toml", "relay.key", "relays.json", "roster.toml", "tls/relay.crt", "tls/relay.key"):
            require_file(state / name)


def operations(desired):
    enabled = ["relay"] if desired["ponor"]["enabled"] else []
    disabled = [] if desired["ponor"]["enabled"] else ["relay"]
    return ([ ["up", "-d", "--no-deps", *enabled] ] if enabled else []) + ([ ["stop", *disabled] ] if disabled else [])


def compose_command(directory, args):
    # Explicit project file/directory: current working directory cannot select
    # another stack. Docker's normal environment/.env image and port settings
    # are retained. Never print resolved configuration or container env values.
    return ["docker", "compose", "--project-directory", str(directory), "-f", str(directory / "docker-compose.yml"), *args]


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
