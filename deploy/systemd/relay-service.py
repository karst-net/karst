#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright the Karst contributors.
"""Manage the bare-metal relay's Ponor process under systemd.

Python 3.11+. Existing bootstrap material (GETTING-STARTED.md §6.1) is reused,
never regenerated. This local process adapter does not change control's
account publication authority. Mirrors deploy/compose/relay-service.py's
manifest/plan/apply/status contract for a host with no Docker, driving
`systemctl` against an already-installed unit instead of `docker compose`.
"""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib

DEFAULT_UNIT = "karst-relay.service"


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
        raise Invalid(f"missing or empty {path}; run GETTING-STARTED.md §6.1 first")


def validate_material(directory, desired):
    if desired["ponor"]["enabled"]:
        for name in ("relay.key", "roster.toml", "relays.json", "tls/relay.crt", "tls/relay.key"):
            require_file(directory / name)


def operations(desired, unit):
    return [["start", unit]] if desired["ponor"]["enabled"] else [["stop", unit]]


def systemctl(args, capture=False):
    return subprocess.run(["systemctl", *args], check=True, text=True, capture_output=capture)


def save_applied(directory, source):
    target = directory / "relay-service.applied.toml"
    target.parent.mkdir(exist_ok=True, parents=True)
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


def status(desired, unit):
    raw = systemctl(["show", unit, "--property=LoadState,ActiveState,SubState"], capture=True).stdout
    fields = dict(line.split("=", 1) for line in raw.strip().splitlines() if "=" in line)
    state = "absent" if fields.get("LoadState") == "not-found" else fields.get("ActiveState", "unknown")
    return {"ponor": {"enabled": desired["ponor"]["enabled"], "state": state, "health": "unprobed"},
            "readiness": "Use control Relay Services observations for admission/allocation readiness; unit state alone is not readiness."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("plan", "apply", "status"))
    parser.add_argument("--directory", type=Path, default=Path("/etc/karst"), help="holds relay.key, roster.toml, relays.json and tls/ (default /etc/karst)")
    parser.add_argument("--manifest", type=Path, help="defaults to relay-service.toml in --directory")
    parser.add_argument("--unit", default=DEFAULT_UNIT, help=f"systemd unit to manage (default {DEFAULT_UNIT})")
    parser.add_argument("--acknowledge-process-change", action="store_true", help="apply can interrupt active allocations and connections")
    args = parser.parse_args()
    directory = args.directory.resolve()
    path = args.manifest or directory / "relay-service.toml"
    try:
        source = path.read_bytes()
        desired = manifest(path, source)
        if args.command == "status":
            print(json.dumps(status(desired, args.unit), indent=2))
            return
        validate_material(directory, desired)
        commands = operations(desired, args.unit)
        if args.command == "plan":
            print(json.dumps({"schema_version": 1, "desired": desired, "commands": [" ".join(["systemctl", *command]) for command in commands], "publication": "unchanged; withdraw disabled endpoints through Relay Services before stopping the unit"}, indent=2))
            return
        if not args.acknowledge_process_change:
            raise Invalid("apply requires --acknowledge-process-change; withdraw affected endpoints through Relay Services first")
        # Validate the unit is installed before any lifecycle action. Captured
        # output is not printed: a unit file can carry Environment= secrets.
        systemctl(["cat", args.unit], capture=True)
        for command in commands:
            systemctl(command)
        save_applied(directory, source)
        print("Relay process reconciled; publication unchanged. Use status and control readiness observations.")
    except (Invalid, OSError, ValueError, subprocess.CalledProcessError) as error:
        # Do not echo arbitrary systemd output or config parse values: these
        # can include secret-bearing configuration. Partial actions are not
        # undone.
        if isinstance(error, Invalid):
            message = str(error)
        else:
            message = f"{type(error).__name__}; inspect local files or `journalctl -u {args.unit}`"
        print(f"relay-service: {message}. No automatic rollback; earlier actions may have completed.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
