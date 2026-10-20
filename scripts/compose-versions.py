#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright the Karst contributors.
"""Record observed Compose image identities, without exposing container secrets.

Run from the Compose project directory. Mount the output directory read-only
into control and set KARST_COMPONENT_VERSIONS_FILE to the container path.
Re-run after every deployment; the UI shows the observation timestamp.
"""
import argparse
import datetime
import json
import os
from pathlib import Path
import subprocess
import tempfile


def docker(*args):
    return subprocess.check_output(["docker", *args], text=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    ids = docker("compose", "ps", "--all", "--quiet").split()
    if not ids:
        parser.error("No Compose containers found; no snapshot written")
    components = []
    for container in json.loads(docker("inspect", *ids)):
        image_id = container["Image"]
        image = json.loads(docker("image", "inspect", image_id))[0]
        components.append({
            "name": container["Name"].lstrip("/"),
            "image": container["Config"]["Image"],
            "image_id": image_id,
            "tags": image.get("RepoTags") or [],
            "state": container["State"]["Status"],
        })
    snapshot = {"observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "components": sorted(components, key=lambda c: c["name"])}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    # Atomic replacement: readers see a whole previous or new snapshot.
    with tempfile.NamedTemporaryFile(mode="w", dir=args.output.parent, delete=False) as tmp:
        json.dump(snapshot, tmp, indent=2)
        tmp.write("\n")
        temp_path = tmp.name
    try:
        os.chmod(temp_path, 0o644)
        os.replace(temp_path, args.output)
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)


if __name__ == "__main__":
    main()
