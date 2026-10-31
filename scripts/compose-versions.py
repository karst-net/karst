#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright the Karst contributors.
"""Record observed Compose or Nomad Docker image identities, without secrets.

Run from the Compose project directory, or select a Nomad job/namespace on
its Docker host with --nomad-job. Mount the output directory read-only
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


def observe_component(container):
    # Resolve metadata by the executing container's immutable image ID, never
    # its configured tag: the tag may already point at a newer image.
    image_id = container["Image"]
    image = json.loads(docker("image", "inspect", image_id))[0]
    labels = image.get("Config", {}).get("Labels") or {}
    return {
        "name": container["Name"].lstrip("/"),
        "image": container["Config"]["Image"],
        "image_id": image_id,
        "version": labels.get("org.opencontainers.image.version"),
        "revision": labels.get("org.opencontainers.image.revision"),
        "tags": image.get("RepoTags") or [],
        "state": container["State"]["Status"],
    }


def container_ids(nomad_job=None, namespace="default"):
    if nomad_job is None:
        return docker("compose", "ps", "--all", "--quiet").split()
    allocations = json.loads(subprocess.check_output(
        ["nomad", "job", "allocs", "-all", "-json", f"-namespace={namespace}", nomad_job], text=True,
    )) or []
    ids = set()
    for allocation in allocations:
        # The CLI accepts job prefixes and can return historical allocations.
        # Restrict to this exact job/namespace and active allocations. Read
        # actual local containers, not desired task image references.
        if allocation.get("JobID") != nomad_job or allocation.get("Namespace") != namespace:
            continue
        if allocation.get("ClientStatus") not in ("pending", "running") or not allocation.get("ID"):
            continue
        # alloc_id is Nomad's mandatory Docker label. Job/namespace labels
        # require optional driver configuration and cannot be assumed present.
        ids.update(docker("ps", "--all", "--quiet", "--filter",
                          f"label=com.hashicorp.nomad.alloc_id={allocation['ID']}").split())
    return sorted(ids)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--nomad-job", help="exact Nomad job ID; observe its Docker tasks on this host")
    parser.add_argument("--nomad-namespace", default="default", help="Nomad namespace (default: default)")
    args = parser.parse_args()
    if not args.nomad_namespace or args.nomad_namespace == "*" or args.nomad_namespace.startswith("-"):
        parser.error("Select one explicit Nomad namespace")
    if args.nomad_job is not None and (not args.nomad_job or args.nomad_job.startswith("-")):
        parser.error("Select one exact Nomad job ID")
    if args.nomad_job is None and args.nomad_namespace != "default":
        parser.error("--nomad-namespace requires --nomad-job")
    ids = container_ids(args.nomad_job, args.nomad_namespace)
    if not ids:
        parser.error("No matching local containers found; no snapshot written")
    components = [observe_component(container) for container in json.loads(docker("inspect", *ids))]
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
