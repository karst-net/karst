#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright the Karst contributors.
#
# Run `package-systemd-verify.sh` inside a container booted on systemd.
#
#   scripts/package-systemd-container.sh PACKAGE_DIR
#
# One entry point for CI and for `just packages-verify-systemd`, so the check
# that runs on a push is the one a developer can run first.
#
# ## Why a container and not the machine
#
# The check replaces /etc/resolv.conf and kills a daemon half way through, and
# it needs the file it is asserting about to be an ordinary file that nothing
# else owns.
#
# On a host running systemd-resolved — which includes every GitHub runner —
# /etc/resolv.conf is a symlink into /run/systemd/resolve/stub-resolv.conf, a
# file resolved regenerates whenever it feels like it. Writing a known original
# through that symlink is writing into another daemon's state, and resolved
# puts its own content back before the assertion runs. That is not the resolver
# integration failing; it is the test having picked a file it does not own.
#
# The container gives the check a resolver of its own, and keeps the developer's
# machine — or the runner that has jobs after this one — out of it entirely.

set -euo pipefail

package_dir=${1:?usage: scripts/package-systemd-container.sh PACKAGE_DIR}
package_dir=$(cd "$package_dir" && pwd)
repo=$(cd "$(dirname "$0")/.." && pwd)
image=karst-systemd-verify

docker build -q -t "$image" -f "$repo/packaging/test/systemd.Dockerfile" "$repo/packaging/test"

container=$(docker run -d --privileged --cgroupns=host \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
  -v "$repo:/karst:ro" \
  -v "$package_dir:/packages:ro" \
  "$image")
trap 'docker rm -f "$container" >/dev/null 2>&1 || true' EXIT

for _ in $(seq 30); do
  state=$(docker exec "$container" systemctl is-system-running 2>/dev/null || true)
  # `degraded` is a running system with some unit failed, which is normal in a
  # container — waiting for `running` alone would time out on every run and
  # then test nothing.
  case "$state" in running | degraded) break ;; esac
  sleep 1
done
case "${state:-}" in
  running | degraded) ;;
  *)
    echo "package-systemd-container: systemd did not come up (state: ${state:-none})" >&2
    docker logs "$container" 2>&1 | tail -20 >&2
    exit 2
    ;;
esac

docker exec "$container" bash /karst/scripts/package-systemd-verify.sh /packages
