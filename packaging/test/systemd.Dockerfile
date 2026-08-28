# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright the Karst contributors.
#
# A container that boots systemd, so `scripts/package-systemd-verify.sh` can be
# run without a virtual machine and without touching the developer's own
# resolver — the check replaces /etc/resolv.conf and kills a daemon half way
# through, which is not something to do to a workstation.
#
# Run it privileged, with the host's cgroup hierarchy:
#
#   docker run -d --privileged --cgroupns=host \
#     -v /sys/fs/cgroup:/sys/fs/cgroup:rw karst-systemd-verify
#
# `just packages-verify-systemd` does that. In CI the same script runs on the
# runner itself, which is a full VM and needs none of this.
#
# Debian 12 rather than the newest thing available: it is the oldest
# systemd in the supported set, so a unit that works here works on the others.
FROM debian:12

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        systemd systemd-resolved dbus iproute2 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN systemctl enable systemd-resolved

# systemd wants SIGRTMIN+3 to shut down; the default SIGTERM makes `docker stop`
# wait out its full timeout on every run.
STOPSIGNAL SIGRTMIN+3

# The Debian image ships no /sbin/init symlink, so systemd is named directly.
CMD ["/lib/systemd/systemd"]
