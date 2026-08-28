#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright the Karst contributors.
#
# Shared by every Karst package. It does one thing: tell systemd that a unit
# file appeared.
#
# It deliberately does **not** enable or start anything. A Karst service with
# no configuration cannot do useful work — `karstd` exits non-zero on a missing
# `/etc/karst/karstd.toml` — so enabling it here would give an administrator a
# restart loop as the first thing the product does on their machine. Enablement
# is the step after configuration, and the console's first-run flow and
# docs/GETTING-STARTED.md both say so.

set -e

# A container, a chroot, or an image build has no manager to talk to. `-d
# /run/systemd/system` is the documented test for "systemd is the running init"
# and is what the systemd packaging guidelines use.
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload >/dev/null 2>&1 || true
fi

exit 0
