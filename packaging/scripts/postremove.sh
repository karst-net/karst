#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright the Karst contributors.
#
# Shared by every Karst package: the unit file has just been deleted, so tell
# systemd to forget it. Without this, `systemctl status` keeps answering for a
# unit that no longer exists until something else reloads.

set -e

if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload >/dev/null 2>&1 || true
fi

exit 0
