#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright the Karst contributors.
#
# Stop and disable the coordination service when its package is being removed, and not when it is
# being upgraded. See preremove-karstd.sh for why $1 is matched in two
# dialects at once and why the enablement symlink is removed by hand.

set -e

case "${1:-}" in
  0 | remove | purge)
    if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
      systemctl stop karst-control.service >/dev/null 2>&1 || true
      systemctl disable karst-control.service >/dev/null 2>&1 || true
    fi
    rm -f /etc/systemd/system/multi-user.target.wants/karst-control.service
    ;;
esac

exit 0
