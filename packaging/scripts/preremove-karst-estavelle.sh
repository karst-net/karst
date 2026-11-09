#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright the Karst contributors.
#
# Stop and disable the estavelle when its package is being removed, and not when it is
# being upgraded. See preremove-karstd.sh for why $1 is matched in two
# dialects at once and why the enablement symlink is removed by hand.

set -e

case "${1:-}" in
  0 | remove | purge)
    if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
      systemctl stop karst-estavelle.service >/dev/null 2>&1 || true
      systemctl disable karst-estavelle.service >/dev/null 2>&1 || true
    fi
    rm -f /etc/systemd/system/multi-user.target.wants/karst-estavelle.service
    ;;
esac

exit 0
