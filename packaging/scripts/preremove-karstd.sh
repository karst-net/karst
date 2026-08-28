#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright the Karst contributors.
#
# Stop and disable the node agent when its package is being removed — and only
# then.
#
# ## Why the argument is inspected
#
# Both packaging systems run this hook on an upgrade as well as a removal, and
# they say which through $1 in two different dialects: dpkg passes `upgrade`,
# `remove`, `purge` or `deconfigure`; rpm passes the number of instances that
# will remain, so `1` for an upgrade and `0` for an erase. Matching on `0` and
# `remove`/`purge` together is what makes one script correct under both.
#
# Getting this wrong is not cosmetic. A hook that stops and disables on every
# invocation turns `apt upgrade` into an outage: the node goes down during the
# upgrade and stays down until someone notices the machine is missing from the
# console after the next reboot.
#
# ## Why the symlink is removed by hand afterwards
#
# `systemctl disable` needs a running manager, and there is not always one — an
# image build, a container, a chroot. Left behind, an enablement symlink whose
# unit file is about to be deleted is a dangling link that systemd complains
# about on every subsequent reload, and that a reinstall silently resurrects as
# a service the administrator never re-enabled.

set -e

case "${1:-}" in
  0 | remove | purge)
    if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
      systemctl stop karstd.service >/dev/null 2>&1 || true
      systemctl disable karstd.service >/dev/null 2>&1 || true
    fi
    rm -f /etc/systemd/system/multi-user.target.wants/karstd.service
    ;;
esac

exit 0
