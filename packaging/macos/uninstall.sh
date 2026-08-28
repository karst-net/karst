#!/bin/bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright the Karst contributors.
#
# Remove Karst, leaving the machine's networking as it was.
#
# macOS has no package manager to do this, so the uninstaller is a script and
# ships in the package. Exit criterion 5 of plans/phase-5/06-macos-client.md is
# that this leaves no daemon, no binaries and **no DNS change** behind, which is
# why the revert runs before anything is deleted rather than after.

set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "karst: uninstalling needs root; re-run with sudo" >&2
    exit 1
fi

PLIST="/Library/LaunchDaemons/dev.karst.karstd.plist"
LABEL="dev.karst.karstd"

# 1. Revert host DNS *first*, while the binary that knows what to revert and
#    the config that says which mechanism was used are both still present.
if [ -x /usr/local/bin/karst ] && [ -f /etc/karst/karstd.toml ]; then
    /usr/local/bin/karst dns revert --config /etc/karst/karstd.toml || true
fi

# 2. Stop the daemon. Dropping the utun descriptor is what removes the
#    interface — Karst never makes one persistent.
/bin/launchctl bootout "system/${LABEL}" 2>/dev/null || true
/bin/launchctl unload "$PLIST" 2>/dev/null || true

# 3. Remove what the package installed.
rm -f "$PLIST"
rm -f /usr/local/bin/karstd /usr/local/bin/karst
rm -f /etc/karst/karstd.toml.example
rm -rf /var/log/karst
/usr/sbin/pkgutil --forget dev.karst.karstd 2>/dev/null || true

# 4. **Not** /etc/karst. It holds the node's private key and its configuration,
#    and deleting those would make a reinstall a re-enrolment — the node would
#    come back with a new identity and the old one would linger in the console
#    as a device nobody can account for. Say where it is and leave it.
if [ -d /etc/karst ]; then
    echo "karst: uninstalled. /etc/karst was kept — it holds this node's key"
    echo "       and configuration. Remove it by hand to forget this node, and"
    echo "       revoke the device in the console as well."
else
    echo "karst: uninstalled."
fi
