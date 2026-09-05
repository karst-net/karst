#!/bin/bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright the Karst contributors.
#
# Remove Karst — the daemon and the menu-bar status app both, one .pkg
# installed them together (plans/phase-6/13-macos-status-indicators.md §2
# item 1) and one uninstall removes them together — leaving the machine's
# networking as it was.
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
STATUS_PLIST="/Library/LaunchAgents/dev.karst.karststatus.plist"
STATUS_LABEL="dev.karst.karststatus"
STATUS_APP="/Applications/Karst Status.app"

# 1. Revert host DNS *first*, while the binary that knows what to revert and
#    the config that says which mechanism was used are both still present.
#
#    On macOS this restores /etc/resolver: it removes the files Karst created,
#    puts back byte for byte any file it replaced, and consumes the revert
#    record under /var/db/karst — including one a killed daemon left behind.
if [ -x /usr/local/bin/karst ] && [ -f /etc/karst/karstd.toml ]; then
    /usr/local/bin/karst dns revert --config /etc/karst/karstd.toml || true
fi

# 2. Stop the daemon. Dropping the utun descriptor is what removes the
#    interface — Karst never makes one persistent.
/bin/launchctl bootout "system/${LABEL}" 2>/dev/null || true
/bin/launchctl unload "$PLIST" 2>/dev/null || true

# 3. Stop the menu-bar app too, for whoever is at the console — it is a
#    per-user LaunchAgent, so unlike the daemon above this cannot be
#    `bootout`-ed as `system/...`; it must be addressed as that user's GUI
#    session, the same `launchctl asuser` pattern status-scripts/preinstall
#    uses. Best-effort: there may be no console user at all (uninstalling
#    from a headless run), and that must not fail the rest of this script.
console_user="$(stat -f%Su /dev/console 2>/dev/null || true)"
if [ -n "$console_user" ] && [ "$console_user" != "root" ]; then
    console_uid="$(id -u "$console_user" 2>/dev/null || true)"
    if [ -n "$console_uid" ]; then
        /bin/launchctl asuser "$console_uid" /bin/launchctl bootout \
            "gui/$console_uid" "$STATUS_PLIST" 2>/dev/null || true
        /bin/launchctl asuser "$console_uid" /bin/launchctl unload \
            "$STATUS_PLIST" 2>/dev/null || true
    fi
fi

# 4. Remove what the package installed.
rm -f "$PLIST"
rm -f /usr/local/bin/karstd /usr/local/bin/karst
rm -f /etc/karst/karstd.toml.example
rm -rf /var/log/karst
rm -f "$STATUS_PLIST"
rm -rf "$STATUS_APP"
# The DNS revert above consumed the record inside it; this takes the directory
# only if that worked, so a leftover record survives to be reverted next time
# rather than being deleted along with the machine's chance of recovering.
rmdir /var/db/karst 2>/dev/null || true
/usr/sbin/pkgutil --forget dev.karst.karstd 2>/dev/null || true
/usr/sbin/pkgutil --forget "$STATUS_LABEL" 2>/dev/null || true

# 5. **Not** /etc/karst. It holds the node's private key and its configuration,
#    and deleting those would make a reinstall a re-enrollment — the node would
#    come back with a new identity and the old one would linger in the console
#    as a device nobody can account for. Say where it is and leave it.
if [ -d /etc/karst ]; then
    echo "karst: uninstalled. /etc/karst was kept — it holds this node's key"
    echo "       and configuration. Remove it by hand to forget this node, and"
    echo "       revoke the device in the console as well."
else
    echo "karst: uninstalled."
fi
