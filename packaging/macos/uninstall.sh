#!/bin/bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Copyright the Karst contributors.
#
# Remove Karst.app and its LaunchAgent.
#
# macOS has no package manager to do this, so the uninstaller is a script and
# ships in the package.
#
# **Does not fully deactivate the packet-tunnel system extension.** There is
# no reliable way to do that from a root shell script:
# `systemextensionsctl uninstall`/`reset` both refuse to run with System
# Integrity Protection enabled (confirmed on real hardware, #159), and full
# programmatic deactivation needs `OSSystemExtensionRequest.deactivationRequest`
# called from a live GUI app process, which this script is not. Best-effort
# here is removing the app and its saved VPN configuration is not; a user may
# need to remove "Karst Network Extension" by hand in System Settings ->
# General -> Login Items & Extensions -> Network Extensions afterward.

set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "karst: uninstalling needs root; re-run with sudo" >&2
    exit 1
fi

STATUS_PLIST="/Library/LaunchAgents/dev.karst.karststatus.plist"
STATUS_LABEL="dev.karst.karststatus"
STATUS_APP="/Applications/Karst.app"

# 1. Stop the menu-bar app, for whoever is at the console — it is a per-user
#    LaunchAgent, so it must be addressed as that user's GUI session, the
#    same `launchctl asuser` pattern status-scripts/preinstall uses.
#    Best-effort: there may be no console user at all (uninstalling from a
#    headless run), and that must not fail the rest of this script.
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

# 2. Remove what the package installed.
rm -f "$STATUS_PLIST"
rm -rf "$STATUS_APP"
rm -f /usr/local/bin/karst
rm -f /usr/local/bin/karst-uninstall
/usr/sbin/pkgutil --forget "$STATUS_LABEL" 2>/dev/null || true

# 3. **Not** the system extension's own state directory
#    (/Library/Application Support/dev.karst.packettunnel). It holds the
#    node's private key and its configuration, and deleting those would
#    make a reinstall a re-enrollment — the node would come back with a new
#    identity and the old one would linger in the console as a device
#    nobody can account for. Say where it is and leave it.
STATE_DIR="/Library/Application Support/dev.karst.packettunnel"
if [ -d "$STATE_DIR" ]; then
    echo "karst: uninstalled. \"$STATE_DIR\" was kept — it holds this"
    echo "       device's key and configuration. Remove it by hand to forget"
    echo "       this device, and revoke it in the console as well."
else
    echo "karst: uninstalled."
fi
echo "karst: the system extension itself may still show as active — remove"
echo "       it by hand in System Settings > General > Login Items &"
echo "       Extensions > Network Extensions if you want it fully gone."
