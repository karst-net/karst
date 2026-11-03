// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright the Karst contributors.

import AppKit
import Foundation

/// The Exit node submenu (ADR-0036 §3) — factored out of `AppDelegate` so
/// its text can be exercised without an `NSApplication`, the same shape
/// `SoftwareVersionMenu` already uses.
///
/// Always shown once a status exists (#481): omitting the whole section
/// when there is nothing to choose used to make "enrolled, zero exit
/// nodes offered" indistinguishable from "this device was never enrolled"
/// — exactly the ambiguity reported enrolling the macOS VM into Shannon,
/// where the absence of `shannon-exit` could not readily be told apart
/// from missing enrollment.
enum ExitNodeMenu {
    static func addItems(
        to menu: NSMenu,
        status: DaemonStatus,
        exitManaged: Bool,
        target: AnyObject?,
        useAction: Selector,
        disableAction: Selector
    ) {
        let submenu = NSMenu()
        if exitManaged {
            submenu.addItem(withTitle: "Managed by your organization", action: nil, keyEquivalent: "")
            if status.exitOffers.count > 1, !status.exitOffers.contains(where: { $0.routeID == status.selectedExit }) {
                submenu.addItem(
                    withTitle: "Several exits offered — none chosen until exactly one is",
                    action: nil, keyEquivalent: ""
                )
            }
            submenu.addItem(NSMenuItem.separator())
        }
        if status.exitOffers.isEmpty, status.selectedExit == nil {
            // Confirmed-empty and "cannot currently tell" are different
            // claims (#481's third requirement): the control-plane sync
            // that would populate this list may simply not have landed
            // yet, which is not the same as the account having offered
            // this device nothing.
            submenu.addItem(withTitle: emptyMessage(controlSynchronized: status.controlSynchronized), action: nil, keyEquivalent: "")
        } else {
            // Managed: shown, not changeable (no action grays the item out).
            let off = NSMenuItem(title: "Off", action: exitManaged ? nil : disableAction, keyEquivalent: "")
            off.target = target
            off.state = status.selectedExit == nil ? .on : .off
            submenu.addItem(off)
            submenu.addItem(NSMenuItem.separator())
            for offer in status.exitOffers {
                let via = offer.gatewayName.map { "Via \($0)" } ?? "Exit route"
                let pending = status.selectedExit == offer.routeID && !offer.active ? " — connecting" : ""
                let item = NSMenuItem(
                    title: "\(via) (\(offer.prefix))\(pending)",
                    action: exitManaged ? nil : useAction,
                    keyEquivalent: ""
                )
                item.target = target
                item.representedObject = offer
                item.state = status.selectedExit == offer.routeID ? .on : .off
                submenu.addItem(item)
            }
            if let selected = status.selectedExit, !status.exitOffers.contains(where: { $0.routeID == selected }) {
                submenu.addItem(withTitle: "Chosen exit is not currently offered", action: nil, keyEquivalent: "")
            }
        }
        let active = status.exitOffers.first(where: \.active)
        let title = active.map { "Exit node: \($0.gatewayName ?? $0.prefix)" } ?? "Exit node: Off"
        let parent = NSMenuItem(title: title, action: nil, keyEquivalent: "")
        parent.submenu = submenu
        menu.addItem(NSMenuItem.separator())
        menu.addItem(parent)
    }

    /// The line shown in place of an offer list when there is nothing to
    /// offer or withdraw — never silence, which read as "this feature
    /// doesn't exist" rather than "nothing is offered right now."
    static func emptyMessage(controlSynchronized: Bool) -> String {
        controlSynchronized
            ? "No exit nodes are currently offered to this device"
            : "Exit node availability unknown — control-plane state is not yet synchronized"
    }
}
